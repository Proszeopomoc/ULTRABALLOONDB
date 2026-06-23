use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ultraballoondb_core::Graph;
use ultraballoondb_lifecycle::{
    DatabaseEdge, DatabaseRecord, DerivedArtifactInventory, DerivedArtifactKind, ReadSnapshot,
    RegisterOutcome,
};
use ultraballoondb_storage::{hex_digest, sha256, sha256_file};
use ultraballoondb_trust::{MaturityState, TrustLedger, TrustState, ValidityState};

use super::{
    column_path, cosine_with_query_norm, squared_norm, validate_vector, CpuGpuRouterReceipt,
    ImportOutcome, Result, SpaceId, VectorHit, VectorInput, VectorNormalization, VectorOrigin,
    VectorSpaceDescriptor, VectorStore, VectorStoreError, VECTOR_SPACE_SCHEMA_VERSION,
};

pub const NATIVE_STRUCTURAL_DIM: u32 = 48;
pub const GRAPH_SNAPSHOT_FORMAT_VERSION: u16 = 1;

const GRAPH_MANIFEST_MAGIC: [u8; 8] = *b"UBGSM01\0";
const GRAPH_NODE_BYTES: usize = 24;
const GRAPH_EDGE_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GraphScopeConfig {
    pub max_steps: usize,
    pub energy_threshold: f64,
    pub candidate_limit: usize,
    pub edge_mask: u32,
    pub rigor_multiplier: f64,
}

impl Default for GraphScopeConfig {
    fn default() -> Self {
        Self {
            max_steps: 3,
            energy_threshold: 0.01,
            candidate_limit: 1_024,
            edge_mask: u32::MAX,
            rigor_multiplier: 1.0,
        }
    }
}

impl GraphScopeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_steps == 0 || self.max_steps > 64 {
            return Err(VectorStoreError::Invalid(
                "graph max_steps must be in 1..=64".to_string(),
            ));
        }
        if self.candidate_limit == 0 || self.candidate_limit > 1_000_000 {
            return Err(VectorStoreError::Invalid(
                "graph candidate_limit must be in 1..=1000000".to_string(),
            ));
        }
        if !self.energy_threshold.is_finite() || self.energy_threshold < 0.0 {
            return Err(VectorStoreError::Invalid(
                "graph energy_threshold must be finite and non-negative".to_string(),
            ));
        }
        if !self.rigor_multiplier.is_finite() || self.rigor_multiplier <= 0.0 {
            return Err(VectorStoreError::Invalid(
                "graph rigor_multiplier must be finite and positive".to_string(),
            ));
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"UBGSC001");
        bytes.extend_from_slice(&(self.max_steps as u64).to_le_bytes());
        bytes.extend_from_slice(&self.energy_threshold.to_bits().to_le_bytes());
        bytes.extend_from_slice(&(self.candidate_limit as u64).to_le_bytes());
        bytes.extend_from_slice(&self.edge_mask.to_le_bytes());
        bytes.extend_from_slice(&self.rigor_multiplier.to_bits().to_le_bytes());
        sha256(&bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphSnapshotReceipt {
    pub layout_path: PathBuf,
    pub manifest_path: PathBuf,
    pub database_snapshot_sha256: [u8; 32],
    pub record_count: u64,
    pub edge_count: u64,
    pub nodes_sha256: [u8; 32],
    pub edges_sha256: [u8; 32],
    pub inventory_outcome: RegisterOutcome,
}

#[derive(Clone, Debug)]
pub struct GraphSnapshotIndex {
    layout_path: PathBuf,
    manifest_path: PathBuf,
    database_snapshot_sha256: [u8; 32],
    record_to_node: BTreeMap<String, u64>,
    node_to_record: BTreeMap<u64, String>,
    outgoing: BTreeMap<u64, Vec<DatabaseEdge>>,
    incoming: BTreeMap<u64, Vec<DatabaseEdge>>,
}

impl GraphSnapshotIndex {
    pub fn materialize(
        database_root: impl AsRef<Path>,
        snapshot: &ReadSnapshot<'_>,
        inventory: &mut DerivedArtifactInventory,
    ) -> Result<(Self, GraphSnapshotReceipt)> {
        let database_root = database_root.as_ref();
        let descriptor = snapshot.descriptor();
        inventory
            .invalidate_stale(descriptor)
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;

        let snapshot_hex = hex_digest(&descriptor.snapshot_sha256);
        let layout_path = database_root
            .join("derived")
            .join("semantic_graph")
            .join(snapshot_hex);
        let manifest_path = layout_path.join("GRAPH_SNAPSHOT.ubgsm");
        let nodes_path = layout_path.join("csr_nodes.bin");
        let edges_path = layout_path.join("csr_edges.bin");

        let records = snapshot
            .records()
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
        let edges = snapshot
            .edges()
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
        let maps = build_record_maps(&records)?;
        let adjacency = build_adjacency(&maps.1, &edges)?;

        if manifest_path.exists() || nodes_path.exists() || edges_path.exists() {
            verify_graph_snapshot_files(
                &manifest_path,
                &nodes_path,
                &edges_path,
                descriptor.snapshot_sha256,
                records.len() as u64,
                edges.len() as u64,
            )?;
        } else {
            let parent = layout_path.parent().ok_or_else(|| {
                VectorStoreError::Invalid("graph layout has no parent".to_string())
            })?;
            fs::create_dir_all(parent)?;
            let temporary_layout = layout_path.with_extension("building");
            if temporary_layout.exists() {
                fs::remove_dir_all(&temporary_layout)?;
            }
            fs::create_dir(&temporary_layout)?;

            let build_result = (|| -> Result<()> {
                let temporary_nodes = temporary_layout.join("csr_nodes.bin");
                let temporary_edges = temporary_layout.join("csr_edges.bin");
                let temporary_manifest = temporary_layout.join("GRAPH_SNAPSHOT.ubgsm");
                let (node_bytes, edge_bytes) = encode_csr(&records, &adjacency.0)?;
                write_atomic_new(&temporary_nodes, &node_bytes)?;
                write_atomic_new(&temporary_edges, &edge_bytes)?;
                let manifest = encode_graph_manifest(
                    descriptor.snapshot_sha256,
                    records.len() as u64,
                    edges.len() as u64,
                    sha256(&node_bytes),
                    sha256(&edge_bytes),
                );
                write_atomic_new(&temporary_manifest, &manifest)?;
                verify_graph_snapshot_files(
                    &temporary_manifest,
                    &temporary_nodes,
                    &temporary_edges,
                    descriptor.snapshot_sha256,
                    records.len() as u64,
                    edges.len() as u64,
                )?;
                Ok(())
            })();

            if let Err(error) = build_result {
                let _ = fs::remove_dir_all(&temporary_layout);
                return Err(error);
            }
            fs::rename(&temporary_layout, &layout_path)?;
        }

        let manifest = decode_graph_manifest(&fs::read(&manifest_path)?)?;
        let relative_manifest = manifest_path.strip_prefix(database_root).map_err(|_| {
            VectorStoreError::Corrupt("graph manifest escapes database root".to_string())
        })?;
        let inventory_outcome = inventory
            .register_complete_file(
                DerivedArtifactKind::HotSnapshot,
                descriptor.committed_transaction_count,
                descriptor,
                relative_manifest,
                records.len() as u64,
            )
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;

        let index = Self {
            layout_path: layout_path.clone(),
            manifest_path: manifest_path.clone(),
            database_snapshot_sha256: descriptor.snapshot_sha256,
            record_to_node: maps.0,
            node_to_record: maps.1,
            outgoing: adjacency.0,
            incoming: adjacency.1,
        };
        let receipt = GraphSnapshotReceipt {
            layout_path,
            manifest_path,
            database_snapshot_sha256: descriptor.snapshot_sha256,
            record_count: manifest.record_count,
            edge_count: manifest.edge_count,
            nodes_sha256: manifest.nodes_sha256,
            edges_sha256: manifest.edges_sha256,
            inventory_outcome,
        };
        Ok((index, receipt))
    }

    pub fn open_verified(
        database_root: impl AsRef<Path>,
        snapshot: &ReadSnapshot<'_>,
    ) -> Result<Self> {
        let database_root = database_root.as_ref();
        let descriptor = snapshot.descriptor();
        let layout_path = database_root
            .join("derived")
            .join("semantic_graph")
            .join(hex_digest(&descriptor.snapshot_sha256));
        let manifest_path = layout_path.join("GRAPH_SNAPSHOT.ubgsm");
        let nodes_path = layout_path.join("csr_nodes.bin");
        let edges_path = layout_path.join("csr_edges.bin");

        let records = snapshot
            .records()
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
        let edges = snapshot
            .edges()
            .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
        verify_graph_snapshot_files(
            &manifest_path,
            &nodes_path,
            &edges_path,
            descriptor.snapshot_sha256,
            records.len() as u64,
            edges.len() as u64,
        )?;
        let maps = build_record_maps(&records)?;
        let adjacency = build_adjacency(&maps.1, &edges)?;
        Ok(Self {
            layout_path,
            manifest_path,
            database_snapshot_sha256: descriptor.snapshot_sha256,
            record_to_node: maps.0,
            node_to_record: maps.1,
            outgoing: adjacency.0,
            incoming: adjacency.1,
        })
    }

    pub fn layout_path(&self) -> &Path {
        &self.layout_path
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn database_snapshot_sha256(&self) -> [u8; 32] {
        self.database_snapshot_sha256
    }

    pub fn record_to_node(&self, record_id: &str) -> Option<u64> {
        self.record_to_node.get(record_id).copied()
    }

    pub fn node_to_record(&self, node_id: u64) -> Option<&str> {
        self.node_to_record.get(&node_id).map(String::as_str)
    }

    pub fn outgoing(&self, node_id: u64) -> &[DatabaseEdge] {
        self.outgoing
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn incoming(&self, node_id: u64) -> &[DatabaseEdge] {
        self.incoming
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn ensure_snapshot(&self, snapshot: &ReadSnapshot<'_>) -> Result<()> {
        if self.database_snapshot_sha256 != snapshot.descriptor().snapshot_sha256 {
            return Err(VectorStoreError::Conflict(
                "graph snapshot and database ReadSnapshot differ".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WaveEvidence {
    pub record_id: String,
    pub node_id: u64,
    pub energy: f64,
    pub path_edge_types: Vec<u32>,
    pub direct_outgoing_edge_types: Vec<u32>,
    pub direct_incoming_edge_types: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WaveScope {
    pub anchor_record_id: String,
    pub anchor_node_id: u64,
    pub database_snapshot_sha256: [u8; 32],
    pub config_digest: [u8; 32],
    pub candidates: BTreeMap<String, WaveEvidence>,
}

impl WaveScope {
    pub fn allowed_record_ids(&self) -> BTreeSet<String> {
        self.candidates.keys().cloned().collect()
    }

    pub fn evidence(&self, record_id: &str) -> Option<&WaveEvidence> {
        self.candidates.get(record_id)
    }
}

pub fn build_wave_scope(
    snapshot: &ReadSnapshot<'_>,
    graph_index: &GraphSnapshotIndex,
    anchor_record_id: &str,
    config: GraphScopeConfig,
) -> Result<WaveScope> {
    config.validate()?;
    graph_index.ensure_snapshot(snapshot)?;
    let anchor_node_id = graph_index
        .record_to_node(anchor_record_id)
        .ok_or_else(|| VectorStoreError::NotFound(format!("anchor record {anchor_record_id}")))?;

    let graph_edge_count = graph_index.outgoing.values().map(Vec::len).sum::<usize>();
    let rows = if graph_edge_count == 0 {
        Vec::new()
    } else {
        let mut graph =
            Graph::open(graph_index.layout_path()).map_err(VectorStoreError::Lifecycle)?;
        graph
            .wave_activation_l3(
                &[anchor_node_id],
                config.max_steps,
                config.energy_threshold,
                config.candidate_limit.saturating_add(1),
                config.edge_mask,
                config.rigor_multiplier,
            )
            .0
    };

    let direct_outgoing = graph_index.outgoing(anchor_node_id);
    let direct_incoming = graph_index.incoming(anchor_node_id);
    let mut candidates = BTreeMap::new();
    for row in rows {
        if row.node_id == anchor_node_id {
            continue;
        }
        let Some(record_id) = graph_index.node_to_record(row.node_id) else {
            continue;
        };
        let mut direct_outgoing_edge_types = direct_outgoing
            .iter()
            .filter(|edge| edge.dst == row.node_id)
            .map(|edge| edge.edge_type)
            .collect::<Vec<_>>();
        let mut direct_incoming_edge_types = direct_incoming
            .iter()
            .filter(|edge| edge.src == row.node_id)
            .map(|edge| edge.edge_type)
            .collect::<Vec<_>>();
        direct_outgoing_edge_types.sort_unstable();
        direct_outgoing_edge_types.dedup();
        direct_incoming_edge_types.sort_unstable();
        direct_incoming_edge_types.dedup();

        candidates.insert(
            record_id.to_string(),
            WaveEvidence {
                record_id: record_id.to_string(),
                node_id: row.node_id,
                energy: row.energy,
                path_edge_types: row.best_path,
                direct_outgoing_edge_types,
                direct_incoming_edge_types,
            },
        );
        if candidates.len() >= config.candidate_limit {
            break;
        }
    }

    Ok(WaveScope {
        anchor_record_id: anchor_record_id.to_string(),
        anchor_node_id,
        database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
        config_digest: config.canonical_digest(),
        candidates,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownTrustPolicy {
    IncludeAsRawActive,
    Exclude,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustFilter {
    Any,
    ActiveOnly,
    MaturityAtLeast(MaturityState),
    VerifiedActiveOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustView {
    pub state: TrustState,
    pub explicit: bool,
    pub last_sequence: u64,
    pub trust_ledger_head_digest: [u8; 32],
}

fn maturity_rank(value: MaturityState) -> u8 {
    match value {
        MaturityState::Raw => 1,
        MaturityState::Hypothesis => 2,
        MaturityState::Candidate => 3,
        MaturityState::Verified => 4,
    }
}

fn trust_view(
    record_id: &str,
    ledger: Option<&TrustLedger>,
    unknown_policy: UnknownTrustPolicy,
) -> Option<TrustView> {
    let head = ledger.map(TrustLedger::head_digest).unwrap_or([0u8; 32]);
    if let Some(snapshot) = ledger.and_then(|value| value.snapshot(record_id)) {
        return Some(TrustView {
            state: snapshot.state,
            explicit: true,
            last_sequence: snapshot.last_sequence,
            trust_ledger_head_digest: head,
        });
    }
    match unknown_policy {
        UnknownTrustPolicy::IncludeAsRawActive => Some(TrustView {
            state: TrustState::raw_active(),
            explicit: false,
            last_sequence: 0,
            trust_ledger_head_digest: head,
        }),
        UnknownTrustPolicy::Exclude => None,
    }
}

fn trust_allows(view: &TrustView, filter: TrustFilter) -> bool {
    match filter {
        TrustFilter::Any => true,
        TrustFilter::ActiveOnly => view.state.validity == ValidityState::Active,
        TrustFilter::MaturityAtLeast(minimum) => {
            maturity_rank(view.state.maturity) >= maturity_rank(minimum)
        }
        TrustFilter::VerifiedActiveOnly => {
            view.state.maturity == MaturityState::Verified
                && view.state.validity == ValidityState::Active
        }
    }
}

impl VectorSpaceDescriptor {
    pub fn ultraballoon_native_structural(config_digest: [u8; 32]) -> Self {
        Self {
            schema_version: VECTOR_SPACE_SCHEMA_VERSION,
            origin: VectorOrigin::UltraBalloonNative,
            provider_id: "ultraballoondb".to_string(),
            model_id: "ultraballoon-native-structural".to_string(),
            model_revision: "v1".to_string(),
            preprocessing_id: format!("graph-wave-motif-{}", hex_digest(&config_digest),),
            dim: NATIVE_STRUCTURAL_DIM,
            dtype: super::VectorDType::F32,
            metric: super::VectorMetric::Cosine,
            normalization: VectorNormalization::UnitL2,
        }
    }
}

impl VectorStore {
    pub fn vector_for_record(
        &self,
        space_id: SpaceId,
        record_id: &str,
    ) -> Result<Option<Vec<f32>>> {
        let column = self
            .columns
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        match column
            .record_ids
            .binary_search_by(|value| value.as_str().cmp(record_id))
        {
            Ok(index) => Ok(Some(column.vector_at(index).to_vec())),
            Err(_) => Ok(None),
        }
    }

    pub fn column_file_path(&self, space_id: SpaceId) -> Result<PathBuf> {
        if !self.registry.contains_key(&space_id) {
            return Err(VectorStoreError::NotFound(format!(
                "space {}",
                space_id.to_hex()
            )));
        }
        Ok(column_path(&self.root, space_id))
    }

    pub fn find_exact_in_records(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        query_vector: &[f32],
        k: usize,
        allowed_record_ids: Option<&BTreeSet<String>>,
    ) -> Result<Vec<VectorHit>> {
        if k == 0 || k > super::MAX_TOP_K {
            return Err(VectorStoreError::Invalid(format!(
                "k must be in 1..={}",
                super::MAX_TOP_K
            )));
        }
        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        validate_vector(query_vector, descriptor.dim)?;
        let query_norm = squared_norm(query_vector);
        let column = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;

        let mut scored = Vec::new();
        for (index, record_id) in column.record_ids.iter().enumerate() {
            if let Some(allowed) = allowed_record_ids {
                if !allowed.contains(record_id) {
                    continue;
                }
            }
            if snapshot
                .record(record_id)
                .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?
                .is_none()
            {
                continue;
            }
            let score = cosine_with_query_norm(query_vector, query_norm, column.vector_at(index));
            scored.push((record_id.clone(), score));
        }

        scored.sort_by(|left, right| match right.1.total_cmp(&left.1) {
            Ordering::Equal => left.0.cmp(&right.0),
            ordering => ordering,
        });
        scored.truncate(k.min(scored.len()));

        Ok(scored
            .into_iter()
            .enumerate()
            .map(|(index, (record_id, cosine_score))| VectorHit {
                record_id,
                cosine_score,
                rank: index + 1,
                exact: true,
                space_id,
                column_generation: column.generation,
                database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
            })
            .collect())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NativeStructuralConfig {
    pub wave: GraphScopeConfig,
}

impl Default for NativeStructuralConfig {
    fn default() -> Self {
        Self {
            wave: GraphScopeConfig {
                max_steps: 3,
                energy_threshold: 0.001,
                candidate_limit: 256,
                edge_mask: u32::MAX,
                rigor_multiplier: 1.0,
            },
        }
    }
}

impl NativeStructuralConfig {
    pub fn validate(&self) -> Result<()> {
        self.wave.validate()
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"UBNSC001");
        bytes.extend_from_slice(&self.wave.canonical_digest());
        bytes.extend_from_slice(&NATIVE_STRUCTURAL_DIM.to_le_bytes());
        sha256(&bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStructuralBuildReceipt {
    pub space_id: SpaceId,
    pub config_digest: [u8; 32],
    pub database_snapshot_sha256: [u8; 32],
    pub record_count: u64,
    pub column_generation: u64,
    pub import_outcome: ImportOutcome,
    pub inventory_outcome: RegisterOutcome,
    pub column_sha256: [u8; 32],
}

pub fn build_native_structural_space(
    snapshot: &ReadSnapshot<'_>,
    graph_index: &GraphSnapshotIndex,
    vector_store: &mut VectorStore,
    inventory: &mut DerivedArtifactInventory,
    config: NativeStructuralConfig,
) -> Result<NativeStructuralBuildReceipt> {
    config.validate()?;
    graph_index.ensure_snapshot(snapshot)?;
    inventory
        .invalidate_stale(snapshot.descriptor())
        .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
    let config_digest = config.canonical_digest();
    let descriptor = VectorSpaceDescriptor::ultraballoon_native_structural(config_digest);
    let (space_id, _outcome) = vector_store.create_space(descriptor)?;

    let records = snapshot
        .records()
        .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;
    let edge_count = graph_index.outgoing.values().map(Vec::len).sum::<usize>();
    let mut graph = if edge_count == 0 {
        None
    } else {
        Some(Graph::open(graph_index.layout_path()).map_err(VectorStoreError::Lifecycle)?)
    };

    let mut batch = Vec::with_capacity(records.len());
    for record in &records {
        let vector = structural_vector(record, graph_index, graph.as_mut(), config)?;
        batch.push(VectorInput::new(record.record_id.clone(), vector));
    }
    batch.sort_by(|left, right| left.record_id.cmp(&right.record_id));

    let import_key = format!(
        "native-v1-{}-{}",
        hex_digest(&snapshot.descriptor().snapshot_sha256),
        hex_digest(&config_digest),
    );
    let import_outcome = vector_store.import_vectors(snapshot, space_id, &import_key, &batch)?;
    let generation = vector_store
        .column_generation(space_id)
        .ok_or_else(|| VectorStoreError::Corrupt("native column generation missing".to_string()))?;
    let column_path = vector_store.column_file_path(space_id)?;
    let database_root = vector_store.root();
    let relative_column = column_path.strip_prefix(database_root).map_err(|_| {
        VectorStoreError::Corrupt("native column escapes vector store root".to_string())
    })?;
    let inventory_outcome = inventory
        .register_complete_file(
            DerivedArtifactKind::VectorColumn,
            generation,
            snapshot.descriptor(),
            relative_column,
            records.len() as u64,
        )
        .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?;

    Ok(NativeStructuralBuildReceipt {
        space_id,
        config_digest,
        database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
        record_count: records.len() as u64,
        column_generation: generation,
        import_outcome,
        inventory_outcome,
        column_sha256: sha256_file(&column_path)?,
    })
}

fn structural_vector(
    record: &DatabaseRecord,
    graph_index: &GraphSnapshotIndex,
    graph: Option<&mut Graph>,
    config: NativeStructuralConfig,
) -> Result<Vec<f32>> {
    let node_id = record.node_id;
    let outgoing = graph_index.outgoing(node_id);
    let incoming = graph_index.incoming(node_id);

    let mut values = vec![0.0f64; NATIVE_STRUCTURAL_DIM as usize];
    values[0] = (outgoing.len() as f64).ln_1p();
    values[1] = (incoming.len() as f64).ln_1p();

    let outgoing_weight = outgoing.iter().map(|edge| edge.weight).sum::<f64>();
    let incoming_weight = incoming.iter().map(|edge| edge.weight).sum::<f64>();
    values[2] = if outgoing.is_empty() {
        0.0
    } else {
        outgoing_weight / outgoing.len() as f64
    };
    values[3] = if incoming.is_empty() {
        0.0
    } else {
        incoming_weight / incoming.len() as f64
    };

    let outgoing_targets = outgoing
        .iter()
        .map(|edge| edge.dst)
        .collect::<BTreeSet<_>>();
    let incoming_sources = incoming
        .iter()
        .map(|edge| edge.src)
        .collect::<BTreeSet<_>>();
    let reciprocal = outgoing_targets.intersection(&incoming_sources).count();
    values[4] = reciprocal as f64;
    values[5] = outgoing_targets.len() as f64;
    values[6] = incoming_sources.len() as f64;

    let mut co_target = 0.0f64;
    for edge in outgoing {
        co_target += graph_index.incoming(edge.dst).len().saturating_sub(1) as f64;
    }
    values[7] = co_target.ln_1p();

    for edge in outgoing {
        let bucket = 8 + (edge.edge_type as usize % 8);
        values[bucket] += edge.weight.max(0.0);
    }
    for edge in incoming {
        let bucket = 16 + (edge.edge_type as usize % 8);
        values[bucket] += edge.weight.max(0.0);
    }

    let wave_rows = if let Some(graph) = graph {
        graph
            .wave_activation_l3(
                &[node_id],
                config.wave.max_steps,
                config.wave.energy_threshold,
                config.wave.candidate_limit,
                config.wave.edge_mask,
                config.wave.rigor_multiplier,
            )
            .0
    } else {
        Vec::new()
    };
    for row in &wave_rows {
        let depth = row.best_path.len().min(3);
        values[24 + depth] += row.energy.max(0.0);
        values[36 + depth] += 1.0;
        if let Some(last_edge_type) = row.best_path.last() {
            let bucket = 28 + (*last_edge_type as usize % 8);
            values[bucket] += row.energy.max(0.0);
        }
    }

    for first in outgoing {
        for second in graph_index.outgoing(first.dst) {
            let hash = (first.edge_type as usize * 131 + second.edge_type as usize * 17) % 8;
            values[40 + hash] += first.weight.max(0.0) * second.weight.max(0.0);
        }
    }

    if values.iter().all(|value| *value == 0.0) {
        values[24] = 1.0;
        values[36] = 1.0;
    }

    let norm = values.iter().map(|value| value * value).sum::<f64>().sqrt();
    if norm == 0.0 || !norm.is_finite() {
        return Err(VectorStoreError::Invalid(
            "native structural vector has invalid norm".to_string(),
        ));
    }
    Ok(values
        .into_iter()
        .map(|value| (value / norm) as f32)
        .collect())
}

#[derive(Clone, Debug, PartialEq)]
pub struct TopologicalHit {
    pub record_id: String,
    pub node_id: u64,
    pub rank: usize,
    pub wave: WaveEvidence,
    pub trust: TrustView,
    pub database_snapshot_sha256: [u8; 32],
}

pub fn query_topological(
    snapshot: &ReadSnapshot<'_>,
    graph_index: &GraphSnapshotIndex,
    anchor_record_id: &str,
    config: GraphScopeConfig,
    ledger: Option<&TrustLedger>,
    trust_filter: TrustFilter,
    unknown_policy: UnknownTrustPolicy,
    k: usize,
) -> Result<Vec<TopologicalHit>> {
    if k == 0 {
        return Err(VectorStoreError::Invalid(
            "topological k must be positive".to_string(),
        ));
    }
    let scope = build_wave_scope(snapshot, graph_index, anchor_record_id, config)?;
    let mut rows = Vec::new();
    for evidence in scope.candidates.values() {
        let Some(trust) = trust_view(&evidence.record_id, ledger, unknown_policy) else {
            continue;
        };
        if !trust_allows(&trust, trust_filter) {
            continue;
        }
        rows.push((evidence.clone(), trust));
    }
    rows.sort_by(
        |left, right| match right.0.energy.total_cmp(&left.0.energy) {
            Ordering::Equal => left.0.record_id.cmp(&right.0.record_id),
            ordering => ordering,
        },
    );
    rows.truncate(k.min(rows.len()));
    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(index, (wave, trust))| TopologicalHit {
            record_id: wave.record_id.clone(),
            node_id: wave.node_id,
            rank: index + 1,
            wave,
            trust,
            database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq)]
pub struct SemanticEvidenceHit {
    pub vector: VectorHit,
    pub wave: Option<WaveEvidence>,
    pub trust: TrustView,
}

pub fn query_semantic_exact(
    snapshot: &ReadSnapshot<'_>,
    vector_store: &VectorStore,
    space_id: SpaceId,
    query_vector: &[f32],
    k: usize,
    scope: Option<&WaveScope>,
    ledger: Option<&TrustLedger>,
    trust_filter: TrustFilter,
    unknown_policy: UnknownTrustPolicy,
) -> Result<Vec<SemanticEvidenceHit>> {
    if let Some(scope) = scope {
        if scope.database_snapshot_sha256 != snapshot.descriptor().snapshot_sha256 {
            return Err(VectorStoreError::Conflict(
                "Wave scope and ReadSnapshot differ".to_string(),
            ));
        }
    }
    let allowed = scope.map(WaveScope::allowed_record_ids);
    let requested = if allowed.is_some() {
        allowed.as_ref().map(BTreeSet::len).unwrap_or(k)
    } else {
        vector_store
            .columns
            .get(&space_id)
            .map(|column| column.record_ids.len())
            .unwrap_or(k)
    };
    let vector_hits = vector_store.find_exact_in_records_routed(
        snapshot,
        space_id,
        query_vector,
        requested.max(k),
        allowed.as_ref(),
    )?;

    let mut results = Vec::new();
    for vector in vector_hits {
        let Some(trust) = trust_view(&vector.record_id, ledger, unknown_policy) else {
            continue;
        };
        if !trust_allows(&trust, trust_filter) {
            continue;
        }
        let wave = scope
            .and_then(|value| value.evidence(&vector.record_id))
            .cloned();
        results.push(SemanticEvidenceHit {
            vector,
            wave,
            trust,
        });
        if results.len() >= k {
            break;
        }
    }
    Ok(results)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HybridWeights {
    pub external: f64,
    pub native: f64,
    pub wave: f64,
}

impl Default for HybridWeights {
    fn default() -> Self {
        Self {
            external: 1.0,
            native: 1.0,
            wave: 1.0,
        }
    }
}

impl HybridWeights {
    pub fn validate(&self) -> Result<()> {
        let values = [self.external, self.native, self.wave];
        if values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
            || values.iter().sum::<f64>() <= 0.0
        {
            return Err(VectorStoreError::Invalid(
                "hybrid weights must be finite, non-negative and not all zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HybridHit {
    pub record_id: String,
    pub node_id: u64,
    pub rank: usize,
    pub hybrid_score: f64,
    pub external_similarity: Option<f64>,
    pub native_similarity: Option<f64>,
    pub wave_energy: f64,
    pub wave: WaveEvidence,
    pub trust: TrustView,
    pub external_exact: bool,
    pub native_exact: bool,
    pub database_snapshot_sha256: [u8; 32],
}

pub const HYBRID_QUERY_RECEIPT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct HybridQueryReceipt {
    pub schema_version: u16,
    pub database_snapshot_sha256: [u8; 32],
    pub graph_config_digest: [u8; 32],
    pub external_router: CpuGpuRouterReceipt,
    pub native_router: CpuGpuRouterReceipt,
    pub weights: HybridWeights,
    pub trust_filter: TrustFilter,
    pub unknown_trust_policy: UnknownTrustPolicy,
    pub trust_ledger_head_digest: [u8; 32],
    pub trust_in_numeric_score: bool,
    pub wave_enabled: bool,
    pub native_structural_enabled: bool,
    pub deterministic_total_cmp_and_record_id_tie_break: bool,
    pub ann_used: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HybridQueryResult {
    pub hits: Vec<HybridHit>,
    pub receipt: HybridQueryReceipt,
}

pub fn query_hybrid(
    snapshot: &ReadSnapshot<'_>,
    vector_store: &VectorStore,
    graph_index: &GraphSnapshotIndex,
    anchor_record_id: &str,
    external_space_id: SpaceId,
    external_query_vector: &[f32],
    native_space_id: SpaceId,
    graph_config: GraphScopeConfig,
    weights: HybridWeights,
    ledger: Option<&TrustLedger>,
    trust_filter: TrustFilter,
    unknown_policy: UnknownTrustPolicy,
    k: usize,
) -> Result<Vec<HybridHit>> {
    Ok(query_hybrid_with_receipt(
        snapshot,
        vector_store,
        graph_index,
        anchor_record_id,
        external_space_id,
        external_query_vector,
        native_space_id,
        graph_config,
        weights,
        ledger,
        trust_filter,
        unknown_policy,
        k,
    )?
    .hits)
}

pub fn query_hybrid_with_receipt(
    snapshot: &ReadSnapshot<'_>,
    vector_store: &VectorStore,
    graph_index: &GraphSnapshotIndex,
    anchor_record_id: &str,
    external_space_id: SpaceId,
    external_query_vector: &[f32],
    native_space_id: SpaceId,
    graph_config: GraphScopeConfig,
    weights: HybridWeights,
    ledger: Option<&TrustLedger>,
    trust_filter: TrustFilter,
    unknown_policy: UnknownTrustPolicy,
    k: usize,
) -> Result<HybridQueryResult> {
    if k == 0 {
        return Err(VectorStoreError::Invalid(
            "hybrid k must be positive".to_string(),
        ));
    }
    weights.validate()?;
    let scope = build_wave_scope(snapshot, graph_index, anchor_record_id, graph_config)?;
    let allowed = scope.allowed_record_ids();

    let external_routed = vector_store.find_exact_routed_with_receipt(
        snapshot,
        external_space_id,
        external_query_vector,
        allowed.len().max(1),
        Some(&allowed),
    )?;
    let external_router = external_routed.receipt;
    let external_hits = external_routed.hits;
    let native_query = vector_store
        .vector_for_record(native_space_id, anchor_record_id)?
        .ok_or_else(|| {
            VectorStoreError::NotFound(format!("anchor native vector {anchor_record_id}"))
        })?;
    let native_routed = vector_store.find_exact_routed_with_receipt(
        snapshot,
        native_space_id,
        &native_query,
        allowed.len().max(1),
        Some(&allowed),
    )?;
    let native_router = native_routed.receipt;
    let native_hits = native_routed.hits;

    let external = external_hits
        .into_iter()
        .map(|hit| (hit.record_id.clone(), hit))
        .collect::<BTreeMap<_, _>>();
    let native = native_hits
        .into_iter()
        .map(|hit| (hit.record_id.clone(), hit))
        .collect::<BTreeMap<_, _>>();

    let mut results = Vec::new();
    for (record_id, wave) in &scope.candidates {
        let Some(trust) = trust_view(record_id, ledger, unknown_policy) else {
            continue;
        };
        if !trust_allows(&trust, trust_filter) {
            continue;
        }

        let external_hit = external.get(record_id);
        let native_hit = native.get(record_id);
        let mut numerator = 0.0f64;
        let mut denominator = 0.0f64;

        if let Some(hit) = external_hit {
            numerator += normalized_cosine(hit.cosine_score) * weights.external;
            denominator += weights.external;
        }
        if let Some(hit) = native_hit {
            numerator += normalized_cosine(hit.cosine_score) * weights.native;
            denominator += weights.native;
        }
        numerator += wave.energy.clamp(0.0, 1.0) * weights.wave;
        denominator += weights.wave;

        if denominator == 0.0 {
            continue;
        }
        results.push(HybridHit {
            record_id: record_id.clone(),
            node_id: wave.node_id,
            rank: 0,
            hybrid_score: numerator / denominator,
            external_similarity: external_hit.map(|hit| hit.cosine_score),
            native_similarity: native_hit.map(|hit| hit.cosine_score),
            wave_energy: wave.energy,
            wave: wave.clone(),
            trust,
            external_exact: external_hit.map(|hit| hit.exact).unwrap_or(false),
            native_exact: native_hit.map(|hit| hit.exact).unwrap_or(false),
            database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
        });
    }

    results.sort_by(
        |left, right| match right.hybrid_score.total_cmp(&left.hybrid_score) {
            Ordering::Equal => left.record_id.cmp(&right.record_id),
            ordering => ordering,
        },
    );
    results.truncate(k.min(results.len()));
    for (index, hit) in results.iter_mut().enumerate() {
        hit.rank = index + 1;
    }
    let receipt = HybridQueryReceipt {
        schema_version: HYBRID_QUERY_RECEIPT_SCHEMA_VERSION,
        database_snapshot_sha256: snapshot.descriptor().snapshot_sha256,
        graph_config_digest: scope.config_digest,
        external_router,
        native_router,
        weights,
        trust_filter,
        unknown_trust_policy: unknown_policy,
        trust_ledger_head_digest: ledger.map(TrustLedger::head_digest).unwrap_or([0u8; 32]),
        trust_in_numeric_score: false,
        wave_enabled: true,
        native_structural_enabled: true,
        deterministic_total_cmp_and_record_id_tie_break: true,
        ann_used: false,
    };
    Ok(HybridQueryResult {
        hits: results,
        receipt,
    })
}

fn normalized_cosine(value: f64) -> f64 {
    ((value + 1.0) * 0.5).clamp(0.0, 1.0)
}

fn build_record_maps(
    records: &[DatabaseRecord],
) -> Result<(BTreeMap<String, u64>, BTreeMap<u64, String>)> {
    let mut record_to_node = BTreeMap::new();
    let mut node_to_record = BTreeMap::new();
    for record in records {
        if record_to_node
            .insert(record.record_id.clone(), record.node_id)
            .is_some()
        {
            return Err(VectorStoreError::Corrupt(
                "duplicate record ID in ReadSnapshot".to_string(),
            ));
        }
        if node_to_record
            .insert(record.node_id, record.record_id.clone())
            .is_some()
        {
            return Err(VectorStoreError::Corrupt(
                "duplicate node ID in ReadSnapshot".to_string(),
            ));
        }
    }
    Ok((record_to_node, node_to_record))
}

type Adjacency = (
    BTreeMap<u64, Vec<DatabaseEdge>>,
    BTreeMap<u64, Vec<DatabaseEdge>>,
);

fn build_adjacency(nodes: &BTreeMap<u64, String>, edges: &[DatabaseEdge]) -> Result<Adjacency> {
    let mut outgoing: BTreeMap<u64, Vec<DatabaseEdge>> =
        nodes.keys().map(|node| (*node, Vec::new())).collect();
    let mut incoming: BTreeMap<u64, Vec<DatabaseEdge>> =
        nodes.keys().map(|node| (*node, Vec::new())).collect();

    for edge in edges {
        if !nodes.contains_key(&edge.src) || !nodes.contains_key(&edge.dst) {
            return Err(VectorStoreError::Corrupt(format!(
                "edge {} references a missing node",
                edge.logical_id
            )));
        }
        if !edge.weight.is_finite() || edge.weight < 0.0 {
            return Err(VectorStoreError::Corrupt(format!(
                "edge {} has invalid weight",
                edge.logical_id
            )));
        }
        outgoing
            .get_mut(&edge.src)
            .expect("validated source node")
            .push(edge.clone());
        incoming
            .get_mut(&edge.dst)
            .expect("validated destination node")
            .push(edge.clone());
    }

    for values in outgoing.values_mut() {
        sort_edges(values);
    }
    for values in incoming.values_mut() {
        sort_edges(values);
    }
    Ok((outgoing, incoming))
}

fn sort_edges(edges: &mut [DatabaseEdge]) {
    edges.sort_by(|left, right| {
        left.src
            .cmp(&right.src)
            .then_with(|| left.dst.cmp(&right.dst))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.weight.to_bits().cmp(&right.weight.to_bits()))
            .then_with(|| left.logical_id.cmp(&right.logical_id))
    });
}

fn encode_csr(
    records: &[DatabaseRecord],
    outgoing: &BTreeMap<u64, Vec<DatabaseEdge>>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut sorted_records = records.to_vec();
    sorted_records.sort_by_key(|record| record.node_id);

    let mut nodes = Vec::with_capacity(sorted_records.len() * GRAPH_NODE_BYTES);
    let edge_count = outgoing.values().map(Vec::len).sum::<usize>();
    let mut edges = Vec::with_capacity(edge_count * GRAPH_EDGE_BYTES);
    let mut first = 0u64;

    for record in sorted_records {
        let values = outgoing
            .get(&record.node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        nodes.extend_from_slice(&record.node_id.to_le_bytes());
        nodes.extend_from_slice(&first.to_le_bytes());
        nodes.extend_from_slice(&(values.len() as u64).to_le_bytes());
        for edge in values {
            edges.extend_from_slice(&edge.dst.to_le_bytes());
            edges.extend_from_slice(&edge.edge_type.to_le_bytes());
            edges.extend_from_slice(&1u32.to_le_bytes());
            edges.extend_from_slice(&edge.weight.to_le_bytes());
        }
        first = first
            .checked_add(values.len() as u64)
            .ok_or_else(|| VectorStoreError::Invalid("CSR edge offset overflow".to_string()))?;
    }
    Ok((nodes, edges))
}

#[derive(Clone, Debug)]
struct GraphManifest {
    database_snapshot_sha256: [u8; 32],
    record_count: u64,
    edge_count: u64,
    nodes_sha256: [u8; 32],
    edges_sha256: [u8; 32],
}

fn encode_graph_manifest(
    snapshot_sha256: [u8; 32],
    record_count: u64,
    edge_count: u64,
    nodes_sha256: [u8; 32],
    edges_sha256: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&GRAPH_MANIFEST_MAGIC);
    body.extend_from_slice(&GRAPH_SNAPSHOT_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&snapshot_sha256);
    body.extend_from_slice(&record_count.to_le_bytes());
    body.extend_from_slice(&edge_count.to_le_bytes());
    body.extend_from_slice(&nodes_sha256);
    body.extend_from_slice(&edges_sha256);
    let footer = sha256(&body);
    body.extend_from_slice(&footer);
    body
}

fn decode_graph_manifest(bytes: &[u8]) -> Result<GraphManifest> {
    const BODY_SIZE: usize = 8 + 2 + 2 + 32 + 8 + 8 + 32 + 32;
    if bytes.len() != BODY_SIZE + 32 {
        return Err(VectorStoreError::Corrupt(
            "graph manifest size mismatch".to_string(),
        ));
    }
    let (body, footer) = bytes.split_at(BODY_SIZE);
    let expected_footer = sha256(body);
    if expected_footer.as_slice() != footer {
        return Err(VectorStoreError::Corrupt(
            "graph manifest SHA footer mismatch".to_string(),
        ));
    }
    if &body[..8] != GRAPH_MANIFEST_MAGIC.as_slice() {
        return Err(VectorStoreError::Corrupt(
            "graph manifest magic mismatch".to_string(),
        ));
    }
    let version = u16::from_le_bytes([body[8], body[9]]);
    let reserved = u16::from_le_bytes([body[10], body[11]]);
    if version != GRAPH_SNAPSHOT_FORMAT_VERSION || reserved != 0 {
        return Err(VectorStoreError::Corrupt(
            "graph manifest version/reserved mismatch".to_string(),
        ));
    }
    let mut snapshot = [0u8; 32];
    snapshot.copy_from_slice(&body[12..44]);
    let mut record_raw = [0u8; 8];
    record_raw.copy_from_slice(&body[44..52]);
    let mut edge_raw = [0u8; 8];
    edge_raw.copy_from_slice(&body[52..60]);
    let mut nodes = [0u8; 32];
    nodes.copy_from_slice(&body[60..92]);
    let mut edges = [0u8; 32];
    edges.copy_from_slice(&body[92..124]);
    Ok(GraphManifest {
        database_snapshot_sha256: snapshot,
        record_count: u64::from_le_bytes(record_raw),
        edge_count: u64::from_le_bytes(edge_raw),
        nodes_sha256: nodes,
        edges_sha256: edges,
    })
}

fn verify_graph_snapshot_files(
    manifest_path: &Path,
    nodes_path: &Path,
    edges_path: &Path,
    expected_snapshot_sha256: [u8; 32],
    expected_record_count: u64,
    expected_edge_count: u64,
) -> Result<()> {
    for path in [manifest_path, nodes_path, edges_path] {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(VectorStoreError::Corrupt(format!(
                "graph snapshot path is not a regular file: {}",
                path.display()
            )));
        }
    }
    let manifest = decode_graph_manifest(&fs::read(manifest_path)?)?;
    if manifest.database_snapshot_sha256 != expected_snapshot_sha256
        || manifest.record_count != expected_record_count
        || manifest.edge_count != expected_edge_count
        || manifest.nodes_sha256 != sha256_file(nodes_path)?
        || manifest.edges_sha256 != sha256_file(edges_path)?
    {
        return Err(VectorStoreError::Corrupt(
            "graph snapshot manifest binding mismatch".to_string(),
        ));
    }
    let nodes_bytes = fs::metadata(nodes_path)?.len();
    let edges_bytes = fs::metadata(edges_path)?.len();
    if nodes_bytes != expected_record_count * GRAPH_NODE_BYTES as u64
        || edges_bytes != expected_edge_count * GRAPH_EDGE_BYTES as u64
    {
        return Err(VectorStoreError::Corrupt(
            "graph snapshot fixed-width size mismatch".to_string(),
        ));
    }
    Ok(())
}

fn write_atomic_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if path.exists() || temporary.exists() {
        return Err(VectorStoreError::Conflict(format!(
            "graph snapshot target already exists: {}",
            path.display()
        )));
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    Ok(())
}
