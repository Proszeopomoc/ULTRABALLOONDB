use ultraballoondb_lifecycle::ReadSnapshot;
use ultraballoondb_semantic::{
    query_hybrid_with_receipt, CpuGpuRouterReceipt, ExactComputeBackend, GraphScopeConfig,
    GraphSnapshotIndex, HybridHit, HybridWeights, Result, SpaceId, TrustFilter, UnknownTrustPolicy,
    VectorStore, VectorStoreError,
};
use ultraballoondb_trust::TrustLedger;

pub const PRODUCT_HYBRID_ENGINE_SCHEMA_VERSION: u16 = 1;
pub const PRODUCT_HYBRID_ENGINE_NAME: &str = "ULTRABALLOONDB_PRODUCT_HYBRID_ENGINE_V1";
pub const PRODUCT_HYBRID_ENGINE_TRUST_IN_NUMERIC_SCORE: bool = false;
pub const PRODUCT_HYBRID_ENGINE_ANN_USED: bool = false;

#[derive(Clone, Debug, PartialEq)]
pub struct ProductHybridReceipt {
    pub schema_version: u16,
    pub engine_name: &'static str,
    pub database_snapshot_sha256: [u8; 32],
    pub graph_snapshot_sha256: [u8; 32],
    pub graph_config_digest: [u8; 32],
    pub external_space_id: SpaceId,
    pub native_space_id: SpaceId,
    pub weights: HybridWeights,
    pub external_router: CpuGpuRouterReceipt,
    pub native_router: CpuGpuRouterReceipt,
    pub external_exact_backend_valid: bool,
    pub native_exact_backend_valid: bool,
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
pub struct ProductHybridResponse {
    pub hits: Vec<HybridHit>,
    pub receipt: ProductHybridReceipt,
}

fn exact_backend_valid(receipt: &CpuGpuRouterReceipt) -> bool {
    match receipt.selected_backend {
        ExactComputeBackend::CpuExact => true,
        ExactComputeBackend::OpenClFp64 => receipt.exact_parity_certified,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_product_hybrid_query(
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
) -> Result<ProductHybridResponse> {
    let database_snapshot_sha256 = snapshot.descriptor().snapshot_sha256;
    let graph_snapshot_sha256 = graph_index.database_snapshot_sha256();
    if graph_snapshot_sha256 != database_snapshot_sha256 {
        return Err(VectorStoreError::Conflict(
            "product hybrid engine requires graph and database snapshots to match".to_string(),
        ));
    }

    let query = query_hybrid_with_receipt(
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
    )?;

    let hits = query.hits;
    let hybrid_receipt = query.receipt;

    if hybrid_receipt.trust_in_numeric_score {
        return Err(VectorStoreError::Conflict(
            "product hybrid engine forbids Trust in numeric ranking score".to_string(),
        ));
    }
    if hybrid_receipt.ann_used {
        return Err(VectorStoreError::Conflict(
            "product hybrid engine canonical path forbids ANN".to_string(),
        ));
    }
    let external_exact_backend_valid = exact_backend_valid(&hybrid_receipt.external_router);
    let native_exact_backend_valid = exact_backend_valid(&hybrid_receipt.native_router);
    if !external_exact_backend_valid || !native_exact_backend_valid {
        return Err(VectorStoreError::Conflict(
            "product hybrid engine requires CPU exact or parity-certified OpenCL".to_string(),
        ));
    }

    let receipt = ProductHybridReceipt {
        schema_version: PRODUCT_HYBRID_ENGINE_SCHEMA_VERSION,
        engine_name: PRODUCT_HYBRID_ENGINE_NAME,
        database_snapshot_sha256,
        graph_snapshot_sha256,
        graph_config_digest: hybrid_receipt.graph_config_digest,
        external_space_id,
        native_space_id,
        weights,
        external_router: hybrid_receipt.external_router,
        native_router: hybrid_receipt.native_router,
        external_exact_backend_valid,
        native_exact_backend_valid,
        trust_filter: hybrid_receipt.trust_filter,
        unknown_trust_policy: hybrid_receipt.unknown_trust_policy,
        trust_ledger_head_digest: hybrid_receipt.trust_ledger_head_digest,
        trust_in_numeric_score: PRODUCT_HYBRID_ENGINE_TRUST_IN_NUMERIC_SCORE,
        wave_enabled: hybrid_receipt.wave_enabled,
        native_structural_enabled: hybrid_receipt.native_structural_enabled,
        deterministic_total_cmp_and_record_id_tie_break: hybrid_receipt
            .deterministic_total_cmp_and_record_id_tie_break,
        ann_used: PRODUCT_HYBRID_ENGINE_ANN_USED,
    };

    Ok(ProductHybridResponse { hits, receipt })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_contract_keeps_trust_out_of_numeric_score() {
        assert!(!PRODUCT_HYBRID_ENGINE_TRUST_IN_NUMERIC_SCORE);
    }

    #[test]
    fn cpu_exact_requires_no_gpu_parity_certificate() {
        let receipt = CpuGpuRouterReceipt {
            schema_version: 1,
            selected_backend: ExactComputeBackend::CpuExact,
            candidate_count: 1,
            dimension: 1,
            k: 1,
            database_snapshot_sha256: [0u8; 32],
            exact_parity_certified: false,
            cpu_fallback: false,
            fallback_reason: None,
            device_name: None,
            kernel_sha256: [0u8; 32],
            measured_crossover_candidates: None,
            batch_bytes: 4,
        };
        assert!(exact_backend_valid(&receipt));
    }

    #[test]
    fn product_contract_uses_no_ann() {
        assert!(!PRODUCT_HYBRID_ENGINE_ANN_USED);
    }

    #[test]
    fn product_contract_has_stable_schema_identity() {
        assert_eq!(PRODUCT_HYBRID_ENGINE_SCHEMA_VERSION, 1);
        assert_eq!(
            PRODUCT_HYBRID_ENGINE_NAME,
            "ULTRABALLOONDB_PRODUCT_HYBRID_ENGINE_V1"
        );
    }
}
