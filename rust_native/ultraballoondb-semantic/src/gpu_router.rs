use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::mem::size_of;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use ultraballoondb_lifecycle::ReadSnapshot;
use ultraballoondb_storage::{hex_digest, sha256};

use super::{
    cosine_with_query_norm, squared_norm, validate_vector, Result, SpaceId, VectorHit,
    VectorStore, VectorStoreError, MAX_TOP_K,
};

pub const CPU_GPU_ROUTER_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_GPU_BOOTSTRAP_CANDIDATES: usize = 4_096;
pub const DEFAULT_GPU_MAX_BATCH_BYTES: usize = 512 * 1024 * 1024;
pub const GPU_CROSSOVER_REPEAT_COUNT: usize = 3;
pub const GPU_CROSSOVER_REQUIRED_SPEEDUP_PERCENT: u128 = 5;

const OPENCL_KERNEL_SOURCE: &str = r#"
#pragma OPENCL EXTENSION cl_khr_fp64 : enable
#pragma OPENCL FP_CONTRACT OFF
__kernel void ultraballoon_exact_cosine_parts(
    __global const float *query,
    __global const float *vectors,
    const uint dim,
    __global double *dots,
    __global double *norms)
{
    const size_t row = get_global_id(0);
    const size_t base = row * (size_t)dim;
    double dot = 0.0;
    double norm = 0.0;
    for (uint index = 0; index < dim; ++index) {
        const double left = (double)query[index];
        const double right = (double)vectors[base + (size_t)index];
        dot = dot + left * right;
        norm = norm + right * right;
    }
    dots[row] = dot;
    norms[row] = norm;
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactComputeBackend {
    CpuExact,
    OpenClFp64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterMode {
    Auto,
    CpuOnly,
    ForceGpuProbe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuGpuRouterConfig {
    pub mode: RouterMode,
    pub bootstrap_candidate_count: usize,
    pub max_batch_bytes: usize,
}

impl Default for CpuGpuRouterConfig {
    fn default() -> Self {
        Self {
            mode: RouterMode::Auto,
            bootstrap_candidate_count: DEFAULT_GPU_BOOTSTRAP_CANDIDATES,
            max_batch_bytes: DEFAULT_GPU_MAX_BATCH_BYTES,
        }
    }
}

impl CpuGpuRouterConfig {
    pub fn from_environment() -> Self {
        let mut value = Self::default();
        if let Ok(mode) = env::var("ULTRABALLOONDB_GPU_ROUTER") {
            value.mode = match mode.trim().to_ascii_lowercase().as_str() {
                "cpu" | "off" | "disabled" => RouterMode::CpuOnly,
                "gpu" | "force-gpu" | "probe" => RouterMode::ForceGpuProbe,
                _ => RouterMode::Auto,
            };
        }
        if let Ok(raw) = env::var("ULTRABALLOONDB_GPU_BOOTSTRAP_CANDIDATES") {
            if let Ok(parsed) = raw.trim().parse::<usize>() {
                value.bootstrap_candidate_count = parsed.max(1);
            }
        }
        if let Ok(raw) = env::var("ULTRABALLOONDB_GPU_MAX_BATCH_BYTES") {
            if let Ok(parsed) = raw.trim().parse::<usize>() {
                value.max_batch_bytes = parsed.max(1024 * 1024);
            }
        }
        value
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuGpuRouterReceipt {
    pub schema_version: u16,
    pub selected_backend: ExactComputeBackend,
    pub candidate_count: usize,
    pub dimension: usize,
    pub k: usize,
    pub database_snapshot_sha256: [u8; 32],
    pub exact_parity_certified: bool,
    pub cpu_fallback: bool,
    pub fallback_reason: Option<String>,
    pub device_name: Option<String>,
    pub kernel_sha256: [u8; 32],
    pub measured_crossover_candidates: Option<usize>,
    pub batch_bytes: usize,
}

impl CpuGpuRouterReceipt {
    pub fn database_snapshot_sha256_hex(&self) -> String {
        hex_digest(&self.database_snapshot_sha256)
    }

    pub fn kernel_sha256_hex(&self) -> String {
        hex_digest(&self.kernel_sha256)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoutedVectorHits {
    pub hits: Vec<VectorHit>,
    pub receipt: CpuGpuRouterReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterBenchmarkRow {
    pub candidate_count: usize,
    pub dimension: usize,
    pub cpu_elapsed_ns: u128,
    pub gpu_elapsed_ns: u128,
    pub exact_parity: bool,
    pub gpu_faster: bool,
    pub host_pack_included: bool,
    pub end_to_end: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuGpuRouterProbeReport {
    pub schema_version: u16,
    pub opencl_available: bool,
    pub fp64_available: bool,
    pub exact_parity_certified: bool,
    pub cpu_fallback_contract: bool,
    pub ann_used: bool,
    pub trust_in_score: bool,
    pub device_name: Option<String>,
    pub kernel_sha256: [u8; 32],
    pub measured_crossover_candidates: Option<usize>,
    pub crossover_includes_host_pack: bool,
    pub crossover_end_to_end: bool,
    pub wave_crossover_reused: bool,
    pub rows: Vec<RouterBenchmarkRow>,
    pub error: Option<String>,
}

impl CpuGpuRouterProbeReport {
    pub fn kernel_sha256_hex(&self) -> String {
        hex_digest(&self.kernel_sha256)
    }

    pub fn to_json(&self) -> String {
        fn escaped(value: &str) -> String {
            let mut out = String::new();
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
                    ch => out.push(ch),
                }
            }
            out
        }

        let device = self
            .device_name
            .as_ref()
            .map(|value| format!("\"{}\"", escaped(value)))
            .unwrap_or_else(|| "null".to_string());
        let error = self
            .error
            .as_ref()
            .map(|value| format!("\"{}\"", escaped(value)))
            .unwrap_or_else(|| "null".to_string());
        let crossover = self
            .measured_crossover_candidates
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_string());
        let rows = self
            .rows
            .iter()
            .map(|row| {
                format!(
                    "{{\"candidate_count\":{},\"dimension\":{},\"cpu_elapsed_ns\":{},\"gpu_elapsed_ns\":{},\"exact_parity\":{},\"gpu_faster\":{},\"host_pack_included\":{},\"end_to_end\":{}}}",
                    row.candidate_count,
                    row.dimension,
                    row.cpu_elapsed_ns,
                    row.gpu_elapsed_ns,
                    row.exact_parity,
                    row.gpu_faster,
                    row.host_pack_included,
                    row.end_to_end,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema_version\":{},\"opencl_available\":{},\"fp64_available\":{},\"exact_parity_certified\":{},\"cpu_fallback_contract\":{},\"ann_used\":{},\"trust_in_score\":{},\"device_name\":{},\"kernel_sha256\":\"{}\",\"measured_crossover_candidates\":{},\"crossover_includes_host_pack\":{},\"crossover_end_to_end\":{},\"wave_crossover_reused\":{},\"rows\":[{}],\"error\":{}}}",
            self.schema_version,
            self.opencl_available,
            self.fp64_available,
            self.exact_parity_certified,
            self.cpu_fallback_contract,
            self.ann_used,
            self.trust_in_score,
            device,
            self.kernel_sha256_hex(),
            crossover,
            self.crossover_includes_host_pack,
            self.crossover_end_to_end,
            self.wave_crossover_reused,
            rows,
            error,
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Calibration {
    crossover_candidates: Option<usize>,
    largest_tested: usize,
}

#[derive(Default)]
struct RouterState {
    engine: Option<platform::OpenClEngine>,
    disabled_reason: Option<String>,
    parity_certified: bool,
    device_name: Option<String>,
    calibrations: BTreeMap<usize, Calibration>,
}

static ROUTER_STATE: OnceLock<Mutex<RouterState>> = OnceLock::new();

fn router_state() -> &'static Mutex<RouterState> {
    ROUTER_STATE.get_or_init(|| Mutex::new(RouterState::default()))
}

impl RouterState {
    fn ensure_engine(&mut self) -> std::result::Result<&mut platform::OpenClEngine, String> {
        if let Some(reason) = &self.disabled_reason {
            return Err(reason.clone());
        }
        if self.engine.is_none() {
            let mut engine = platform::OpenClEngine::new(OPENCL_KERNEL_SOURCE)?;
            certify_engine_exact_parity(&mut engine)?;
            self.device_name = Some(engine.device_name().to_string());
            self.parity_certified = true;
            self.engine = Some(engine);
        }
        self.engine
            .as_mut()
            .ok_or_else(|| "OpenCL engine unavailable after initialization".to_string())
    }

    fn disable(&mut self, reason: String) {
        self.engine = None;
        self.parity_certified = false;
        self.disabled_reason = Some(reason);
    }
}

impl VectorStore {
    pub fn find_exact_routed(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        query_vector: &[f32],
        k: usize,
    ) -> Result<Vec<VectorHit>> {
        Ok(self
            .find_exact_routed_with_receipt(snapshot, space_id, query_vector, k, None)?
            .hits)
    }

    pub fn find_exact_in_records_routed(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        query_vector: &[f32],
        k: usize,
        allowed_record_ids: Option<&BTreeSet<String>>,
    ) -> Result<Vec<VectorHit>> {
        Ok(self
            .find_exact_routed_with_receipt(
                snapshot,
                space_id,
                query_vector,
                k,
                allowed_record_ids,
            )?
            .hits)
    }

    pub fn find_exact_routed_with_receipt(
        &self,
        snapshot: &ReadSnapshot<'_>,
        space_id: SpaceId,
        query_vector: &[f32],
        k: usize,
        allowed_record_ids: Option<&BTreeSet<String>>,
    ) -> Result<RoutedVectorHits> {
        if k == 0 || k > MAX_TOP_K {
            return Err(VectorStoreError::Invalid(format!(
                "k must be in 1..={MAX_TOP_K}"
            )));
        }
        let descriptor = self
            .registry
            .get(&space_id)
            .ok_or_else(|| VectorStoreError::NotFound(format!("space {}", space_id.to_hex())))?;
        validate_vector(query_vector, descriptor.dim)?;
        let column = self.columns.get(&space_id).ok_or_else(|| {
            VectorStoreError::Corrupt("registered space has no loaded column".to_string())
        })?;

        let mut indices = Vec::new();
        for (index, record_id) in column.record_ids.iter().enumerate() {
            if let Some(allowed) = allowed_record_ids {
                if !allowed.contains(record_id) {
                    continue;
                }
            }
            if snapshot
                .record(record_id)
                .map_err(|error| VectorStoreError::Lifecycle(error.to_string()))?
                .is_some()
            {
                indices.push(index);
            }
        }

        let dimension = descriptor.dim as usize;
        let batch_bytes = checked_batch_bytes(indices.len(), dimension)?;
        let config = CpuGpuRouterConfig::from_environment();
        let kernel_sha256 = sha256(OPENCL_KERNEL_SOURCE.as_bytes());
        let snapshot_sha256 = snapshot.descriptor().snapshot_sha256;

        let cpu = |reason: Option<String>, crossover: Option<usize>| -> Result<RoutedVectorHits> {
            let hits = score_cpu(
                query_vector,
                &indices,
                column,
                k,
                space_id,
                snapshot_sha256,
            );
            Ok(RoutedVectorHits {
                hits,
                receipt: CpuGpuRouterReceipt {
                    schema_version: CPU_GPU_ROUTER_SCHEMA_VERSION,
                    selected_backend: ExactComputeBackend::CpuExact,
                    candidate_count: indices.len(),
                    dimension,
                    k,
                    database_snapshot_sha256: snapshot_sha256,
                    exact_parity_certified: false,
                    cpu_fallback: reason.is_some(),
                    fallback_reason: reason,
                    device_name: None,
                    kernel_sha256,
                    measured_crossover_candidates: crossover,
                    batch_bytes,
                },
            })
        };

        if indices.is_empty() {
            return cpu(None, None);
        }
        if config.mode == RouterMode::CpuOnly {
            return cpu(Some("router configured for CPU-only execution".to_string()), None);
        }
        if batch_bytes > config.max_batch_bytes {
            return cpu(
                Some(format!(
                    "GPU batch bytes {batch_bytes} exceed configured maximum {}",
                    config.max_batch_bytes
                )),
                None,
            );
        }
        if config.mode == RouterMode::Auto
            && indices.len() < config.bootstrap_candidate_count
        {
            return cpu(
                Some(format!(
                    "candidate count {} below GPU bootstrap threshold {}",
                    indices.len(), config.bootstrap_candidate_count
                )),
                None,
            );
        }

        let host_pack_start = Instant::now();
        let mut flat = Vec::with_capacity(indices.len().saturating_mul(dimension));
        for index in &indices {
            flat.extend_from_slice(column.vector_at(*index));
        }
        let host_pack_elapsed_ns = host_pack_start.elapsed().as_nanos();

        let mut guard = router_state()
            .lock()
            .map_err(|_| VectorStoreError::Conflict("CPU/GPU router lock poisoned".to_string()))?;
        let device_name;
        {
            let engine = match guard.ensure_engine() {
                Ok(engine) => engine,
                Err(reason) => return cpu(Some(reason), None),
            };
            device_name = Some(engine.device_name().to_string());
        }

        let calibration = guard.calibrations.get(&dimension).copied();
        let needs_calibration = match calibration {
            None => true,
            Some(value) => {
                value.crossover_candidates.is_none() && indices.len() > value.largest_tested
            }
        };
        if needs_calibration {
            let result = {
                let engine = guard
                    .engine
                    .as_mut()
                    .ok_or_else(|| VectorStoreError::Conflict("OpenCL engine missing".to_string()))?;
                calibrate_on_query(
                    engine,
                    query_vector,
                    &flat,
                    dimension,
                    indices.len(),
                    host_pack_elapsed_ns,
                )
            };
            match result {
                Ok(value) => {
                    guard.calibrations.insert(dimension, value);
                }
                Err(reason) => {
                    guard.disable(reason.clone());
                    return cpu(Some(reason), None);
                }
            }
        }

        let calibration = guard
            .calibrations
            .get(&dimension)
            .copied()
            .unwrap_or(Calibration {
                crossover_candidates: None,
                largest_tested: 0,
            });
        if config.mode == RouterMode::Auto {
            match calibration.crossover_candidates {
                Some(crossover) if indices.len() >= crossover => {}
                Some(crossover) => {
                    return cpu(
                        Some(format!(
                            "candidate count {} below measured GPU crossover {crossover}",
                            indices.len()
                        )),
                        Some(crossover),
                    )
                }
                None => {
                    return cpu(
                        Some(format!(
                            "GPU did not beat CPU through {} tested candidates",
                            calibration.largest_tested
                        )),
                        None,
                    )
                }
            }
        }

        let parts_result = {
            let engine = guard
                .engine
                .as_mut()
                .ok_or_else(|| VectorStoreError::Conflict("OpenCL engine missing".to_string()))?;
            engine.exact_parts(query_vector, &flat, dimension, indices.len())
        };
        let parts = match parts_result {
            Ok(value) => value,
            Err(reason) => {
                guard.disable(reason.clone());
                return cpu(Some(reason), calibration.crossover_candidates);
            }
        };

        if let Err(reason) = verify_query_samples(query_vector, &flat, dimension, &parts) {
            guard.disable(reason.clone());
            return cpu(Some(reason), calibration.crossover_candidates);
        }
        let parity_certified = guard.parity_certified;
        drop(guard);

        let query_norm = squared_norm(query_vector);
        let mut scored = Vec::with_capacity(indices.len());
        for (position, index) in indices.iter().enumerate() {
            let (dot, norm) = parts[position];
            let score = dot / (query_norm.sqrt() * norm.sqrt());
            scored.push((column.record_ids[*index].clone(), score));
        }
        scored.sort_by(|left, right| match right.1.total_cmp(&left.1) {
            Ordering::Equal => left.0.cmp(&right.0),
            ordering => ordering,
        });
        scored.truncate(k.min(scored.len()));
        let hits = scored
            .into_iter()
            .enumerate()
            .map(|(index, (record_id, cosine_score))| VectorHit {
                record_id,
                cosine_score,
                rank: index + 1,
                exact: true,
                space_id,
                column_generation: column.generation,
                database_snapshot_sha256: snapshot_sha256,
            })
            .collect();

        Ok(RoutedVectorHits {
            hits,
            receipt: CpuGpuRouterReceipt {
                schema_version: CPU_GPU_ROUTER_SCHEMA_VERSION,
                selected_backend: ExactComputeBackend::OpenClFp64,
                candidate_count: indices.len(),
                dimension,
                k,
                database_snapshot_sha256: snapshot_sha256,
                exact_parity_certified: parity_certified,
                cpu_fallback: false,
                fallback_reason: None,
                device_name,
                kernel_sha256,
                measured_crossover_candidates: calibration.crossover_candidates,
                batch_bytes,
            },
        })
    }
}

fn checked_batch_bytes(candidate_count: usize, dimension: usize) -> Result<usize> {
    let vector_values = candidate_count
        .checked_mul(dimension)
        .ok_or_else(|| VectorStoreError::Invalid("GPU vector value count overflow".to_string()))?;
    let vector_bytes = vector_values
        .checked_mul(size_of::<f32>())
        .ok_or_else(|| VectorStoreError::Invalid("GPU vector byte count overflow".to_string()))?;
    let query_bytes = dimension
        .checked_mul(size_of::<f32>())
        .ok_or_else(|| VectorStoreError::Invalid("GPU query byte count overflow".to_string()))?;
    let output_bytes = candidate_count
        .checked_mul(size_of::<f64>() * 2)
        .ok_or_else(|| VectorStoreError::Invalid("GPU output byte count overflow".to_string()))?;
    vector_bytes
        .checked_add(query_bytes)
        .and_then(|value| value.checked_add(output_bytes))
        .ok_or_else(|| VectorStoreError::Invalid("GPU batch byte count overflow".to_string()))
}

fn score_cpu(
    query_vector: &[f32],
    indices: &[usize],
    column: &super::VectorColumn,
    k: usize,
    space_id: SpaceId,
    snapshot_sha256: [u8; 32],
) -> Vec<VectorHit> {
    let query_norm = squared_norm(query_vector);
    let mut scored = Vec::with_capacity(indices.len());
    for index in indices {
        let score = cosine_with_query_norm(query_vector, query_norm, column.vector_at(*index));
        scored.push((column.record_ids[*index].clone(), score));
    }
    scored.sort_by(|left, right| match right.1.total_cmp(&left.1) {
        Ordering::Equal => left.0.cmp(&right.0),
        ordering => ordering,
    });
    scored.truncate(k.min(scored.len()));
    scored
        .into_iter()
        .enumerate()
        .map(|(index, (record_id, cosine_score))| VectorHit {
            record_id,
            cosine_score,
            rank: index + 1,
            exact: true,
            space_id,
            column_generation: column.generation,
            database_snapshot_sha256: snapshot_sha256,
        })
        .collect()
}

fn cpu_parts(query: &[f32], vectors: &[f32], dimension: usize) -> Vec<(f64, f64)> {
    let candidate_count = if dimension == 0 {
        0
    } else {
        vectors.len() / dimension
    };
    let mut output = Vec::with_capacity(candidate_count);
    for row in 0..candidate_count {
        let base = row * dimension;
        let mut dot = 0.0f64;
        let mut norm = 0.0f64;
        for index in 0..dimension {
            let left = query[index] as f64;
            let right = vectors[base + index] as f64;
            dot += left * right;
            norm += right * right;
        }
        output.push((dot, norm));
    }
    output
}

fn parts_bit_equal(left: &[(f64, f64)], right: &[(f64, f64)]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(left, right)| {
            left.0.to_bits() == right.0.to_bits() && left.1.to_bits() == right.1.to_bits()
        })
}

fn certify_engine_exact_parity(
    engine: &mut platform::OpenClEngine,
) -> std::result::Result<(), String> {
    for dimension in [1usize, 2, 3, 7, 16, 48, 127, 256] {
        let candidate_count = 19usize;
        let query = deterministic_query(dimension, 17);
        let vectors = deterministic_vectors(candidate_count, dimension, 29);
        let cpu = cpu_parts(&query, &vectors, dimension);
        let gpu = engine.exact_parts(&query, &vectors, dimension, candidate_count)?;
        if !parts_bit_equal(&cpu, &gpu) {
            return Err(format!(
                "OpenCL FP64 exact-parity selftest failed at dimension {dimension}"
            ));
        }
        let query_norm = squared_norm(&query);
        for (cpu_parts, gpu_parts) in cpu.iter().zip(gpu.iter()) {
            let cpu_score = cpu_parts.0 / (query_norm.sqrt() * cpu_parts.1.sqrt());
            let gpu_score = gpu_parts.0 / (query_norm.sqrt() * gpu_parts.1.sqrt());
            if cpu_score.to_bits() != gpu_score.to_bits() {
                return Err(format!(
                    "OpenCL cosine score exact-parity selftest failed at dimension {dimension}"
                ));
            }
        }
    }
    Ok(())
}

fn verify_query_samples(
    query: &[f32],
    vectors: &[f32],
    dimension: usize,
    gpu: &[(f64, f64)],
) -> std::result::Result<(), String> {
    if gpu.is_empty() {
        return Ok(());
    }
    let mut samples = vec![0usize, gpu.len() / 2, gpu.len() - 1];
    samples.sort_unstable();
    samples.dedup();
    for row in samples {
        let base = row * dimension;
        let cpu = cpu_parts(query, &vectors[base..base + dimension], dimension)[0];
        if cpu.0.to_bits() != gpu[row].0.to_bits()
            || cpu.1.to_bits() != gpu[row].1.to_bits()
        {
            return Err(format!(
                "OpenCL per-query exact-parity sample failed at row {row}"
            ));
        }
    }
    Ok(())
}

fn median_elapsed_ns(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn gpu_wins_with_margin(cpu_elapsed_ns: u128, gpu_elapsed_ns: u128) -> bool {
    if cpu_elapsed_ns == 0 {
        return false;
    }
    let allowed_percent = 100u128.saturating_sub(GPU_CROSSOVER_REQUIRED_SPEEDUP_PERCENT);
    gpu_elapsed_ns.saturating_mul(100) <= cpu_elapsed_ns.saturating_mul(allowed_percent)
}

fn calibrate_on_query(
    engine: &mut platform::OpenClEngine,
    query: &[f32],
    vectors: &[f32],
    dimension: usize,
    candidate_count: usize,
    host_pack_elapsed_ns: u128,
) -> std::result::Result<Calibration, String> {
    let mut cpu_samples = Vec::with_capacity(GPU_CROSSOVER_REPEAT_COUNT);
    let mut cpu_reference = Vec::new();
    for _ in 0..GPU_CROSSOVER_REPEAT_COUNT {
        let cpu_start = Instant::now();
        let cpu = cpu_parts(query, vectors, dimension);
        cpu_samples.push(cpu_start.elapsed().as_nanos());
        cpu_reference = cpu;
    }

    let mut gpu_samples = Vec::with_capacity(GPU_CROSSOVER_REPEAT_COUNT);
    for _ in 0..GPU_CROSSOVER_REPEAT_COUNT {
        let gpu_start = Instant::now();
        let gpu = engine.exact_parts(query, vectors, dimension, candidate_count)?;
        let elapsed = gpu_start
            .elapsed()
            .as_nanos()
            .saturating_add(host_pack_elapsed_ns);
        if !parts_bit_equal(&cpu_reference, &gpu) {
            return Err(format!(
                "OpenCL calibration exact-parity failure at {candidate_count} candidates"
            ));
        }
        gpu_samples.push(elapsed);
    }

    let cpu_elapsed_ns = median_elapsed_ns(cpu_samples);
    let gpu_elapsed_ns = median_elapsed_ns(gpu_samples);
    let crossover_candidates = if gpu_wins_with_margin(cpu_elapsed_ns, gpu_elapsed_ns) {
        Some(candidate_count)
    } else {
        None
    };
    Ok(Calibration {
        crossover_candidates,
        largest_tested: candidate_count,
    })
}

fn deterministic_query(dimension: usize, seed: u64) -> Vec<f32> {
    (0..dimension)
        .map(|index| {
            let raw = ((index as u64 + 1) * 1_103_515_245 + seed * 12_345) % 65_521;
            ((raw as f64 / 32_760.5) - 1.0) as f32
        })
        .collect()
}

fn deterministic_vectors(candidate_count: usize, dimension: usize, seed: u64) -> Vec<f32> {
    let mut output = Vec::with_capacity(candidate_count.saturating_mul(dimension));
    for row in 0..candidate_count {
        for column in 0..dimension {
            let index = row as u64 * dimension as u64 + column as u64 + 1;
            let raw = (index * 1_664_525 + seed * 1_013_904_223) % 65_519;
            let mut value = ((raw as f64 / 32_759.5) - 1.0) as f32;
            if value == 0.0 {
                value = 0.000_030_517_578_125;
            }
            output.push(value);
        }
    }
    output
}

pub fn run_cpu_gpu_router_backend_probe() -> CpuGpuRouterProbeReport {
    let kernel_sha256 = sha256(OPENCL_KERNEL_SOURCE.as_bytes());
    let mut report = CpuGpuRouterProbeReport {
        schema_version: CPU_GPU_ROUTER_SCHEMA_VERSION,
        opencl_available: false,
        fp64_available: false,
        exact_parity_certified: false,
        cpu_fallback_contract: true,
        ann_used: false,
        trust_in_score: false,
        device_name: None,
        kernel_sha256,
        measured_crossover_candidates: None,
        crossover_includes_host_pack: true,
        crossover_end_to_end: true,
        wave_crossover_reused: false,
        rows: Vec::new(),
        error: None,
    };

    let mut engine = match platform::OpenClEngine::new(OPENCL_KERNEL_SOURCE) {
        Ok(value) => value,
        Err(error) => {
            report.error = Some(error);
            return report;
        }
    };
    report.opencl_available = true;
    report.fp64_available = true;
    report.device_name = Some(engine.device_name().to_string());
    if let Err(error) = certify_engine_exact_parity(&mut engine) {
        report.error = Some(error);
        return report;
    }
    report.exact_parity_certified = true;

    let dimension = 48usize;
    let query = deterministic_query(dimension, 71);
    let max_candidates = 262_144usize;
    let vectors = deterministic_vectors(max_candidates, dimension, 91);
    for candidate_count in [256usize, 1_024, 4_096, 16_384, 65_536, 262_144] {
        let slice = &vectors[..candidate_count * dimension];
        let mut cpu_samples = Vec::with_capacity(GPU_CROSSOVER_REPEAT_COUNT);
        let mut cpu = Vec::new();
        for _ in 0..GPU_CROSSOVER_REPEAT_COUNT {
            let cpu_start = Instant::now();
            cpu = cpu_parts(&query, slice, dimension);
            cpu_samples.push(cpu_start.elapsed().as_nanos());
        }
        let cpu_elapsed = median_elapsed_ns(cpu_samples);

        let mut gpu_samples = Vec::with_capacity(GPU_CROSSOVER_REPEAT_COUNT);
        let mut gpu = Vec::new();
        for _ in 0..GPU_CROSSOVER_REPEAT_COUNT {
            let gpu_start = Instant::now();
            let packed = slice.to_vec();
            gpu = match engine.exact_parts(&query, &packed, dimension, candidate_count) {
                Ok(value) => value,
                Err(error) => {
                    report.error = Some(error);
                    return report;
                }
            };
            gpu_samples.push(gpu_start.elapsed().as_nanos());
        }
        let gpu_elapsed = median_elapsed_ns(gpu_samples);
        let exact_parity = parts_bit_equal(&cpu, &gpu);
        let gpu_faster = gpu_wins_with_margin(cpu_elapsed, gpu_elapsed);
        if exact_parity && gpu_faster && report.measured_crossover_candidates.is_none() {
            report.measured_crossover_candidates = Some(candidate_count);
        }
        report.rows.push(RouterBenchmarkRow {
            candidate_count,
            dimension,
            cpu_elapsed_ns: cpu_elapsed,
            gpu_elapsed_ns: gpu_elapsed,
            exact_parity,
            gpu_faster,
            host_pack_included: true,
            end_to_end: true,
        });
        if !exact_parity {
            report.exact_parity_certified = false;
            report.error = Some(format!(
                "benchmark parity failed at {candidate_count} candidates"
            ));
            return report;
        }
    }
    report
}

#[cfg(windows)]
mod platform {
    use std::ffi::{c_char, c_void, CStr, CString, OsStr};
    use std::mem::{size_of, transmute_copy};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    type ClInt = i32;
    type ClUint = u32;
    type ClUlong = u64;
    type ClBool = u32;
    type ClBitfield = u64;
    type ClDeviceType = ClBitfield;
    type ClPlatformId = *mut c_void;
    type ClDeviceId = *mut c_void;
    type ClContext = *mut c_void;
    type ClCommandQueue = *mut c_void;
    type ClMem = *mut c_void;
    type ClProgram = *mut c_void;
    type ClKernel = *mut c_void;
    type ClEvent = *mut c_void;
    type ClContextProperties = isize;

    const CL_SUCCESS: ClInt = 0;
    const CL_DEVICE_NOT_FOUND: ClInt = -1;
    const CL_DEVICE_TYPE_GPU: ClDeviceType = 1 << 2;
    const CL_DEVICE_NAME: ClUint = 0x102B;
    const CL_DEVICE_EXTENSIONS: ClUint = 0x1030;
    const CL_DEVICE_DOUBLE_FP_CONFIG: ClUint = 0x1032;
    const CL_PROGRAM_BUILD_LOG: ClUint = 0x1183;
    const CL_MEM_WRITE_ONLY: ClBitfield = 1 << 1;
    const CL_MEM_READ_ONLY: ClBitfield = 1 << 2;
    const CL_TRUE: ClBool = 1;

    type ContextNotify = Option<
        unsafe extern "system" fn(*const c_char, *const c_void, usize, *mut c_void),
    >;
    type ProgramNotify = Option<unsafe extern "system" fn(ClProgram, *mut c_void)>;

    type ClGetPlatformIDs =
        unsafe extern "system" fn(ClUint, *mut ClPlatformId, *mut ClUint) -> ClInt;
    type ClGetDeviceIDs = unsafe extern "system" fn(
        ClPlatformId,
        ClDeviceType,
        ClUint,
        *mut ClDeviceId,
        *mut ClUint,
    ) -> ClInt;
    type ClGetDeviceInfo = unsafe extern "system" fn(
        ClDeviceId,
        ClUint,
        usize,
        *mut c_void,
        *mut usize,
    ) -> ClInt;
    type ClCreateContext = unsafe extern "system" fn(
        *const ClContextProperties,
        ClUint,
        *const ClDeviceId,
        ContextNotify,
        *mut c_void,
        *mut ClInt,
    ) -> ClContext;
    type ClCreateCommandQueue = unsafe extern "system" fn(
        ClContext,
        ClDeviceId,
        ClBitfield,
        *mut ClInt,
    ) -> ClCommandQueue;
    type ClCreateProgramWithSource = unsafe extern "system" fn(
        ClContext,
        ClUint,
        *const *const c_char,
        *const usize,
        *mut ClInt,
    ) -> ClProgram;
    type ClBuildProgram = unsafe extern "system" fn(
        ClProgram,
        ClUint,
        *const ClDeviceId,
        *const c_char,
        ProgramNotify,
        *mut c_void,
    ) -> ClInt;
    type ClGetProgramBuildInfo = unsafe extern "system" fn(
        ClProgram,
        ClDeviceId,
        ClUint,
        usize,
        *mut c_void,
        *mut usize,
    ) -> ClInt;
    type ClCreateKernel =
        unsafe extern "system" fn(ClProgram, *const c_char, *mut ClInt) -> ClKernel;
    type ClCreateBuffer = unsafe extern "system" fn(
        ClContext,
        ClBitfield,
        usize,
        *mut c_void,
        *mut ClInt,
    ) -> ClMem;
    type ClSetKernelArg =
        unsafe extern "system" fn(ClKernel, ClUint, usize, *const c_void) -> ClInt;
    type ClEnqueueWriteBuffer = unsafe extern "system" fn(
        ClCommandQueue,
        ClMem,
        ClBool,
        usize,
        usize,
        *const c_void,
        ClUint,
        *const ClEvent,
        *mut ClEvent,
    ) -> ClInt;
    type ClEnqueueNDRangeKernel = unsafe extern "system" fn(
        ClCommandQueue,
        ClKernel,
        ClUint,
        *const usize,
        *const usize,
        *const usize,
        ClUint,
        *const ClEvent,
        *mut ClEvent,
    ) -> ClInt;
    type ClEnqueueReadBuffer = unsafe extern "system" fn(
        ClCommandQueue,
        ClMem,
        ClBool,
        usize,
        usize,
        *mut c_void,
        ClUint,
        *const ClEvent,
        *mut ClEvent,
    ) -> ClInt;
    type ClFinish = unsafe extern "system" fn(ClCommandQueue) -> ClInt;
    type ClReleaseMemObject = unsafe extern "system" fn(ClMem) -> ClInt;
    type ClReleaseKernel = unsafe extern "system" fn(ClKernel) -> ClInt;
    type ClReleaseProgram = unsafe extern "system" fn(ClProgram) -> ClInt;
    type ClReleaseCommandQueue = unsafe extern "system" fn(ClCommandQueue) -> ClInt;
    type ClReleaseContext = unsafe extern "system" fn(ClContext) -> ClInt;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    struct OpenClApi {
        module: *mut c_void,
        get_platform_ids: ClGetPlatformIDs,
        get_device_ids: ClGetDeviceIDs,
        get_device_info: ClGetDeviceInfo,
        create_context: ClCreateContext,
        create_command_queue: ClCreateCommandQueue,
        create_program_with_source: ClCreateProgramWithSource,
        build_program: ClBuildProgram,
        get_program_build_info: ClGetProgramBuildInfo,
        create_kernel: ClCreateKernel,
        create_buffer: ClCreateBuffer,
        set_kernel_arg: ClSetKernelArg,
        enqueue_write_buffer: ClEnqueueWriteBuffer,
        enqueue_nd_range_kernel: ClEnqueueNDRangeKernel,
        enqueue_read_buffer: ClEnqueueReadBuffer,
        finish: ClFinish,
        release_mem_object: ClReleaseMemObject,
        release_kernel: ClReleaseKernel,
        release_program: ClReleaseProgram,
        release_command_queue: ClReleaseCommandQueue,
        release_context: ClReleaseContext,
    }

    unsafe impl Send for OpenClApi {}

    impl OpenClApi {
        unsafe fn load_symbol<T: Copy>(
            module: *mut c_void,
            name: &'static [u8],
        ) -> std::result::Result<T, String> {
            let pointer = GetProcAddress(module, name.as_ptr());
            if pointer.is_null() {
                return Err(format!(
                    "OpenCL symbol missing: {}",
                    CStr::from_bytes_with_nul(name)
                        .map(|value| value.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "invalid-symbol".to_string())
                ));
            }
            Ok(transmute_copy(&pointer))
        }

        fn load() -> std::result::Result<Self, String> {
            let wide: Vec<u16> = OsStr::new("OpenCL.dll")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let module = unsafe { LoadLibraryW(wide.as_ptr()) };
            if module.is_null() {
                return Err("OpenCL.dll could not be loaded".to_string());
            }
            let result: std::result::Result<Self, String> = (|| unsafe {
                Ok(Self {
                    module,
                    get_platform_ids: Self::load_symbol(module, b"clGetPlatformIDs\0")?,
                    get_device_ids: Self::load_symbol(module, b"clGetDeviceIDs\0")?,
                    get_device_info: Self::load_symbol(module, b"clGetDeviceInfo\0")?,
                    create_context: Self::load_symbol(module, b"clCreateContext\0")?,
                    create_command_queue: Self::load_symbol(module, b"clCreateCommandQueue\0")?,
                    create_program_with_source: Self::load_symbol(
                        module,
                        b"clCreateProgramWithSource\0",
                    )?,
                    build_program: Self::load_symbol(module, b"clBuildProgram\0")?,
                    get_program_build_info: Self::load_symbol(
                        module,
                        b"clGetProgramBuildInfo\0",
                    )?,
                    create_kernel: Self::load_symbol(module, b"clCreateKernel\0")?,
                    create_buffer: Self::load_symbol(module, b"clCreateBuffer\0")?,
                    set_kernel_arg: Self::load_symbol(module, b"clSetKernelArg\0")?,
                    enqueue_write_buffer: Self::load_symbol(
                        module,
                        b"clEnqueueWriteBuffer\0",
                    )?,
                    enqueue_nd_range_kernel: Self::load_symbol(
                        module,
                        b"clEnqueueNDRangeKernel\0",
                    )?,
                    enqueue_read_buffer: Self::load_symbol(
                        module,
                        b"clEnqueueReadBuffer\0",
                    )?,
                    finish: Self::load_symbol(module, b"clFinish\0")?,
                    release_mem_object: Self::load_symbol(module, b"clReleaseMemObject\0")?,
                    release_kernel: Self::load_symbol(module, b"clReleaseKernel\0")?,
                    release_program: Self::load_symbol(module, b"clReleaseProgram\0")?,
                    release_command_queue: Self::load_symbol(
                        module,
                        b"clReleaseCommandQueue\0",
                    )?,
                    release_context: Self::load_symbol(module, b"clReleaseContext\0")?,
                })
            })();
            if result.is_err() {
                unsafe {
                    FreeLibrary(module);
                }
            }
            result
        }
    }

    impl Drop for OpenClApi {
        fn drop(&mut self) {
            if !self.module.is_null() {
                unsafe {
                    FreeLibrary(self.module);
                }
                self.module = null_mut();
            }
        }
    }

    pub struct OpenClEngine {
        api: OpenClApi,
        device: ClDeviceId,
        context: ClContext,
        queue: ClCommandQueue,
        program: ClProgram,
        kernel: ClKernel,
        device_name: String,
    }

    unsafe impl Send for OpenClEngine {}

    impl OpenClEngine {
        pub fn new(kernel_source: &str) -> std::result::Result<Self, String> {
            let api = OpenClApi::load()?;
            let (device, device_name) = select_fp64_gpu(&api)?;
            let mut status = 0;
            let context = unsafe {
                (api.create_context)(null(), 1, &device, None, null_mut(), &mut status)
            };
            check_handle(context, status, "clCreateContext")?;
            let queue = unsafe { (api.create_command_queue)(context, device, 0, &mut status) };
            if queue.is_null() || status != CL_SUCCESS {
                unsafe {
                    (api.release_context)(context);
                }
                return Err(format!("clCreateCommandQueue failed with {status}"));
            }

            let source = CString::new(kernel_source)
                .map_err(|_| "OpenCL kernel source contains NUL".to_string())?;
            let source_pointer = source.as_ptr();
            let source_length = kernel_source.as_bytes().len();
            let program = unsafe {
                (api.create_program_with_source)(
                    context,
                    1,
                    &source_pointer,
                    &source_length,
                    &mut status,
                )
            };
            if program.is_null() || status != CL_SUCCESS {
                unsafe {
                    (api.release_command_queue)(queue);
                    (api.release_context)(context);
                }
                return Err(format!("clCreateProgramWithSource failed with {status}"));
            }

            let options = CString::new("-cl-std=CL1.2")
                .map_err(|_| "OpenCL build options contain NUL".to_string())?;
            status = unsafe {
                (api.build_program)(program, 1, &device, options.as_ptr(), None, null_mut())
            };
            if status != CL_SUCCESS {
                let log = program_build_log(&api, program, device)
                    .unwrap_or_else(|_| "build log unavailable".to_string());
                unsafe {
                    (api.release_program)(program);
                    (api.release_command_queue)(queue);
                    (api.release_context)(context);
                }
                return Err(format!("clBuildProgram failed with {status}: {log}"));
            }

            let kernel_name = CString::new("ultraballoon_exact_cosine_parts")
                .map_err(|_| "OpenCL kernel name contains NUL".to_string())?;
            let kernel = unsafe { (api.create_kernel)(program, kernel_name.as_ptr(), &mut status) };
            if kernel.is_null() || status != CL_SUCCESS {
                unsafe {
                    (api.release_program)(program);
                    (api.release_command_queue)(queue);
                    (api.release_context)(context);
                }
                return Err(format!("clCreateKernel failed with {status}"));
            }

            Ok(Self {
                api,
                device,
                context,
                queue,
                program,
                kernel,
                device_name,
            })
        }

        pub fn device_name(&self) -> &str {
            &self.device_name
        }

        pub fn exact_parts(
            &mut self,
            query: &[f32],
            vectors: &[f32],
            dimension: usize,
            candidate_count: usize,
        ) -> std::result::Result<Vec<(f64, f64)>, String> {
            if dimension == 0
                || candidate_count == 0
                || query.len() != dimension
                || vectors.len() != dimension.saturating_mul(candidate_count)
            {
                return Err("invalid OpenCL exact-parts dimensions".to_string());
            }
            if dimension > u32::MAX as usize {
                return Err("OpenCL dimension exceeds u32".to_string());
            }

            let query_bytes = query.len() * size_of::<f32>();
            let vector_bytes = vectors.len() * size_of::<f32>();
            let output_bytes = candidate_count * size_of::<f64>();
            let mut status = 0;
            let mut buffers: Vec<ClMem> = Vec::new();

            let result = (|| {
                let query_buffer = unsafe {
                    (self.api.create_buffer)(
                        self.context,
                        CL_MEM_READ_ONLY,
                        query_bytes,
                        null_mut(),
                        &mut status,
                    )
                };
                check_handle(query_buffer, status, "clCreateBuffer(query)")?;
                buffers.push(query_buffer);

                let vectors_buffer = unsafe {
                    (self.api.create_buffer)(
                        self.context,
                        CL_MEM_READ_ONLY,
                        vector_bytes,
                        null_mut(),
                        &mut status,
                    )
                };
                check_handle(vectors_buffer, status, "clCreateBuffer(vectors)")?;
                buffers.push(vectors_buffer);

                let dots_buffer = unsafe {
                    (self.api.create_buffer)(
                        self.context,
                        CL_MEM_WRITE_ONLY,
                        output_bytes,
                        null_mut(),
                        &mut status,
                    )
                };
                check_handle(dots_buffer, status, "clCreateBuffer(dots)")?;
                buffers.push(dots_buffer);

                let norms_buffer = unsafe {
                    (self.api.create_buffer)(
                        self.context,
                        CL_MEM_WRITE_ONLY,
                        output_bytes,
                        null_mut(),
                        &mut status,
                    )
                };
                check_handle(norms_buffer, status, "clCreateBuffer(norms)")?;
                buffers.push(norms_buffer);

                check(
                    unsafe {
                        (self.api.enqueue_write_buffer)(
                            self.queue,
                            query_buffer,
                            CL_TRUE,
                            0,
                            query_bytes,
                            query.as_ptr() as *const c_void,
                            0,
                            null(),
                            null_mut(),
                        )
                    },
                    "clEnqueueWriteBuffer(query)",
                )?;
                check(
                    unsafe {
                        (self.api.enqueue_write_buffer)(
                            self.queue,
                            vectors_buffer,
                            CL_TRUE,
                            0,
                            vector_bytes,
                            vectors.as_ptr() as *const c_void,
                            0,
                            null(),
                            null_mut(),
                        )
                    },
                    "clEnqueueWriteBuffer(vectors)",
                )?;

                let dimension_u32 = dimension as u32;
                set_arg(&self.api, self.kernel, 0, &query_buffer)?;
                set_arg(&self.api, self.kernel, 1, &vectors_buffer)?;
                set_arg(&self.api, self.kernel, 2, &dimension_u32)?;
                set_arg(&self.api, self.kernel, 3, &dots_buffer)?;
                set_arg(&self.api, self.kernel, 4, &norms_buffer)?;

                let global = [candidate_count];
                check(
                    unsafe {
                        (self.api.enqueue_nd_range_kernel)(
                            self.queue,
                            self.kernel,
                            1,
                            null(),
                            global.as_ptr(),
                            null(),
                            0,
                            null(),
                            null_mut(),
                        )
                    },
                    "clEnqueueNDRangeKernel",
                )?;
                check(unsafe { (self.api.finish)(self.queue) }, "clFinish")?;

                let mut dots = vec![0.0f64; candidate_count];
                let mut norms = vec![0.0f64; candidate_count];
                check(
                    unsafe {
                        (self.api.enqueue_read_buffer)(
                            self.queue,
                            dots_buffer,
                            CL_TRUE,
                            0,
                            output_bytes,
                            dots.as_mut_ptr() as *mut c_void,
                            0,
                            null(),
                            null_mut(),
                        )
                    },
                    "clEnqueueReadBuffer(dots)",
                )?;
                check(
                    unsafe {
                        (self.api.enqueue_read_buffer)(
                            self.queue,
                            norms_buffer,
                            CL_TRUE,
                            0,
                            output_bytes,
                            norms.as_mut_ptr() as *mut c_void,
                            0,
                            null(),
                            null_mut(),
                        )
                    },
                    "clEnqueueReadBuffer(norms)",
                )?;
                Ok(dots.into_iter().zip(norms.into_iter()).collect())
            })();

            for buffer in buffers.into_iter().rev() {
                unsafe {
                    (self.api.release_mem_object)(buffer);
                }
            }
            result
        }
    }

    impl Drop for OpenClEngine {
        fn drop(&mut self) {
            unsafe {
                if !self.kernel.is_null() {
                    (self.api.release_kernel)(self.kernel);
                }
                if !self.program.is_null() {
                    (self.api.release_program)(self.program);
                }
                if !self.queue.is_null() {
                    (self.api.release_command_queue)(self.queue);
                }
                if !self.context.is_null() {
                    (self.api.release_context)(self.context);
                }
            }
            self.kernel = null_mut();
            self.program = null_mut();
            self.queue = null_mut();
            self.context = null_mut();
        }
    }

    fn select_fp64_gpu(api: &OpenClApi) -> std::result::Result<(ClDeviceId, String), String> {
        let mut platform_count = 0u32;
        check(
            unsafe { (api.get_platform_ids)(0, null_mut(), &mut platform_count) },
            "clGetPlatformIDs(count)",
        )?;
        if platform_count == 0 {
            return Err("OpenCL reports zero platforms".to_string());
        }
        let mut platforms = vec![null_mut(); platform_count as usize];
        check(
            unsafe {
                (api.get_platform_ids)(platform_count, platforms.as_mut_ptr(), null_mut())
            },
            "clGetPlatformIDs(list)",
        )?;
        for platform in platforms {
            let mut device_count = 0u32;
            let status = unsafe {
                (api.get_device_ids)(
                    platform,
                    CL_DEVICE_TYPE_GPU,
                    0,
                    null_mut(),
                    &mut device_count,
                )
            };
            if status == CL_DEVICE_NOT_FOUND || device_count == 0 {
                continue;
            }
            check(status, "clGetDeviceIDs(count)")?;
            let mut devices = vec![null_mut(); device_count as usize];
            check(
                unsafe {
                    (api.get_device_ids)(
                        platform,
                        CL_DEVICE_TYPE_GPU,
                        device_count,
                        devices.as_mut_ptr(),
                        null_mut(),
                    )
                },
                "clGetDeviceIDs(list)",
            )?;
            for device in devices {
                let mut fp64_config: ClUlong = 0;
                let status = unsafe {
                    (api.get_device_info)(
                        device,
                        CL_DEVICE_DOUBLE_FP_CONFIG,
                        size_of::<ClUlong>(),
                        &mut fp64_config as *mut ClUlong as *mut c_void,
                        null_mut(),
                    )
                };
                let extensions = device_string(api, device, CL_DEVICE_EXTENSIONS)
                    .unwrap_or_else(|_| String::new());
                if (status == CL_SUCCESS && fp64_config != 0)
                    || extensions.split_whitespace().any(|value| value == "cl_khr_fp64")
                {
                    let name = device_string(api, device, CL_DEVICE_NAME)
                        .unwrap_or_else(|_| "OpenCL FP64 GPU".to_string());
                    return Ok((device, name));
                }
            }
        }
        Err("no OpenCL GPU with FP64 support was found".to_string())
    }

    fn device_string(
        api: &OpenClApi,
        device: ClDeviceId,
        parameter: ClUint,
    ) -> std::result::Result<String, String> {
        let mut size = 0usize;
        check(
            unsafe { (api.get_device_info)(device, parameter, 0, null_mut(), &mut size) },
            "clGetDeviceInfo(size)",
        )?;
        if size == 0 {
            return Ok(String::new());
        }
        let mut bytes = vec![0u8; size];
        check(
            unsafe {
                (api.get_device_info)(
                    device,
                    parameter,
                    size,
                    bytes.as_mut_ptr() as *mut c_void,
                    null_mut(),
                )
            },
            "clGetDeviceInfo(value)",
        )?;
        while bytes.last().copied() == Some(0) {
            bytes.pop();
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn program_build_log(
        api: &OpenClApi,
        program: ClProgram,
        device: ClDeviceId,
    ) -> std::result::Result<String, String> {
        let mut size = 0usize;
        check(
            unsafe {
                (api.get_program_build_info)(
                    program,
                    device,
                    CL_PROGRAM_BUILD_LOG,
                    0,
                    null_mut(),
                    &mut size,
                )
            },
            "clGetProgramBuildInfo(size)",
        )?;
        let mut bytes = vec![0u8; size];
        check(
            unsafe {
                (api.get_program_build_info)(
                    program,
                    device,
                    CL_PROGRAM_BUILD_LOG,
                    size,
                    bytes.as_mut_ptr() as *mut c_void,
                    null_mut(),
                )
            },
            "clGetProgramBuildInfo(value)",
        )?;
        while bytes.last().copied() == Some(0) {
            bytes.pop();
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn set_arg<T>(
        api: &OpenClApi,
        kernel: ClKernel,
        index: u32,
        value: &T,
    ) -> std::result::Result<(), String> {
        check(
            unsafe {
                (api.set_kernel_arg)(
                    kernel,
                    index,
                    size_of::<T>(),
                    value as *const T as *const c_void,
                )
            },
            "clSetKernelArg",
        )
    }

    fn check(status: ClInt, operation: &str) -> std::result::Result<(), String> {
        if status == CL_SUCCESS {
            Ok(())
        } else {
            Err(format!("{operation} failed with OpenCL status {status}"))
        }
    }

    fn check_handle<T>(
        handle: *mut T,
        status: ClInt,
        operation: &str,
    ) -> std::result::Result<(), String> {
        if !handle.is_null() && status == CL_SUCCESS {
            Ok(())
        } else {
            Err(format!("{operation} failed with OpenCL status {status}"))
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub struct OpenClEngine;

    impl OpenClEngine {
        pub fn new(_kernel_source: &str) -> std::result::Result<Self, String> {
            Err("the R4.4 OpenCL backend is currently enabled on Windows; CPU fallback is active on this platform".to_string())
        }

        pub fn device_name(&self) -> &str {
            "unsupported-platform"
        }

        pub fn exact_parts(
            &mut self,
            _query: &[f32],
            _vectors: &[f32],
            _dimension: usize,
            _candidate_count: usize,
        ) -> std::result::Result<Vec<(f64, f64)>, String> {
            Err("OpenCL backend unavailable on this platform".to_string())
        }
    }
}
