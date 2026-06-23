use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ultraballoondb_lifecycle::{
    BatchLimits, DurableDatabase, TransactionCore, TransactionId, TransactionState,
};
use ultraballoondb_semantic::{
    ExactComputeBackend, VectorInput, VectorNormalization, VectorSpaceDescriptor, VectorStore,
};

const SCALE: usize = 10_000;
const DIMENSION: usize = 384;
const TOP_K: usize = 10;
const SAMPLES: usize = 31;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn unit_vector(seed: u64) -> Vec<f32> {
    let mut state = seed;
    let mut vector = Vec::with_capacity(DIMENSION);
    let mut norm = 0.0f64;
    for _ in 0..DIMENSION {
        let bits = splitmix64(&mut state);
        let unit = ((bits >> 11) as f64) / ((1u64 << 53) as f64);
        let value = (unit * 2.0 - 1.0) as f32;
        norm += (value as f64) * (value as f64);
        vector.push(value);
    }
    let norm = norm.sqrt();
    for value in &mut vector {
        *value = (*value as f64 / norm) as f32;
    }
    vector
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index]
}

fn transaction_id() -> TransactionId {
    TransactionId::new([0x8Au8; 16])
}

fn main() -> Result<(), Box<dyn Error>> {
    let report_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("report path argument required")?;
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let database_root = report_path.with_extension("database");
    let _ = fs::remove_dir_all(&database_root);

    let mut database = DurableDatabase::create(&database_root)?;
    let mut transaction = TransactionCore::new(BatchLimits {
        max_operations: SCALE + 1024,
        max_payload_bytes: 128 * 1024 * 1024,
    });
    let tx = transaction_id();
    transaction.begin(tx)?;

    let mut inputs = Vec::with_capacity(SCALE);
    for index in 0..SCALE {
        let record_id = format!("router-r4-8a-{index:05}");
        transaction.put_record(
            (index + 1) as u64,
            &record_id,
            (index + 1) as u64,
            record_id.as_bytes(),
        )?;
        inputs.push(VectorInput::new(
            record_id,
            unit_vector(0xA800_0000_0000_0000 + index as u64),
        ));
    }
    transaction.prepare()?;
    let commit = transaction.commit_durable(&mut database, 1, 1)?;
    if !commit.durable_commit {
        return Err("database commit was not durable".into());
    }
    if transaction.release_terminal(tx)? != TransactionState::DurableCommitted {
        return Err("unexpected terminal transaction state".into());
    }
    database.checkpoint(2)?;

    let snapshot = database.read_snapshot();
    let mut store = VectorStore::create(&database_root)?;
    let descriptor = VectorSpaceDescriptor::external(
        "r4-8a-router-policy-probe",
        "deterministic",
        "v1",
        "unit-f32-v1",
        DIMENSION as u32,
        VectorNormalization::UnitL2,
    );
    let (space_id, _) = store.create_space(descriptor)?;
    store.import_vectors(&snapshot, space_id, "r4-8a-import-v1", &inputs)?;
    let query = unit_vector(0xB800_0000_0000_0001);

    std::env::set_var("ULTRABALLOONDB_GPU_ROUTER", "force-gpu");
    let force_gpu =
        store.find_exact_routed_with_receipt(&snapshot, space_id, &query, TOP_K, None)?;
    let force_gpu_pass = force_gpu.receipt.selected_backend == ExactComputeBackend::OpenClFp64
        && !force_gpu.receipt.cpu_fallback
        && force_gpu.receipt.exact_parity_certified
        && force_gpu.receipt.device_name.is_some();

    std::env::set_var("ULTRABALLOONDB_GPU_ROUTER", "auto");
    let mut auto_latencies = Vec::with_capacity(SAMPLES);
    let mut auto_ids = Vec::new();
    let mut auto_cpu_policy_count = 0usize;
    let mut auto_gpu_count = 0usize;
    let mut auto_fallback_count = 0usize;
    let mut auto_parity_count = 0usize;
    let mut policy_reason_count = 0usize;
    let mut device_receipt_count = 0usize;

    for sample in 0..SAMPLES {
        let start = Instant::now();
        let result =
            store.find_exact_routed_with_receipt(&snapshot, space_id, &query, TOP_K, None)?;
        auto_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        if sample == 0 {
            auto_ids = result
                .hits
                .iter()
                .map(|hit| hit.record_id.clone())
                .collect();
        }
        match result.receipt.selected_backend {
            ExactComputeBackend::CpuExact => {
                if result.receipt.cpu_selected_by_policy() {
                    auto_cpu_policy_count += 1;
                }
            }
            ExactComputeBackend::OpenClFp64 => auto_gpu_count += 1,
        }
        if result.receipt.gpu_failure_fallback() {
            auto_fallback_count += 1;
        }
        if result.receipt.exact_parity_certified {
            auto_parity_count += 1;
        }
        if result
            .receipt
            .route_reason()
            .is_some_and(|reason| reason.starts_with("policy:"))
        {
            policy_reason_count += 1;
        }
        if result.receipt.device_name.is_some() {
            device_receipt_count += 1;
        }
    }

    std::env::set_var("ULTRABALLOONDB_GPU_ROUTER", "cpu");
    let mut cpu_latencies = Vec::with_capacity(SAMPLES);
    let mut ranking_equal_count = 0usize;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let result =
            store.find_exact_routed_with_receipt(&snapshot, space_id, &query, TOP_K, None)?;
        cpu_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        let ids = result
            .hits
            .iter()
            .map(|hit| hit.record_id.clone())
            .collect::<Vec<_>>();
        if ids == auto_ids {
            ranking_equal_count += 1;
        }
        if result.receipt.cpu_fallback {
            return Err("forced CPU policy was incorrectly marked as fallback".into());
        }
    }
    std::env::remove_var("ULTRABALLOONDB_GPU_ROUTER");

    let auto_p50_ms = percentile(&auto_latencies, 0.50);
    let auto_p95_ms = percentile(&auto_latencies, 0.95);
    let cpu_p50_ms = percentile(&cpu_latencies, 0.50);
    let overhead_ms = auto_p50_ms - cpu_p50_ms;
    let overhead_ratio = if cpu_p50_ms > 0.0 {
        auto_p50_ms / cpu_p50_ms
    } else {
        f64::INFINITY
    };

    let auto_policy_cpu = auto_cpu_policy_count == SAMPLES && auto_gpu_count == 0;
    let auto_gpu = auto_gpu_count == SAMPLES && auto_cpu_policy_count == 0;
    let backend_consistent = auto_policy_cpu || auto_gpu;
    let policy_contract_pass = if auto_policy_cpu {
        auto_fallback_count == 0
            && auto_parity_count == SAMPLES
            && policy_reason_count == SAMPLES
            && device_receipt_count == SAMPLES
    } else {
        auto_fallback_count == 0 && auto_parity_count == SAMPLES
    };
    let latency_gate_pass = if auto_policy_cpu {
        auto_p50_ms <= cpu_p50_ms * 1.10 + 0.75
    } else {
        true
    };
    let pass = force_gpu_pass
        && backend_consistent
        && policy_contract_pass
        && latency_gate_pass
        && ranking_equal_count == SAMPLES;

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\":\"ultraballoondb.r4_8a.cached_cpu_policy_probe.v1\",\n",
            "  \"pass\":{},\n",
            "  \"scale\":{},\n",
            "  \"dimension\":{},\n",
            "  \"samples\":{},\n",
            "  \"force_gpu_pass\":{},\n",
            "  \"auto_cpu_policy_count\":{},\n",
            "  \"auto_gpu_count\":{},\n",
            "  \"auto_gpu_failure_fallback_count\":{},\n",
            "  \"auto_parity_certified_count\":{},\n",
            "  \"auto_policy_reason_count\":{},\n",
            "  \"auto_device_receipt_count\":{},\n",
            "  \"ranking_equal_count\":{},\n",
            "  \"auto_latency_p50_ms\":{:.6},\n",
            "  \"auto_latency_p95_ms\":{:.6},\n",
            "  \"direct_cpu_latency_p50_ms\":{:.6},\n",
            "  \"auto_overhead_ms\":{:.6},\n",
            "  \"auto_overhead_ratio\":{:.9},\n",
            "  \"backend_consistent\":{},\n",
            "  \"policy_contract_pass\":{},\n",
            "  \"latency_gate_pass\":{},\n",
            "  \"host_pack_skipped_for_cached_cpu_policy_inferred\":{}\n",
            "}}\n"
        ),
        pass,
        SCALE,
        DIMENSION,
        SAMPLES,
        force_gpu_pass,
        auto_cpu_policy_count,
        auto_gpu_count,
        auto_fallback_count,
        auto_parity_count,
        policy_reason_count,
        device_receipt_count,
        ranking_equal_count,
        auto_p50_ms,
        auto_p95_ms,
        cpu_p50_ms,
        overhead_ms,
        overhead_ratio,
        backend_consistent,
        policy_contract_pass,
        latency_gate_pass,
        auto_policy_cpu && latency_gate_pass,
    );
    fs::write(&report_path, report)?;

    if pass {
        println!("PASS_ULTRABALLOONDB_R4_8A_GPU_ROUTER_PREPACK_POLICY_PROBE");
    } else {
        println!("NO_GO_ULTRABALLOONDB_R4_8A_GPU_ROUTER_PREPACK_POLICY_PROBE");
    }
    println!("REPORT={}", report_path.display());
    println!("FORCE_GPU_PASS={force_gpu_pass}");
    println!("AUTO_CPU_POLICY_COUNT={auto_cpu_policy_count}");
    println!("AUTO_GPU_COUNT={auto_gpu_count}");
    println!("AUTO_GPU_FAILURE_FALLBACK_COUNT={auto_fallback_count}");
    println!("AUTO_PARITY_CERTIFIED_COUNT={auto_parity_count}");
    println!("AUTO_POLICY_REASON_COUNT={policy_reason_count}");
    println!("AUTO_DEVICE_RECEIPT_COUNT={device_receipt_count}");
    println!("AUTO_LATENCY_P50_MS={auto_p50_ms:.6}");
    println!("DIRECT_CPU_LATENCY_P50_MS={cpu_p50_ms:.6}");
    println!("AUTO_OVERHEAD_MS={overhead_ms:.6}");
    println!("AUTO_OVERHEAD_RATIO={overhead_ratio:.9}");
    println!("RANKING_EQUAL_COUNT={ranking_equal_count}/{SAMPLES}");
    println!(
        "HOST_PACK_SKIPPED_FOR_CACHED_CPU_POLICY_INFERRED={}",
        auto_policy_cpu && latency_gate_pass
    );

    let _ = fs::remove_dir_all(database_root);
    if !pass {
        std::process::exit(2);
    }
    Ok(())
}
