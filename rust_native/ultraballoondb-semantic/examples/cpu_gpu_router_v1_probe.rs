use std::fs;
use std::path::PathBuf;

use ultraballoondb_semantic::run_cpu_gpu_router_backend_probe;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    assert!(
        arguments.len() <= 2,
        "usage: cpu_gpu_router_v1_probe [REPORT]"
    );

    let report = run_cpu_gpu_router_backend_probe();
    let json = report.to_json();
    println!("{json}");
    println!("OPENCL_AVAILABLE={}", report.opencl_available);
    println!("OPENCL_FP64_AVAILABLE={}", report.fp64_available);
    println!(
        "EXACT_CPU_GPU_PARITY={}",
        report.exact_parity_certified
    );
    println!("CPU_FALLBACK_CONTRACT={}", report.cpu_fallback_contract);
    println!("ANN_USED={}", report.ann_used);
    println!("TRUST_IN_SCORE={}", report.trust_in_score);
    println!("KERNEL_SHA256={}", report.kernel_sha256_hex());
    println!(
        "CROSSOVER_INCLUDES_HOST_PACK={}",
        report.crossover_includes_host_pack
    );
    println!("CROSSOVER_END_TO_END={}", report.crossover_end_to_end);
    println!("WAVE_CROSSOVER_REUSED={}", report.wave_crossover_reused);
    match report.measured_crossover_candidates {
        Some(value) => println!("MEASURED_CROSSOVER_CANDIDATES={value}"),
        None => println!("MEASURED_CROSSOVER_CANDIDATES=NONE"),
    }
    if let Some(device) = &report.device_name {
        println!("OPENCL_DEVICE={device}");
    }
    if let Some(error) = &report.error {
        eprintln!("ROUTER_PROBE_ERROR={error}");
    }

    if let Some(path) = arguments.get(1).map(PathBuf::from) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create report parent");
        }
        fs::write(&path, format!("{json}\n")).expect("write router report");
        println!("REPORT={}", path.display());
    }

    if report.opencl_available
        && report.fp64_available
        && report.exact_parity_certified
        && report.cpu_fallback_contract
        && !report.ann_used
        && !report.trust_in_score
        && report.crossover_includes_host_pack
        && report.crossover_end_to_end
        && !report.wave_crossover_reused
        && report
            .rows
            .iter()
            .all(|row| row.exact_parity && row.host_pack_included && row.end_to_end)
    {
        println!("PASS_R4_4_ACTIVE_CPU_GPU_ROUTER_EXACT_PARITY_PROBE");
    } else {
        eprintln!("NO_GO_R4_4_ACTIVE_CPU_GPU_ROUTER_EXACT_PARITY_PROBE");
        std::process::exit(2);
    }
}
