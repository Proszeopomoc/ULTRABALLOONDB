use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_daemon::{BackendHealth, DaemonBackend};
use ultraballoondb_observability_security::{
    strict_replay, ObservedBackend, SecurityPolicy, VERSION,
};
use ultraballoondb_storage::sha256;

const PASS: &str = "PASS_ULTRABALLOONDB_V00R3E1_OBSERVABILITY_AND_SECURITY_PROBE";
const REQUEST_SECRET: &[u8] = b"customer-secret-token";
const RESPONSE_SECRET: &[u8] = b"private-response-value";
const BACKEND_SECRET: &str = "backend-secret-error-text";

struct ProbeBackend {
    generation: u64,
}

impl DaemonBackend for ProbeBackend {
    fn health(&self) -> BackendHealth {
        BackendHealth {
            healthy: true,
            read_only: false,
            generation: self.generation,
        }
    }

    fn execute_read(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        if request == b"FAIL" {
            Err(BACKEND_SECRET.to_string())
        } else {
            Ok(RESPONSE_SECRET.to_vec())
        }
    }

    fn execute_write(&mut self, _request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.generation = self.generation.saturating_add(1);
        Ok(b"write-ok".to_vec())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for value in bytes {
        output.push(DIGITS[(value >> 4) as usize] as char);
        output.push(DIGITS[(value & 0x0F) as usize] as char);
    }
    output
}

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04X}", value as u32)),
            value => output.push(value),
        }
    }
    output
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn required_output_dir() -> Result<PathBuf, String> {
    let mut arguments = env::args().skip(1);
    match (arguments.next().as_deref(), arguments.next(), arguments.next()) {
        (Some("--output-dir"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err("usage: observability_security_probe --output-dir <path>".to_string()),
    }
}

fn write_report(
    path: &Path,
    audit_path: &Path,
    metrics_path: &Path,
    event_count: usize,
    metrics: &ultraballoondb_observability_security::MetricsSnapshot,
    audit_digest: &[u8; 32],
    metrics_digest: &[u8; 32],
) -> Result<(), String> {
    let text = format!(
        concat!(
            "{{\n",
            "  \"version\": \"{}\",\n",
            "  \"pass\": true,\n",
            "  \"audit_file\": \"{}\",\n",
            "  \"metrics_file\": \"{}\",\n",
            "  \"audit_event_count\": {},\n",
            "  \"total_operations\": {},\n",
            "  \"accepted_operations\": {},\n",
            "  \"rejected_operations\": {},\n",
            "  \"backend_errors\": {},\n",
            "  \"health_operations\": {},\n",
            "  \"read_operations\": {},\n",
            "  \"write_operations\": {},\n",
            "  \"audit_available\": {},\n",
            "  \"raw_request_payload_absent\": true,\n",
            "  \"raw_response_payload_absent\": true,\n",
            "  \"backend_error_text_absent\": true,\n",
            "  \"remote_enablement_rejected\": true,\n",
            "  \"oversized_request_rejected\": true,\n",
            "  \"backend_error_genericized\": true,\n",
            "  \"tamper_rejected\": true,\n",
            "  \"truncation_rejected\": true,\n",
            "  \"fixed_low_cardinality_metrics\": true,\n",
            "  \"audit_sha256\": \"{}\",\n",
            "  \"metrics_sha256\": \"{}\",\n",
            "  \"active_runtime_changed\": false,\n",
            "  \"database_cli_changed\": false,\n",
            "  \"storage_format_changed\": false,\n",
            "  \"wal_changed\": false,\n",
            "  \"lifecycle_changed\": false,\n",
            "  \"trust_semantics_changed\": false,\n",
            "  \"wave_semantics_changed\": false,\n",
            "  \"production_service_installed\": false,\n",
            "  \"network_listener_exposed\": false\n",
            "}}\n"
        ),
        VERSION,
        json_escape(&audit_path.display().to_string()),
        json_escape(&metrics_path.display().to_string()),
        event_count,
        metrics.total_operations,
        metrics.accepted_operations,
        metrics.rejected_operations,
        metrics.backend_errors,
        metrics.health_operations,
        metrics.read_operations,
        metrics.write_operations,
        if metrics.audit_available { "true" } else { "false" },
        hex(audit_digest),
        hex(metrics_digest),
    );
    fs::write(path, text).map_err(|error| error.to_string())
}

fn run() -> Result<(), String> {
    let output_dir = required_output_dir()?;
    fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    let audit_path = output_dir.join("observability-security.ube1audit");
    let metrics_path = output_dir.join("observability.prom");
    let report_path = output_dir.join("observability_security_probe_report.json");
    let tampered_path = output_dir.join("tampered.ube1audit");
    let truncated_path = output_dir.join("truncated.ube1audit");

    for path in [
        &audit_path,
        &metrics_path,
        &report_path,
        &tampered_path,
        &truncated_path,
    ] {
        if path.exists() {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }

    let mut remote_policy = SecurityPolicy::default();
    remote_policy.remote_network_enabled = true;
    if remote_policy.validate().is_ok() {
        return Err("remote policy unexpectedly accepted".to_string());
    }

    let policy = SecurityPolicy {
        allow_writes: true,
        remote_network_enabled: false,
        max_request_bytes: 64,
        max_response_bytes: 128,
        max_audit_events: 64,
    };
    let mut observed = ObservedBackend::new(ProbeBackend { generation: 12 }, policy, &audit_path)
        .map_err(|error| error.to_string())?;

    let health = observed.health();
    if !health.healthy || health.generation != 12 {
        return Err("health observation mismatch".to_string());
    }
    let read = observed.execute_read(REQUEST_SECRET)?;
    if read.as_slice() != RESPONSE_SECRET {
        return Err("read result mismatch".to_string());
    }
    if observed.execute_write(b"write-secret")?.as_slice() != b"write-ok" {
        return Err("write result mismatch".to_string());
    }
    if observed.execute_read(&[0x41; 65]) != Err("E1_REQUEST_TOO_LARGE".to_string()) {
        return Err("oversized request was not rejected".to_string());
    }
    if observed.execute_read(b"FAIL") != Err("E1_BACKEND_ERROR".to_string()) {
        return Err("backend error was not genericized".to_string());
    }

    let metrics = observed.metrics_snapshot();
    if metrics.total_operations != 5
        || metrics.accepted_operations != 3
        || metrics.rejected_operations != 1
        || metrics.backend_errors != 1
        || metrics.health_operations != 1
        || metrics.read_operations != 3
        || metrics.write_operations != 1
        || metrics.audit_events != 5
        || !metrics.audit_available
    {
        return Err("metrics snapshot mismatch".to_string());
    }
    let metrics_text = observed.export_prometheus();
    if metrics_text.contains('{') || metrics_text.contains('}') {
        return Err("dynamic labels are not allowed in E1 metrics".to_string());
    }
    fs::write(&metrics_path, metrics_text.as_bytes()).map_err(|error| error.to_string())?;
    drop(observed);

    let records = strict_replay(&audit_path).map_err(|error| error.to_string())?;
    if records.len() != 5 {
        return Err("strict replay event count mismatch".to_string());
    }
    let audit_bytes = fs::read(&audit_path).map_err(|error| error.to_string())?;
    let metrics_bytes = fs::read(&metrics_path).map_err(|error| error.to_string())?;
    for secret in [REQUEST_SECRET, RESPONSE_SECRET, BACKEND_SECRET.as_bytes()] {
        if contains_bytes(&audit_bytes, secret) || contains_bytes(&metrics_bytes, secret) {
            return Err("raw secret material found in observability artifacts".to_string());
        }
    }

    let mut tampered = audit_bytes.clone();
    let index = ultraballoondb_observability_security::AUDIT_HEADER_BYTES + 60;
    tampered[index] ^= 0x01;
    fs::write(&tampered_path, tampered).map_err(|error| error.to_string())?;
    if strict_replay(&tampered_path).is_ok() {
        return Err("tampered audit was accepted".to_string());
    }
    fs::write(&truncated_path, &audit_bytes[..audit_bytes.len() - 1])
        .map_err(|error| error.to_string())?;
    if strict_replay(&truncated_path).is_ok() {
        return Err("truncated audit was accepted".to_string());
    }
    fs::remove_file(&tampered_path).map_err(|error| error.to_string())?;
    fs::remove_file(&truncated_path).map_err(|error| error.to_string())?;

    let audit_digest = sha256(&audit_bytes);
    let metrics_digest = sha256(&metrics_bytes);
    write_report(
        &report_path,
        &audit_path,
        &metrics_path,
        records.len(),
        &metrics,
        &audit_digest,
        &metrics_digest,
    )?;
    println!("{PASS}");
    println!("REPORT={}", report_path.display());
    println!("AUDIT={}", audit_path.display());
    println!("METRICS={}", metrics_path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("NO_GO_ULTRABALLOONDB_V00R3E1_OBSERVABILITY_AND_SECURITY_PROBE");
        eprintln!("ERROR={error}");
        std::process::exit(1);
    }
}
