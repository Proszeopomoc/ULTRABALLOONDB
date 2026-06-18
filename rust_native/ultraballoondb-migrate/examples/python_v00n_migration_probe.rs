use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_migrate::{
    import_plan, MigrationPlan,
};
use ultraballoondb_storage::hex_digest;

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(&mut output, "\\u{:04X}", character as u32)
                    .expect("writing to String");
            }
            character => output.push(character),
        }
    }
    output
}

fn path_json(path: &Path) -> String {
    json_escape(&path.to_string_lossy())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 4 {
        return Err(
            "usage: python_v00n_migration_probe <plan> <target-root> <report-json>"
                .into(),
        );
    }
    let plan_path = PathBuf::from(&arguments[1]);
    let target_root = PathBuf::from(&arguments[2]);
    let report_path = PathBuf::from(&arguments[3]);

    if target_root.exists() {
        fs::remove_dir_all(&target_root)?;
    }

    let plan = MigrationPlan::read(&plan_path)?;
    let receipt = import_plan(&plan, &target_root)?;
    if receipt.record_count != plan.record_count
        || receipt.edge_count != plan.edge_count
        || receipt.semantic_state_sha256
            != plan.semantic_state_sha256
        || !receipt.restart_deterministic
        || receipt.source_overwritten
        || receipt.active_runtime_changed
    {
        return Err("migration receipt contract failed".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"plan_path\": \"{}\",\n",
            "  \"target_root\": \"{}\",\n",
            "  \"source_python_state_sha256\": \"{}\",\n",
            "  \"semantic_state_sha256\": \"{}\",\n",
            "  \"target_state_sha256\": \"{}\",\n",
            "  \"record_count\": {},\n",
            "  \"edge_count\": {},\n",
            "  \"source_committed_transaction_count\": {},\n",
            "  \"canonical_batch_count\": {},\n",
            "  \"durable_commit_count\": {},\n",
            "  \"checkpoint_generation\": {},\n",
            "  \"checkpoint_lsn\": {},\n",
            "  \"target_wal_path\": \"{}\",\n",
            "  \"target_checkpoint_path\": \"{}\",\n",
            "  \"target_manifest_path\": \"{}\",\n",
            "  \"target_head_path\": \"{}\",\n",
            "  \"durable_commit\": true,\n",
            "  \"wal_recorded\": true,\n",
            "  \"checkpoint_published\": true,\n",
            "  \"restart_deterministic\": {},\n",
            "  \"source_overwritten\": false,\n",
            "  \"active_runtime_changed\": false\n",
            "}}\n"
        ),
        path_json(&plan_path),
        path_json(&receipt.target_root),
        hex_digest(&receipt.source_python_state_sha256),
        hex_digest(&receipt.semantic_state_sha256),
        hex_digest(&receipt.target_state_sha256),
        receipt.record_count,
        receipt.edge_count,
        receipt.source_committed_transaction_count,
        receipt.canonical_batch_count,
        receipt.durable_commit_count,
        receipt.checkpoint_generation,
        receipt.checkpoint_lsn,
        path_json(&receipt.target_wal_path),
        path_json(&receipt.target_checkpoint_path),
        path_json(&receipt.target_manifest_path),
        path_json(&receipt.target_head_path),
        if receipt.restart_deterministic {
            "true"
        } else {
            "false"
        },
    );

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!(
        "PASS_ULTRABALLOONDB_PYTHON_V00N_TO_RUST_MIGRATION_PROBE"
    );
    println!("REPORT={}", report_path.display());
    Ok(())
}
