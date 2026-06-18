use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_lifecycle::DurableDatabase;
use ultraballoondb_storage::sha256;
use ultraballoondb_trust::TrustLedger;
use ultraballoondb_trust_commit::{
    PolicyRegistry, TrustCommitJournal,
};

use crate::crypto::audit_root_digest;
use crate::governance::PolicyStatusLedger;
use crate::ledger::{AuthorizationLedger, KeyRegistry};
use crate::{
    hex, validate_policy_status_bindings, AuthError, Result, TrustPaths,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditExportReceipt {
    pub output_root: PathBuf,
    pub copied_file_count: usize,
    pub manifest_sha256: [u8; 32],
    pub summary_sha256: [u8; 32],
    pub root_digest: [u8; 32],
    pub source_unchanged: bool,
    pub deterministic_format: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileDigest {
    relative_path: String,
    size_bytes: u64,
    sha256: [u8; 32],
}

pub fn export_offline_audit(
    database_root: impl AsRef<Path>,
    paths: &TrustPaths,
    output_root: impl AsRef<Path>,
) -> Result<AuditExportReceipt> {
    let database_root = database_root.as_ref();
    let output_root = output_root.as_ref();

    if output_root.exists() {
        return Err(AuthError::Invalid(format!(
            "audit export output already exists: {}",
            output_root.display(),
        )));
    }
    let database_canonical = database_root.canonicalize()?;
    let trust_canonical = paths.root.canonicalize()?;
    let output_parent = output_root.parent().ok_or_else(|| {
        AuthError::Invalid(
            "audit export output must have a parent".to_string(),
        )
    })?;
    fs::create_dir_all(output_parent)?;
    let output_parent_canonical = output_parent.canonicalize()?;
    let output_absolute = output_parent_canonical.join(
        output_root.file_name().ok_or_else(|| {
            AuthError::Invalid(
                "audit export output filename is missing".to_string(),
            )
        })?,
    );
    if output_absolute.starts_with(&database_canonical)
        || output_absolute.starts_with(&trust_canonical)
        || database_canonical.starts_with(&output_absolute)
        || trust_canonical.starts_with(&output_absolute)
    {
        return Err(AuthError::Invalid(
            "audit export output overlaps a source root".to_string(),
        ));
    }

    let database = DurableDatabase::open(
        &database_canonical,
        false,
    )
    .map_err(|error| AuthError::Database(error.to_string()))?;
    let keys = KeyRegistry::open_strict(&paths.key_registry)?;
    let authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let policies = PolicyRegistry::open_strict(&paths.policy_registry)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let policy_status =
        PolicyStatusLedger::open_strict(&paths.policy_status)?;
    validate_policy_status_bindings(
        &policy_status,
        &authorizations,
        &policies,
    )?;
    let trust = TrustLedger::open_strict(&paths.trust_ledger)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let journal = TrustCommitJournal::open_strict(
        &paths.commit_journal,
    )
    .map_err(|error| AuthError::Trust(error.to_string()))?;

    let source_before = source_snapshot(
        &database_canonical,
        paths,
    )?;

    let result = (|| {
        fs::create_dir(&output_absolute)?;
        let export_database = output_absolute.join("database");
        let export_trust = output_absolute.join("trust");
        fs::create_dir(&export_database)?;
        fs::create_dir(&export_trust)?;

        copy_tree_strict(
            &database_canonical,
            &export_database,
        )?;
        for source in paths.all_files() {
            let filename = source.file_name().ok_or_else(|| {
                AuthError::Invalid(
                    "trust source filename missing".to_string(),
                )
            })?;
            copy_file_verified(
                source,
                &export_trust.join(filename),
            )?;
        }

        let (record_count, edge_count) = database.state_counts();
        let summary = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"ultraballoondb.trust.audit.summary.v1\",\n",
                "  \"database_state_digest\": \"{}\",\n",
                "  \"database_record_count\": {},\n",
                "  \"database_edge_count\": {},\n",
                "  \"key_event_count\": {},\n",
                "  \"active_key_count\": {},\n",
                "  \"authorization_count\": {},\n",
                "  \"policy_count\": {},\n",
                "  \"policy_revocation_count\": {},\n",
                "  \"active_policy_count\": {},\n",
                "  \"trust_transition_count\": {},\n",
                "  \"commit_journal_entry_count\": {},\n",
                "  \"key_registry_head\": \"{}\",\n",
                "  \"authorization_head\": \"{}\",\n",
                "  \"policy_registry_head\": \"{}\",\n",
                "  \"policy_status_head\": \"{}\",\n",
                "  \"trust_ledger_head\": \"{}\",\n",
                "  \"commit_journal_head\": \"{}\",\n",
                "  \"signature_algorithm\": \"HMAC-SHA256\",\n",
                "  \"raw_secret_persisted\": false,\n",
                "  \"network_enabled\": false,\n",
                "  \"automatic_repair_enabled\": false,\n",
                "  \"source_read_only\": true\n",
                "}}\n"
            ),
            hex(&database.state_sha256()),
            record_count,
            edge_count,
            keys.event_count(),
            keys.active_key_count(),
            authorizations.record_count(),
            policies.policy_count(),
            policy_status.revoked_count(),
            policies.policy_count()
                .saturating_sub(policy_status.revoked_count()),
            trust.transition_count(),
            journal.entry_count(),
            hex(&keys.head_digest()),
            hex(&authorizations.head_digest()),
            hex(&policies.head_digest()),
            hex(&policy_status.head_digest()),
            hex(&trust.head_digest()),
            hex(&journal.head_digest()),
        );
        let summary_path = output_absolute.join(
            "audit-summary.json",
        );
        fs::write(&summary_path, summary.as_bytes())?;
        sync_file(&summary_path)?;

        let manifest_entries = collect_export_files(
            &output_absolute,
            &["audit-manifest.json", "audit-receipt.json"],
        )?;
        let manifest = manifest_json(&manifest_entries);
        let manifest_path = output_absolute.join(
            "audit-manifest.json",
        );
        fs::write(&manifest_path, manifest.as_bytes())?;
        sync_file(&manifest_path)?;

        let summary_sha256 = sha256(summary.as_bytes());
        let manifest_sha256 = sha256(manifest.as_bytes());
        let root_digest = audit_root_digest(
            manifest_sha256,
            summary_sha256,
        );
        let receipt = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"ultraballoondb.trust.audit.receipt.v1\",\n",
                "  \"manifest_sha256\": \"{}\",\n",
                "  \"summary_sha256\": \"{}\",\n",
                "  \"root_digest\": \"{}\",\n",
                "  \"copied_file_count\": {},\n",
                "  \"source_unchanged\": true,\n",
                "  \"deterministic_format\": true\n",
                "}}\n"
            ),
            hex(&manifest_sha256),
            hex(&summary_sha256),
            hex(&root_digest),
            manifest_entries.len(),
        );
        let receipt_path = output_absolute.join(
            "audit-receipt.json",
        );
        fs::write(&receipt_path, receipt.as_bytes())?;
        sync_file(&receipt_path)?;

        verify_export(
            &output_absolute,
            database.state_sha256(),
            keys.event_count(),
            authorizations.record_count(),
            policies.policy_count(),
            policy_status.revoked_count(),
            trust.transition_count(),
            journal.entry_count(),
        )?;

        let source_after = source_snapshot(
            &database_canonical,
            paths,
        )?;
        if source_before != source_after {
            return Err(AuthError::Invalid(
                "audit source changed during export".to_string(),
            ));
        }

        Ok(AuditExportReceipt {
            output_root: output_absolute.clone(),
            copied_file_count: manifest_entries.len(),
            manifest_sha256,
            summary_sha256,
            root_digest,
            source_unchanged: true,
            deterministic_format: true,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&output_absolute);
    }
    result
}

fn verify_export(
    output_root: &Path,
    expected_database_digest: [u8; 32],
    expected_key_events: usize,
    expected_authorizations: usize,
    expected_policies: usize,
    expected_policy_revocations: usize,
    expected_transitions: usize,
    expected_journal_entries: usize,
) -> Result<()> {
    let database_root = output_root.join("database");
    let trust_root = output_root.join("trust");
    let paths = TrustPaths::from_root(&trust_root);

    let database = DurableDatabase::open(&database_root, false)
        .map_err(|error| AuthError::Database(error.to_string()))?;
    if database.state_sha256() != expected_database_digest {
        return Err(AuthError::Invalid(
            "exported database state digest mismatch".to_string(),
        ));
    }
    let keys = KeyRegistry::open_strict(&paths.key_registry)?;
    let authorizations =
        AuthorizationLedger::open_strict(&paths.authorization_ledger)?;
    let policies = PolicyRegistry::open_strict(&paths.policy_registry)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let policy_status =
        PolicyStatusLedger::open_strict(&paths.policy_status)?;
    validate_policy_status_bindings(
        &policy_status,
        &authorizations,
        &policies,
    )?;
    let trust = TrustLedger::open_strict(&paths.trust_ledger)
        .map_err(|error| AuthError::Trust(error.to_string()))?;
    let journal = TrustCommitJournal::open_strict(
        &paths.commit_journal,
    )
    .map_err(|error| AuthError::Trust(error.to_string()))?;

    if keys.event_count() != expected_key_events
        || authorizations.record_count() != expected_authorizations
        || policies.policy_count() != expected_policies
        || policy_status.revoked_count()
            != expected_policy_revocations
        || trust.transition_count() != expected_transitions
        || journal.entry_count() != expected_journal_entries
    {
        return Err(AuthError::Invalid(
            "exported ledger count mismatch".to_string(),
        ));
    }
    Ok(())
}

fn source_snapshot(
    database_root: &Path,
    paths: &TrustPaths,
) -> Result<Vec<FileDigest>> {
    let mut values = collect_tree_files(
        database_root,
        "database",
    )?;
    for path in paths.all_files() {
        if path.symlink_metadata()?.file_type().is_symlink() {
            return Err(AuthError::Invalid(format!(
                "trust source symlink rejected: {}",
                path.display(),
            )));
        }
        let metadata = path.metadata()?;
        if !metadata.is_file() {
            return Err(AuthError::Invalid(format!(
                "trust source is not a file: {}",
                path.display(),
            )));
        }
        values.push(FileDigest {
            relative_path: format!(
                "trust/{}",
                path.file_name()
                    .ok_or_else(|| AuthError::Invalid(
                        "trust filename missing".to_string(),
                    ))?
                    .to_string_lossy(),
            ),
            size_bytes: metadata.len(),
            sha256: sha256(&fs::read(path)?),
        });
    }
    values.sort_by(|left, right| {
        left.relative_path.cmp(&right.relative_path)
    });
    Ok(values)
}

fn copy_tree_strict(source: &Path, destination: &Path) -> Result<()> {
    for entry in sorted_entries(source)? {
        let source_path = entry.path();
        let relative = source_path.strip_prefix(source).map_err(|_| {
            AuthError::Invalid(
                "database path prefix mismatch".to_string(),
            )
        })?;
        let destination_path = destination.join(relative);
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(AuthError::Invalid(format!(
                "database symlink rejected: {}",
                source_path.display(),
            )));
        }
        if file_type.is_dir() {
            fs::create_dir_all(&destination_path)?;
            copy_tree_strict(
                &source_path,
                &destination_path,
            )?;
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_file_verified(&source_path, &destination_path)?;
        } else {
            return Err(AuthError::Invalid(format!(
                "unsupported database filesystem entry: {}",
                source_path.display(),
            )));
        }
    }
    Ok(())
}

fn copy_file_verified(source: &Path, destination: &Path) -> Result<()> {
    if source.symlink_metadata()?.file_type().is_symlink() {
        return Err(AuthError::Invalid(format!(
            "symlink copy rejected: {}",
            source.display(),
        )));
    }
    let bytes = fs::read(source)?;
    fs::write(destination, &bytes)?;
    sync_file(destination)?;
    let copied = fs::read(destination)?;
    if sha256(&copied) != sha256(&bytes) {
        return Err(AuthError::Invalid(format!(
            "copied file hash mismatch: {}",
            source.display(),
        )));
    }
    Ok(())
}

fn collect_export_files(
    root: &Path,
    excluded: &[&str],
) -> Result<Vec<FileDigest>> {
    let mut values = collect_tree_files(root, "")?;
    values.retain(|value| {
        !excluded.iter().any(|excluded_name| {
            value.relative_path == *excluded_name
        })
    });
    values.sort_by(|left, right| {
        left.relative_path.cmp(&right.relative_path)
    });
    Ok(values)
}

fn collect_tree_files(
    root: &Path,
    prefix: &str,
) -> Result<Vec<FileDigest>> {
    let mut values = Vec::new();
    collect_tree_files_inner(root, root, prefix, &mut values)?;
    values.sort_by(|left, right| {
        left.relative_path.cmp(&right.relative_path)
    });
    Ok(values)
}

fn collect_tree_files_inner(
    base: &Path,
    current: &Path,
    prefix: &str,
    output: &mut Vec<FileDigest>,
) -> Result<()> {
    for entry in sorted_entries(current)? {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(AuthError::Invalid(format!(
                "audit source symlink rejected: {}",
                path.display(),
            )));
        }
        if file_type.is_dir() {
            collect_tree_files_inner(
                base,
                &path,
                prefix,
                output,
            )?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(base).map_err(|_| {
                AuthError::Invalid(
                    "audit path prefix mismatch".to_string(),
                )
            })?;
            let relative_text = relative_path_text(relative);
            let final_path = if prefix.is_empty() {
                relative_text
            } else if relative_text.is_empty() {
                prefix.to_string()
            } else {
                format!("{prefix}/{relative_text}")
            };
            let metadata = path.metadata()?;
            output.push(FileDigest {
                relative_path: final_path,
                size_bytes: metadata.len(),
                sha256: sha256(&fs::read(&path)?),
            });
        } else {
            return Err(AuthError::Invalid(format!(
                "unsupported audit source entry: {}",
                path.display(),
            )));
        }
    }
    Ok(())
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn manifest_json(entries: &[FileDigest]) -> String {
    let values = entries.iter().map(|entry| {
        format!(
            concat!(
                "    {{",
                "\"path\":\"{}\",",
                "\"size_bytes\":{},",
                "\"sha256\":\"{}\"",
                "}}"
            ),
            json_escape(&entry.relative_path),
            entry.size_bytes,
            hex(&entry.sha256),
        )
    }).collect::<Vec<_>>().join(",\n");
    format!(
        concat!(
            "{{\n",
            "  \"schema\": \"ultraballoondb.trust.audit.manifest.v1\",\n",
            "  \"file_count\": {},\n",
            "  \"files\": [\n",
            "{}\n",
            "  ]\n",
            "}}\n"
        ),
        entries.len(),
        values,
    )
}

fn relative_path_text(path: &Path) -> String {
    path.components()
        .map(|component| {
            component.as_os_str().to_string_lossy()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn sync_file(path: &Path) -> Result<()> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
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
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(&mut output, "\\u{:04X}", character as u32)
                    .expect("write to String");
            }
            character => output.push(character),
        }
    }
    output
}
