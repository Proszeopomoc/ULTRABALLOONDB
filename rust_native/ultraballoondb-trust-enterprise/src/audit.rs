use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::sha256;
use ultraballoondb_trust_auth::{
    export_offline_audit, AuthorizationLedger, KeyEventKind,
    KeyRegistry, TrustPaths, DOMAIN_POLICY_REGISTER,
    DOMAIN_POLICY_REVOKE, DOMAIN_TRUST_COMMIT,
};

use crate::approval::ApprovalLedger;
use crate::crypto::enterprise_audit_root_digest;
use crate::profile::open_enterprise_profile;
use crate::{
    hex, EnterpriseError, EnterprisePaths, Result,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnterpriseAuditReceipt {
    pub output_root: PathBuf,
    pub protected_operation_count: usize,
    pub covered_operation_count: usize,
    pub uncovered_operation_count: usize,
    pub expired_request_count: usize,
    pub manifest_sha256: [u8; 32],
    pub summary_sha256: [u8; 32],
    pub core_receipt_sha256: [u8; 32],
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

pub fn export_enterprise_audit(
    database_root: impl AsRef<Path>,
    trust_root: impl AsRef<Path>,
    output_root: impl AsRef<Path>,
    logical_timestamp: u64,
) -> Result<EnterpriseAuditReceipt> {
    let database_root = database_root.as_ref();
    let trust_root = trust_root.as_ref();
    let output_root = output_root.as_ref();
    if logical_timestamp == 0 {
        return Err(EnterpriseError::Invalid(
            "enterprise audit logical timestamp must be non-zero"
                .to_string(),
        ));
    }
    if output_root.exists() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise audit output already exists: {}",
            output_root.display(),
        )));
    }

    let trust_paths = TrustPaths::from_root(trust_root);
    let enterprise_paths =
        EnterprisePaths::from_trust_root(trust_root);
    let profile = open_enterprise_profile(
        &enterprise_paths.profile,
    )?;
    let approvals = ApprovalLedger::open_strict(
        &enterprise_paths.approvals,
    )?;
    let keys = KeyRegistry::open_strict(
        &trust_paths.key_registry,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;
    let authorizations = AuthorizationLedger::open_strict(
        &trust_paths.authorization_ledger,
    )
    .map_err(|error| EnterpriseError::Trust(error.to_string()))?;

    let finalized_references: BTreeSet<[u8; 32]> = approvals
        .states()
        .values()
        .filter_map(|state| {
            state.finalization.as_ref().map(|event| {
                event.operation_reference
            })
        })
        .collect();
    if finalized_references.len()
        != approvals.finalization_count()
    {
        return Err(EnterpriseError::Invalid(
            "enterprise approval operation references are not unique"
                .to_string(),
        ));
    }

    let mut protected_references = BTreeSet::new();
    for record in authorizations.records() {
        if record.proof.logical_timestamp < profile.activated_at {
            continue;
        }
        if matches!(
            record.proof.domain_code,
            DOMAIN_POLICY_REGISTER
                | DOMAIN_POLICY_REVOKE
                | DOMAIN_TRUST_COMMIT
        ) {
            protected_references.insert(record.event_id);
        }
    }
    for event in keys.events() {
        if event.logical_timestamp >= profile.activated_at
            && event.kind == KeyEventKind::Rotate
        {
            protected_references.insert(event.frame_digest);
        }
    }
    let covered_operation_count = protected_references
        .intersection(&finalized_references)
        .count();
    let uncovered_operation_count = protected_references
        .difference(&finalized_references)
        .count();
    if uncovered_operation_count != 0 {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise audit found uncovered protected operations: {uncovered_operation_count}",
        )));
    }

    let database_canonical = database_root.canonicalize()?;
    let trust_canonical = trust_root.canonicalize()?;
    let output_parent = output_root.parent().ok_or_else(|| {
        EnterpriseError::Invalid(
            "enterprise audit output requires a parent"
                .to_string(),
        )
    })?;
    fs::create_dir_all(output_parent)?;
    let output_parent_canonical =
        output_parent.canonicalize()?;
    let output_absolute = output_parent_canonical.join(
        output_root.file_name().ok_or_else(|| {
            EnterpriseError::Invalid(
                "enterprise audit output filename missing"
                    .to_string(),
            )
        })?,
    );
    if output_absolute.starts_with(&database_canonical)
        || output_absolute.starts_with(&trust_canonical)
        || database_canonical.starts_with(&output_absolute)
        || trust_canonical.starts_with(&output_absolute)
    {
        return Err(EnterpriseError::Invalid(
            "enterprise audit output overlaps source"
                .to_string(),
        ));
    }

    let source_before = source_snapshot(
        &database_canonical,
        &trust_paths,
        &enterprise_paths,
    )?;

    let result = (|| {
        fs::create_dir(&output_absolute)?;
        let core_output = output_absolute.join("core-audit");
        let core_receipt = export_offline_audit(
            &database_canonical,
            &trust_paths,
            &core_output,
        )
        .map_err(|error| {
            EnterpriseError::Trust(error.to_string())
        })?;

        let enterprise_output =
            output_absolute.join("enterprise");
        fs::create_dir(&enterprise_output)?;
        copy_file_verified(
            &enterprise_paths.profile,
            &enterprise_output.join("enterprise.ubent"),
        )?;
        copy_file_verified(
            &enterprise_paths.approvals,
            &enterprise_output.join("approvals.ubapproval"),
        )?;

        let expired_request_count = approvals
            .expired_count_at(logical_timestamp);
        let summary = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"ultraballoondb.trust.enterprise.audit.summary.v1\",\n",
                "  \"profile_id\": \"{}\",\n",
                "  \"profile_digest\": \"{}\",\n",
                "  \"profile_activated_at\": {},\n",
                "  \"approval_threshold\": {},\n",
                "  \"approver_role_mask\": {},\n",
                "  \"approval_event_count\": {},\n",
                "  \"approval_request_count\": {},\n",
                "  \"approval_signature_count\": {},\n",
                "  \"approval_finalization_count\": {},\n",
                "  \"expired_request_count\": {},\n",
                "  \"protected_operation_count\": {},\n",
                "  \"covered_operation_count\": {},\n",
                "  \"uncovered_operation_count\": {},\n",
                "  \"invalid_finalization_count\": 0,\n",
                "  \"expired_finalization_count\": 0,\n",
                "  \"enterprise_compliance_pass\": true,\n",
                "  \"logical_timestamp\": {},\n",
                "  \"core_audit_root_digest\": \"{}\",\n",
                "  \"source_read_only\": true,\n",
                "  \"raw_secret_persisted\": false,\n",
                "  \"network_enabled\": false,\n",
                "  \"automatic_repair_enabled\": false\n",
                "}}\n"
            ),
            json_escape(&profile.profile_id),
            hex(&profile.profile_digest),
            profile.activated_at,
            profile.approval_threshold,
            profile.approver_role_mask,
            approvals.event_count(),
            approvals.request_count(),
            approvals.approval_count(),
            approvals.finalization_count(),
            expired_request_count,
            protected_references.len(),
            covered_operation_count,
            uncovered_operation_count,
            logical_timestamp,
            hex(&core_receipt.root_digest),
        );
        let summary_path = output_absolute.join(
            "enterprise-summary.json",
        );
        fs::write(&summary_path, summary.as_bytes())?;
        sync_file(&summary_path)?;

        let manifest_entries = collect_files(
            &output_absolute,
            &[
                "enterprise-manifest.json",
                "enterprise-receipt.json",
            ],
        )?;
        let manifest = manifest_json(&manifest_entries);
        let manifest_path = output_absolute.join(
            "enterprise-manifest.json",
        );
        fs::write(&manifest_path, manifest.as_bytes())?;
        sync_file(&manifest_path)?;

        let manifest_sha256 = sha256(manifest.as_bytes());
        let summary_sha256 = sha256(summary.as_bytes());
        let core_receipt_path = core_output.join(
            "audit-receipt.json",
        );
        let core_receipt_sha256 = sha256(
            &fs::read(&core_receipt_path)?,
        );
        let root_digest = enterprise_audit_root_digest(
            manifest_sha256,
            summary_sha256,
            core_receipt_sha256,
        );
        let receipt = format!(
            concat!(
                "{{\n",
                "  \"schema\": \"ultraballoondb.trust.enterprise.audit.receipt.v1\",\n",
                "  \"manifest_sha256\": \"{}\",\n",
                "  \"summary_sha256\": \"{}\",\n",
                "  \"core_receipt_sha256\": \"{}\",\n",
                "  \"root_digest\": \"{}\",\n",
                "  \"file_count\": {},\n",
                "  \"source_unchanged\": true,\n",
                "  \"deterministic_format\": true,\n",
                "  \"enterprise_compliance_pass\": true\n",
                "}}\n"
            ),
            hex(&manifest_sha256),
            hex(&summary_sha256),
            hex(&core_receipt_sha256),
            hex(&root_digest),
            manifest_entries.len(),
        );
        let receipt_path = output_absolute.join(
            "enterprise-receipt.json",
        );
        fs::write(&receipt_path, receipt.as_bytes())?;
        sync_file(&receipt_path)?;

        let source_after = source_snapshot(
            &database_canonical,
            &trust_paths,
            &enterprise_paths,
        )?;
        if source_before != source_after {
            return Err(EnterpriseError::Invalid(
                "enterprise audit source changed during export"
                    .to_string(),
            ));
        }

        Ok(EnterpriseAuditReceipt {
            output_root: output_absolute.clone(),
            protected_operation_count:
                protected_references.len(),
            covered_operation_count,
            uncovered_operation_count,
            expired_request_count,
            manifest_sha256,
            summary_sha256,
            core_receipt_sha256,
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

fn source_snapshot(
    database_root: &Path,
    trust_paths: &TrustPaths,
    enterprise_paths: &EnterprisePaths,
) -> Result<Vec<FileDigest>> {
    let mut values = collect_tree_files(
        database_root,
        "database",
    )?;
    for source in trust_paths.all_files() {
        push_file_digest(
            &mut values,
            source,
            &format!(
                "trust/{}",
                source.file_name()
                    .ok_or_else(|| EnterpriseError::Invalid(
                        "trust source filename missing"
                            .to_string(),
                    ))?
                    .to_string_lossy(),
            ),
        )?;
    }
    for source in enterprise_paths.all_files() {
        push_file_digest(
            &mut values,
            source,
            &format!(
                "enterprise/{}",
                source.file_name()
                    .ok_or_else(|| EnterpriseError::Invalid(
                        "enterprise source filename missing"
                            .to_string(),
                    ))?
                    .to_string_lossy(),
            ),
        )?;
    }
    values.sort_by(|left, right| {
        left.relative_path.cmp(&right.relative_path)
    });
    Ok(values)
}

fn push_file_digest(
    output: &mut Vec<FileDigest>,
    path: &Path,
    relative_path: &str,
) -> Result<()> {
    if path.symlink_metadata()?.file_type().is_symlink() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise audit source symlink rejected: {}",
            path.display(),
        )));
    }
    let metadata = path.metadata()?;
    if !metadata.is_file() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise audit source is not a file: {}",
            path.display(),
        )));
    }
    output.push(FileDigest {
        relative_path: relative_path.to_string(),
        size_bytes: metadata.len(),
        sha256: sha256(&fs::read(path)?),
    });
    Ok(())
}

fn copy_file_verified(
    source: &Path,
    destination: &Path,
) -> Result<()> {
    if source.symlink_metadata()?.file_type().is_symlink() {
        return Err(EnterpriseError::Invalid(format!(
            "enterprise audit symlink rejected: {}",
            source.display(),
        )));
    }
    let bytes = fs::read(source)?;
    fs::write(destination, &bytes)?;
    sync_file(destination)?;
    if sha256(&fs::read(destination)?) != sha256(&bytes) {
        return Err(EnterpriseError::Integrity(format!(
            "enterprise audit copied file mismatch: {}",
            source.display(),
        )));
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    excluded: &[&str],
) -> Result<Vec<FileDigest>> {
    let mut values = collect_tree_files(root, "")?;
    values.retain(|entry| {
        !excluded.iter().any(|name| {
            entry.relative_path == *name
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
    let mut output = Vec::new();
    collect_tree_files_inner(
        root,
        root,
        prefix,
        &mut output,
    )?;
    output.sort_by(|left, right| {
        left.relative_path.cmp(&right.relative_path)
    });
    Ok(output)
}

fn collect_tree_files_inner(
    base: &Path,
    current: &Path,
    prefix: &str,
    output: &mut Vec<FileDigest>,
) -> Result<()> {
    let mut entries = fs::read_dir(current)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(EnterpriseError::Invalid(format!(
                "enterprise audit tree symlink rejected: {}",
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
                EnterpriseError::Invalid(
                    "enterprise audit path prefix mismatch"
                        .to_string(),
                )
            })?;
            let relative_text = relative.components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_string_lossy()
                })
                .collect::<Vec<_>>()
                .join("/");
            let final_path = if prefix.is_empty() {
                relative_text
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
            return Err(EnterpriseError::Invalid(format!(
                "unsupported enterprise audit entry: {}",
                path.display(),
            )));
        }
    }
    Ok(())
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
            "  \"schema\": \"ultraballoondb.trust.enterprise.audit.manifest.v1\",\n",
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
                write!(
                    &mut output,
                    "\\u{:04X}",
                    character as u32,
                )
                .expect("write to String");
            }
            character => output.push(character),
        }
    }
    output
}
