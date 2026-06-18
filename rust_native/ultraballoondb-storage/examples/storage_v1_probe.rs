use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ultraballoondb_storage::{
    hex_digest, sha256_file, Head, PageStore, SegmentEntry,
};

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
    if arguments.len() != 3 {
        return Err("usage: storage_v1_probe <database-root> <report-json>".into());
    }

    let root = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }

    let store = PageStore::create(&root)?;
    let segment1 = store.write_segment(
        1,
        0,
        vec![
            SegmentEntry::record(1, "alpha", 1001, b"alpha-payload")?,
            SegmentEntry::typed_edge(2, 1001, 2002, 7, 0.75)?,
            SegmentEntry::metadata(3, b"b1-metadata".to_vec())?,
        ],
    )?;
    let segment2 = store.write_segment(
        2,
        0,
        vec![
            SegmentEntry::record(4, "beta", 2002, b"beta-payload")?,
            SegmentEntry::typed_edge(5, 2002, 3003, 9, 0.5)?,
        ],
    )?;

    let manifest1_payload = format!(
        "generation=1\nsegment={}\nsegment_sha256={}\n",
        segment1.path.file_name().unwrap().to_string_lossy(),
        hex_digest(&sha256_file(&segment1.path)?)
    );
    let manifest1 = store.write_manifest(1, 1, manifest1_payload.as_bytes())?;
    let manifest1_file_hash = sha256_file(&manifest1.path)?;
    store.publish_head(&Head {
        generation: 1,
        manifest_filename: manifest1
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        manifest_sha256: manifest1_file_hash,
    })?;

    let manifest2_payload = format!(
        "generation=2\nsegment={}\nsegment_sha256={}\n",
        segment2.path.file_name().unwrap().to_string_lossy(),
        hex_digest(&sha256_file(&segment2.path)?)
    );
    let manifest2 = store.write_manifest(2, 1, manifest2_payload.as_bytes())?;
    let manifest2_file_hash = sha256_file(&manifest2.path)?;
    store.publish_head(&Head {
        generation: 2,
        manifest_filename: manifest2
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        manifest_sha256: manifest2_file_hash,
    })?;

    let reopened = PageStore::open(&root)?;
    let integrity = reopened.verify()?;
    let head = integrity.head.as_ref().ok_or("head missing after publish")?;
    if head.generation != 2 {
        return Err("head replacement did not publish generation 2".into());
    }
    if integrity.segment_count != 2 {
        return Err("unexpected segment count".into());
    }

    let report = format!(
        concat!(
            "{{\n",
            "  \"pass\": true,\n",
            "  \"database_root\": \"{}\",\n",
            "  \"segment_count\": {},\n",
            "  \"head_generation\": {},\n",
            "  \"head_replacement_verified\": true,\n",
            "  \"segment1_path\": \"{}\",\n",
            "  \"segment1_sha256\": \"{}\",\n",
            "  \"segment1_item_count\": {},\n",
            "  \"segment2_path\": \"{}\",\n",
            "  \"segment2_sha256\": \"{}\",\n",
            "  \"segment2_item_count\": {},\n",
            "  \"manifest_path\": \"{}\",\n",
            "  \"manifest_sha256\": \"{}\",\n",
            "  \"head_path\": \"{}\"\n",
            "}}\n"
        ),
        path_json(&root),
        integrity.segment_count,
        head.generation,
        path_json(&segment1.path),
        hex_digest(&sha256_file(&segment1.path)?),
        segment1.item_count,
        path_json(&segment2.path),
        hex_digest(&sha256_file(&segment2.path)?),
        segment2.item_count,
        path_json(&manifest2.path),
        hex_digest(&manifest2_file_hash),
        path_json(&root.join("CURRENT.ubhead")),
    );
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, report)?;
    println!("PASS_ULTRABALLOONDB_STORAGE_V1_PROBE");
    println!("REPORT={}", report_path.display());
    Ok(())
}
