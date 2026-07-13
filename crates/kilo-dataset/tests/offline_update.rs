use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use arrow::array::{ArrayRef, StringArray, UInt8Array, UInt64Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{SecondsFormat, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use kilo_dataset::{UpdateOptions, open_active, update};
use parquet::arrow::ArrowWriter;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn offline_release_install_replaces_edge_sources_and_preserves_last_good_snapshot() {
    let fixture = TempDir::new().unwrap();
    build_base(fixture.path());
    build_edge(fixture.path());
    let home = TempDir::new().unwrap();
    let options = UpdateOptions {
        offline_dir: Some(fixture.path().to_owned()),
        ..UpdateOptions::default()
    };

    let report = update(home.path(), &options).expect("fixture update succeeds");
    assert_eq!(report.records, 3);
    let snapshot = open_active(home.path()).expect("active snapshot opens");
    assert!(
        snapshot
            .query("203.0.113.7".parse().unwrap())
            .unwrap()
            .is_empty(),
        "edge feodo source must replace its base records"
    );
    let c2 = snapshot.query("203.0.113.8".parse().unwrap()).unwrap();
    assert_eq!(c2[0].classification, "command-and-control");
    assert_eq!(c2[0].license_id, "CC0-1.0");
    let prefix = snapshot.query("198.51.100.99".parse().unwrap()).unwrap();
    assert_eq!(prefix[0].classification, "dedicated-malicious-netblock");
    let tor = snapshot.query("2001:db8::7".parse().unwrap()).unwrap();
    assert_eq!(tor[0].classification, "tor-exit");

    OpenOptions::new()
        .append(true)
        .open(fixture.path().join("kilocheck-data-edge.tar.gz"))
        .unwrap()
        .write_all(b"tamper")
        .unwrap();
    let error = update(home.path(), &options).expect_err("tampered update must fail");
    assert!(error.to_string().contains("checksum mismatch"));
    let still_active = open_active(home.path()).expect("last verified snapshot remains active");
    assert_eq!(still_active.manifest.snapshot_id, report.snapshot_id);
}

#[test]
fn index_tampering_is_detected_before_query() {
    let fixture = TempDir::new().unwrap();
    build_base(fixture.path());
    build_edge(fixture.path());
    let home = TempDir::new().unwrap();
    let options = UpdateOptions {
        offline_dir: Some(fixture.path().to_owned()),
        ..UpdateOptions::default()
    };
    let report = update(home.path(), &options).unwrap();
    let index = home
        .path()
        .join("snapshots")
        .join(report.snapshot_id)
        .join("snapshot.kilo");
    OpenOptions::new()
        .append(true)
        .open(index)
        .unwrap()
        .write_all(b"tamper")
        .unwrap();
    let error = open_active(home.path())
        .err()
        .expect("tampered index must not open");
    assert!(error.to_string().contains("hash mismatch"));
}

#[test]
fn compiler_rejects_duplicate_claims_and_conflicting_indicators() {
    let duplicate_fixture = TempDir::new().unwrap();
    build_base_rows(
        duplicate_fixture.path(),
        &[
            ("01", "ipv4", "203.0.113.7", 4, 32),
            ("02", "prefix", "198.51.100.0/24", 4, 24),
        ],
        &[
            (
                "11",
                "01",
                "feodo-c2",
                "directly-observed",
                "command-and-control",
            ),
            (
                "11",
                "02",
                "spamhaus-drop-v4",
                "investigator-confirmed",
                "dedicated-malicious-netblock",
            ),
        ],
    );
    build_edge(duplicate_fixture.path());
    let home = TempDir::new().unwrap();
    let error = update(
        home.path(),
        &UpdateOptions {
            offline_dir: Some(duplicate_fixture.path().to_owned()),
            ..UpdateOptions::default()
        },
    )
    .expect_err("duplicate claim IDs must fail");
    assert!(error.to_string().contains("duplicate claim_id"));

    let conflict_fixture = TempDir::new().unwrap();
    build_base_rows(
        conflict_fixture.path(),
        &[
            ("01", "ipv4", "203.0.113.7", 4, 32),
            ("01", "ipv4", "203.0.113.8", 4, 32),
        ],
        &[(
            "11",
            "01",
            "spamhaus-drop-v4",
            "investigator-confirmed",
            "dedicated-malicious-netblock",
        )],
    );
    build_edge(conflict_fixture.path());
    let error = update(
        home.path(),
        &UpdateOptions {
            offline_dir: Some(conflict_fixture.path().to_owned()),
            ..UpdateOptions::default()
        },
    )
    .expect_err("conflicting indicator IDs must fail");
    assert!(error.to_string().contains("conflicting values"));
}

fn build_base(output: &Path) {
    build_base_rows(
        output,
        &[
            ("01", "ipv4", "203.0.113.7", 4, 32),
            ("02", "prefix", "198.51.100.0/24", 4, 24),
        ],
        &[
            (
                "11",
                "01",
                "feodo-c2",
                "directly-observed",
                "command-and-control",
            ),
            (
                "12",
                "02",
                "spamhaus-drop-v4",
                "investigator-confirmed",
                "dedicated-malicious-netblock",
            ),
        ],
    );
}

fn build_base_rows(
    output: &Path,
    indicators: &[(&str, &str, &str, u8, u8)],
    claims: &[(&str, &str, &str, &str, &str)],
) {
    let root = TempDir::new().unwrap();
    let data = root.path().join("canonical");
    fs::create_dir(&data).unwrap();
    write_indicators(&data.join("indicators.parquet"), indicators);
    write_claims(&data.join("claims.parquet"), claims);
    let indicators_hash = sha(&data.join("indicators.parquet"));
    let claims_hash = sha(&data.join("claims.parquet"));
    let manifest = json!({
        "schema": "kilo.canonical.snapshot.v1",
        "snapshot_id": "11".repeat(32),
        "created_at": now(),
        "sources": [
            {"id":"feodo-c2","sha256":"aa".repeat(32)},
            {"id":"spamhaus-drop-v4","sha256":"bb".repeat(32)}
        ],
        "tables": {
            "indicators":{"rows":indicators.len(),"sha256":indicators_hash},
            "claims":{"rows":claims.len(),"sha256":claims_hash}
        }
    });
    fs::write(
        data.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    package(
        root.path(),
        "canonical",
        &output.join("kilocheck-data-base.tar.gz"),
    );
    checksum(&output.join("kilocheck-data-base.tar.gz"));
}

fn build_edge(output: &Path) {
    let root = TempDir::new().unwrap();
    let data = root.path().join("edge");
    fs::create_dir(&data).unwrap();
    write_indicators(
        &data.join("indicators.parquet"),
        &[
            ("03", "ipv4", "203.0.113.8", 4, 32),
            ("04", "ipv6", "2001:db8::7", 6, 128),
        ],
    );
    write_claims(
        &data.join("claims.parquet"),
        &[
            (
                "13",
                "03",
                "feodo-c2",
                "directly-observed",
                "command-and-control",
            ),
            ("14", "04", "tor-exits", "provider-published", "tor-exit"),
        ],
    );
    let manifest = json!({
        "schema": "kilo.edge.snapshot.v1",
        "snapshot_id": "22".repeat(32),
        "created_at": now(),
        "sources": [
            {"id":"feodo-c2","sha256":"cc".repeat(32)},
            {"id":"tor-exits","sha256":"dd".repeat(32)}
        ]
    });
    fs::write(
        data.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    package(
        root.path(),
        "edge",
        &output.join("kilocheck-data-edge.tar.gz"),
    );
    checksum(&output.join("kilocheck-data-edge.tar.gz"));
}

fn write_indicators(path: &Path, rows: &[(&str, &str, &str, u8, u8)]) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("indicator_id", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("canonical_value", DataType::Utf8, false),
        Field::new("ip_version", DataType::UInt8, true),
        Field::new("prefix_length", DataType::UInt8, true),
    ]));
    let arrays: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.0.repeat(32)),
        )),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|row| row.1))),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|row| row.2))),
        Arc::new(UInt8Array::from_iter_values(rows.iter().map(|row| row.3))),
        Arc::new(UInt8Array::from_iter_values(rows.iter().map(|row| row.4))),
    ];
    write_batch(path, schema, arrays);
}

fn write_claims(path: &Path, rows: &[(&str, &str, &str, &str, &str)]) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("claim_id", DataType::Utf8, false),
        Field::new("indicator_id", DataType::Utf8, false),
        Field::new("source_id", DataType::Utf8, false),
        Field::new("claim_type", DataType::Utf8, false),
        Field::new("classification", DataType::Utf8, true),
        Field::new("first_seen", DataType::Utf8, true),
        Field::new("last_seen", DataType::Utf8, true),
        Field::new("confidence_band", DataType::Utf8, true),
        Field::new("source_record_index", DataType::UInt64, false),
        Field::new("attributes_json", DataType::Utf8, false),
    ]));
    let arrays: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.0.repeat(32)),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.1.repeat(32)),
        )),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|row| row.2))),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|row| row.3))),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|row| row.4))),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|_| "2026-07-13 01:02:03"),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|_| "2026-07-13"),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|_| "confirmed"),
        )),
        Arc::new(UInt64Array::from_iter_values(0..rows.len() as u64)),
        Arc::new(StringArray::from_iter_values(rows.iter().map(|_| "{}"))),
    ];
    write_batch(path, schema, arrays);
}

fn write_batch(path: &Path, schema: Arc<Schema>, arrays: Vec<ArrayRef>) {
    let mut writer =
        ArrowWriter::try_new(File::create(path).unwrap(), schema.clone(), None).unwrap();
    writer
        .write(&RecordBatch::try_new(schema, arrays).unwrap())
        .unwrap();
    writer.close().unwrap();
}

fn package(root: &Path, directory: &str, output: &Path) {
    let encoder = GzEncoder::new(File::create(output).unwrap(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    archive
        .append_dir_all(directory, root.join(directory))
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();
}

fn checksum(archive: &Path) {
    let name = archive.file_name().unwrap().to_str().unwrap();
    fs::write(
        archive.with_file_name(format!("{name}.sha256")),
        format!("{}  {name}\n", sha(archive)),
    )
    .unwrap();
}

fn sha(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).unwrap()))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
