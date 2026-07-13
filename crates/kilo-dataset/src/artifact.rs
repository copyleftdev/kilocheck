use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};

use crate::compiler;
use crate::{ActivePointer, BASE_ARCHIVE, BASE_URL, DatasetError, EDGE_ARCHIVE, EDGE_URL, Result};

const MAX_ARCHIVE_BYTES: u64 = 768 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_BASE_MAX_AGE: Duration = Duration::from_secs(72 * 60 * 60);
const DEFAULT_EDGE_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);
const DEFAULT_FUTURE_SKEW: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub struct UpdateOptions {
    pub offline_dir: Option<PathBuf>,
    pub include_edge: bool,
    pub base_url: String,
    pub edge_url: String,
    pub base_max_age: Duration,
    pub edge_max_age: Duration,
    pub future_skew: Duration,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            offline_dir: None,
            include_edge: true,
            base_url: BASE_URL.into(),
            edge_url: EDGE_URL.into(),
            base_max_age: DEFAULT_BASE_MAX_AGE,
            edge_max_age: DEFAULT_EDGE_MAX_AGE,
            future_skew: DEFAULT_FUTURE_SKEW,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateReport {
    pub snapshot_id: String,
    pub base_snapshot_id: String,
    pub edge_snapshot_id: Option<String>,
    pub records: u64,
    pub index_bytes: u64,
    pub installed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InstalledManifest {
    pub schema: String,
    pub snapshot_id: String,
    pub created_at: String,
    pub base_snapshot_id: String,
    pub edge_snapshot_id: Option<String>,
    pub index_sha256: String,
    pub records: u64,
    pub sources: Vec<String>,
}

impl InstalledManifest {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != "kilo.snapshot.v1" {
            return Err(DatasetError::Invalid(format!(
                "unsupported installed manifest schema {:?}",
                self.schema
            )));
        }
        for (field, value) in [
            ("snapshot_id", self.snapshot_id.as_str()),
            ("base_snapshot_id", self.base_snapshot_id.as_str()),
            ("index_sha256", self.index_sha256.as_str()),
        ] {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(DatasetError::Invalid(format!(
                    "installed manifest field {field:?} is not a SHA-256 value"
                )));
            }
        }
        if self.created_at.trim().is_empty() || self.records == 0 {
            return Err(DatasetError::Invalid(
                "installed manifest has an empty timestamp or zero records".into(),
            ));
        }
        Ok(())
    }

    /// Enforce the runtime freshness policy for an installed snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Stale`] when the snapshot is over age, or an
    /// integrity error when its timestamp is malformed or future-dated.
    pub fn ensure_fresh(&self) -> Result<()> {
        let max_age = if self.edge_snapshot_id.is_some() {
            DEFAULT_EDGE_MAX_AGE
        } else {
            DEFAULT_BASE_MAX_AGE
        };
        validate_freshness(
            Path::new("installed manifest"),
            &self.created_at,
            max_age,
            DEFAULT_FUTURE_SKEW,
            Utc::now(),
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DataManifest {
    pub schema: String,
    pub snapshot_id: String,
    pub created_at: String,
    #[serde(default)]
    pub sources: Vec<DataSource>,
    #[serde(default)]
    pub tables: BTreeMap<String, TableMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DataSource {
    pub id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TableMetadata {
    pub rows: u64,
    pub sha256: String,
}

/// Acquire, verify, compile, and atomically activate Kilo Data artifacts.
///
/// # Errors
///
/// Returns an error when acquisition, integrity checks, freshness checks,
/// compilation, or activation fails. The active snapshot is unchanged unless
/// the complete operation succeeds.
pub fn update(home: &Path, options: &UpdateOptions) -> Result<UpdateReport> {
    fs::create_dir_all(home)?;
    let staging_root = home.join("staging");
    fs::create_dir_all(&staging_root)?;
    let staging = Builder::new().prefix("update-").tempdir_in(&staging_root)?;
    let compiled = prepare_snapshot(staging.path(), options, Utc::now())?;

    let snapshots = home.join("snapshots");
    fs::create_dir_all(&snapshots)?;
    let snapshot_temp = Builder::new().prefix(".snapshot-").tempdir_in(&snapshots)?;
    fs::write(snapshot_temp.path().join("snapshot.kilo"), &compiled.index)?;
    fs::write(
        snapshot_temp.path().join("manifest.json"),
        serde_json::to_vec_pretty(&compiled.manifest)?,
    )?;
    let final_directory = snapshots.join(&compiled.manifest.snapshot_id);
    if final_directory.is_dir() {
        drop(snapshot_temp);
    } else {
        fs::rename(snapshot_temp.keep(), &final_directory)?;
    }
    activate(home, &compiled.manifest.snapshot_id)?;
    Ok(UpdateReport {
        snapshot_id: compiled.manifest.snapshot_id,
        base_snapshot_id: compiled.manifest.base_snapshot_id,
        edge_snapshot_id: compiled.manifest.edge_snapshot_id,
        records: compiled.manifest.records,
        index_bytes: u64::try_from(compiled.index.len())
            .map_err(|_| DatasetError::Invalid("compiled index is too large".into()))?,
        installed_at: compiled.manifest.created_at,
    })
}

struct BuiltSnapshot {
    manifest: InstalledManifest,
    index: Vec<u8>,
}

fn prepare_snapshot(
    staging: &Path,
    options: &UpdateOptions,
    now: DateTime<Utc>,
) -> Result<BuiltSnapshot> {
    let base_archive = acquire(
        staging,
        options.offline_dir.as_deref(),
        BASE_ARCHIVE,
        &options.base_url,
    )?;
    let base_directory = staging.join("base");
    unpack(&base_archive, &base_directory)?;
    let base_data = base_directory.join("canonical");
    let base_manifest = read_data_manifest(
        &base_data.join("manifest.json"),
        "kilo.canonical.snapshot.v1",
        options.base_max_age,
        options.future_skew,
        now,
    )?;
    verify_tables(&base_data, &base_manifest)?;

    let edge = if options.include_edge {
        let archive = acquire(
            staging,
            options.offline_dir.as_deref(),
            EDGE_ARCHIVE,
            &options.edge_url,
        )?;
        let directory = staging.join("edge-archive");
        unpack(&archive, &directory)?;
        let data = directory.join("edge");
        let manifest = read_data_manifest(
            &data.join("manifest.json"),
            "kilo.edge.snapshot.v1",
            options.edge_max_age,
            options.future_skew,
            now,
        )?;
        verify_required_tables(&data)?;
        Some((data, manifest))
    } else {
        None
    };

    let index = compiler::compile(
        &base_data,
        &base_manifest,
        edge.as_ref()
            .map(|(path, manifest)| (path.as_path(), manifest)),
    )?;
    let index_sha256 = hex::encode(Sha256::digest(&index));
    let snapshot_id = combined_snapshot_id(
        &base_manifest.snapshot_id,
        edge.as_ref()
            .map(|(_, manifest)| manifest.snapshot_id.as_str()),
        &index_sha256,
    );
    let records = index_record_count(&index)?;
    let created_at = edge.as_ref().map_or_else(
        || base_manifest.created_at.clone(),
        |(_, manifest)| {
            std::cmp::max(
                base_manifest.created_at.clone(),
                manifest.created_at.clone(),
            )
        },
    );
    let mut sources = base_manifest
        .sources
        .iter()
        .map(|source| source.id.clone())
        .collect::<Vec<_>>();
    if let Some((_, manifest)) = &edge {
        sources.extend(manifest.sources.iter().map(|source| source.id.clone()));
    }
    sources.sort();
    sources.dedup();
    let manifest = InstalledManifest {
        schema: "kilo.snapshot.v1".into(),
        snapshot_id: snapshot_id.clone(),
        created_at: created_at.clone(),
        base_snapshot_id: base_manifest.snapshot_id.clone(),
        edge_snapshot_id: edge
            .as_ref()
            .map(|(_, manifest)| manifest.snapshot_id.clone()),
        index_sha256,
        records,
        sources,
    };
    manifest.validate()?;
    Ok(BuiltSnapshot { manifest, index })
}

fn acquire(
    staging: &Path,
    offline_dir: Option<&Path>,
    filename: &str,
    url: &str,
) -> Result<PathBuf> {
    let archive = staging.join(filename);
    let checksum_name = format!("{filename}.sha256");
    let checksum = staging.join(&checksum_name);
    if let Some(directory) = offline_dir {
        fs::copy(directory.join(filename), &archive).map_err(|error| {
            DatasetError::Invalid(format!(
                "cannot copy offline archive {}: {error}",
                directory.join(filename).display()
            ))
        })?;
        fs::copy(directory.join(&checksum_name), &checksum).map_err(|error| {
            DatasetError::Invalid(format!(
                "cannot copy offline checksum {}: {error}",
                directory.join(&checksum_name).display()
            ))
        })?;
    } else {
        download(url, &archive)?;
        download(&format!("{url}.sha256"), &checksum)?;
    }
    verify_archive_checksum(&archive, &checksum, filename)?;
    Ok(archive)
}

fn download(url: &str, destination: &Path) -> Result<()> {
    let response = ureq::get(url)
        .header(
            "User-Agent",
            "KiloCheck/0.2 (+https://github.com/copyleftdev/kilocheck)",
        )
        .call()
        .map_err(|error| DatasetError::Http(format!("{url}: {error}")))?;
    if response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
    {
        return Err(DatasetError::Invalid(format!(
            "download at {url} exceeds the archive size limit"
        )));
    }
    let mut reader = response
        .into_body()
        .into_reader()
        .take(MAX_ARCHIVE_BYTES + 1);
    let mut output = File::create(destination)?;
    let copied = io::copy(&mut reader, &mut output)?;
    if copied > MAX_ARCHIVE_BYTES {
        return Err(DatasetError::Invalid(format!(
            "download at {url} exceeds the archive size limit"
        )));
    }
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn verify_archive_checksum(archive: &Path, checksum: &Path, filename: &str) -> Result<()> {
    let text = fs::read_to_string(checksum)?;
    let mut fields = text.split_whitespace();
    let expected = fields
        .next()
        .ok_or_else(|| DatasetError::Invalid("checksum file is empty".into()))?;
    let named = fields
        .next()
        .ok_or_else(|| DatasetError::Invalid("checksum file has no filename".into()))?
        .trim_start_matches('*');
    if fields.next().is_some() || named != filename {
        return Err(DatasetError::Invalid(format!(
            "checksum file must name exactly {filename:?}"
        )));
    }
    let actual = sha256_file(archive)?;
    if expected != actual {
        return Err(DatasetError::Invalid(format!(
            "archive checksum mismatch for {filename}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn unpack(archive_path: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let decoder = GzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut unpacked = 0_u64;
    let mut files = 0_u32;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(DatasetError::Invalid(format!(
                "archive contains unsafe path {}",
                path.display()
            )));
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(DatasetError::Invalid(format!(
                "archive contains unsupported entry {}",
                path.display()
            )));
        }
        unpacked = unpacked
            .checked_add(entry.size())
            .ok_or_else(|| DatasetError::Invalid("archive size overflow".into()))?;
        if unpacked > MAX_UNPACKED_BYTES {
            return Err(DatasetError::Invalid(
                "archive exceeds the unpacked size limit".into(),
            ));
        }
        files += u32::from(kind.is_file());
        if files > 64 {
            return Err(DatasetError::Invalid(
                "archive contains too many files".into(),
            ));
        }
        if !entry.unpack_in(destination)? {
            return Err(DatasetError::Invalid(format!(
                "archive entry escaped destination: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_data_manifest(
    path: &Path,
    expected_schema: &str,
    max_age: Duration,
    future_skew: Duration,
    now: DateTime<Utc>,
) -> Result<DataManifest> {
    let manifest: DataManifest = serde_json::from_slice(&fs::read(path)?)?;
    if manifest.schema != expected_schema
        || manifest.snapshot_id.len() != 64
        || !manifest
            .snapshot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || manifest.created_at.trim().is_empty()
        || manifest.sources.is_empty()
    {
        return Err(DatasetError::Invalid(format!(
            "invalid data manifest at {}",
            path.display()
        )));
    }
    for source in &manifest.sources {
        if source.id.trim().is_empty()
            || source.sha256.len() != 64
            || !source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DatasetError::Invalid(format!(
                "invalid source identity in {}",
                path.display()
            )));
        }
    }
    validate_freshness(path, &manifest.created_at, max_age, future_skew, now)?;
    Ok(manifest)
}

fn validate_freshness(
    path: &Path,
    created_at: &str,
    max_age: Duration,
    future_skew: Duration,
    now: DateTime<Utc>,
) -> Result<()> {
    let created_at = DateTime::parse_from_rfc3339(created_at)
        .map_err(|error| {
            DatasetError::Invalid(format!(
                "manifest timestamp at {} is not RFC 3339: {error}",
                path.display()
            ))
        })?
        .with_timezone(&Utc);
    let age = now.signed_duration_since(created_at);
    let max_future = chrono::Duration::from_std(future_skew)
        .map_err(|_| DatasetError::Invalid("future-skew limit is too large".into()))?;
    if age < -max_future {
        return Err(DatasetError::Invalid(format!(
            "manifest at {} is future-dated ({created_at})",
            path.display()
        )));
    }
    let max_age = chrono::Duration::from_std(max_age)
        .map_err(|_| DatasetError::Invalid("freshness limit is too large".into()))?;
    if age > max_age {
        return Err(DatasetError::Stale(format!(
            "manifest at {} was created at {created_at}; maximum age is {} seconds",
            path.display(),
            max_age.num_seconds()
        )));
    }
    Ok(())
}

fn verify_tables(directory: &Path, manifest: &DataManifest) -> Result<()> {
    verify_required_tables(directory)?;
    if manifest.tables.is_empty() {
        return Err(DatasetError::Invalid(
            "base manifest contains no table hashes".into(),
        ));
    }
    for (name, metadata) in &manifest.tables {
        if metadata.rows == 0
            || metadata.sha256.len() != 64
            || !metadata.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DatasetError::Invalid(format!(
                "invalid table metadata for {name:?}"
            )));
        }
        let path = directory.join(format!("{name}.parquet"));
        let actual = sha256_file(&path)?;
        if actual != metadata.sha256 {
            return Err(DatasetError::Invalid(format!(
                "table hash mismatch for {}: expected {}, got {actual}",
                path.display(),
                metadata.sha256
            )));
        }
    }
    Ok(())
}

fn verify_required_tables(directory: &Path) -> Result<()> {
    for name in ["claims.parquet", "indicators.parquet"] {
        let path = directory.join(name);
        if !path.is_file() || fs::metadata(&path)?.len() == 0 {
            return Err(DatasetError::Invalid(format!(
                "required dataset table is missing or empty: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn combined_snapshot_id(base: &str, edge: Option<&str>, index: &str) -> String {
    let mut digest = Sha256::new();
    for value in [Some(base), edge, Some(index)].into_iter().flatten() {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())
}

fn index_record_count(index: &[u8]) -> Result<u64> {
    let bytes = index
        .get(16..24)
        .ok_or_else(|| DatasetError::Invalid("compiled index header is truncated".into()))?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("eight-byte slice"),
    ))
}

fn activate(home: &Path, snapshot_id: &str) -> Result<()> {
    let pointer = ActivePointer {
        schema: "kilo.active.v1".into(),
        snapshot_id: snapshot_id.into(),
    };
    let directory = home.join("activations");
    fs::create_dir_all(&directory)?;
    loop {
        let next = fs::read_dir(&directory)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_suffix(".json")?
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| DatasetError::Invalid("activation sequence exhausted".into()))?;
        let path = directory.join(format!("{next:020}.json"));
        let mut temporary = NamedTempFile::new_in(&directory)?;
        temporary.write_all(&serde_json::to_vec_pretty(&pointer)?)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(path) {
            Ok(_) => return Ok(()),
            Err(error) => {
                if error.error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(DatasetError::Io(error.error));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn instant(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 13, hour, 0, 0)
            .single()
            .unwrap()
    }

    #[test]
    fn freshness_accepts_exact_boundaries() {
        let path = Path::new("manifest.json");
        validate_freshness(
            path,
            "2026-07-13T06:00:00Z",
            Duration::from_secs(2 * 60 * 60),
            Duration::from_secs(15 * 60),
            instant(8),
        )
        .unwrap();
        validate_freshness(
            path,
            "2026-07-13T08:15:00Z",
            Duration::from_secs(2 * 60 * 60),
            Duration::from_secs(15 * 60),
            instant(8),
        )
        .unwrap();
    }

    #[test]
    fn freshness_distinguishes_stale_future_and_malformed() {
        let path = Path::new("manifest.json");
        let stale = validate_freshness(
            path,
            "2026-07-13T05:59:59Z",
            Duration::from_secs(2 * 60 * 60),
            Duration::from_secs(15 * 60),
            instant(8),
        )
        .unwrap_err();
        assert!(matches!(stale, DatasetError::Stale(_)));

        let future = validate_freshness(
            path,
            "2026-07-13T08:15:01Z",
            Duration::from_secs(2 * 60 * 60),
            Duration::from_secs(15 * 60),
            instant(8),
        )
        .unwrap_err();
        assert!(future.to_string().contains("future-dated"));

        let malformed = validate_freshness(
            path,
            "July 13",
            Duration::from_secs(2 * 60 * 60),
            Duration::from_secs(15 * 60),
            instant(8),
        )
        .unwrap_err();
        assert!(malformed.to_string().contains("RFC 3339"));
    }

    #[test]
    fn installed_snapshot_rechecks_freshness_at_query_time() {
        let manifest = InstalledManifest {
            schema: "kilo.snapshot.v1".into(),
            snapshot_id: "11".repeat(32),
            created_at: "2020-01-01T00:00:00Z".into(),
            base_snapshot_id: "22".repeat(32),
            edge_snapshot_id: Some("33".repeat(32)),
            index_sha256: "44".repeat(32),
            records: 1,
            sources: vec!["fixture".into()],
        };
        assert!(matches!(
            manifest.ensure_fresh(),
            Err(DatasetError::Stale(_))
        ));

        let future = InstalledManifest {
            created_at: "2999-01-01T00:00:00Z".into(),
            ..manifest
        };
        assert!(
            future
                .ensure_fresh()
                .unwrap_err()
                .to_string()
                .contains("future-dated")
        );
    }

    #[test]
    fn activation_records_are_atomic_and_sequence_concurrent_updates() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().to_owned();
        let workers = (1_u8..=8)
            .map(|value| {
                let path = path.clone();
                std::thread::spawn(move || activate(&path, &format!("{value:02x}").repeat(32)))
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let records = fs::read_dir(home.path().join("activations"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json")
            })
            .count();
        assert_eq!(records, 8);
        let active = crate::active_snapshot_dir(home.path())
            .unwrap()
            .expect("latest activation exists");
        assert!((1_u8..=8).any(|value| active.ends_with(format!("{value:02x}").repeat(32))));
    }

    #[test]
    fn unpack_rejects_links() {
        let temporary = tempfile::tempdir().unwrap();
        let archive_path = temporary.path().join("link.tar.gz");
        let encoder = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_path("canonical/link").unwrap();
        header.set_link_name("/tmp/escape").unwrap();
        header.set_cksum();
        archive.append(&header, io::empty()).unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        let error = unpack(&archive_path, &temporary.path().join("out")).unwrap_err();
        assert!(error.to_string().contains("unsupported entry"));
    }

    #[test]
    fn unpack_rejects_parent_traversal_without_writing_outside() {
        let temporary = tempfile::tempdir().unwrap();
        let archive_path = temporary.path().join("traversal.tar.gz");
        let encoder = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(1);
        header.set_mode(0o644);
        header.as_mut_bytes()[..9].copy_from_slice(b"../escape");
        header.set_cksum();
        archive.append(&header, &b"x"[..]).unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        let outside = temporary.path().join("escape");
        let error = unpack(&archive_path, &temporary.path().join("out")).unwrap_err();
        assert!(error.to_string().contains("unsafe path"));
        assert!(!outside.exists());
    }
}
