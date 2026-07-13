use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{DatasetError, InstalledManifest, Result};

const MAGIC: &[u8; 8] = b"KILOIDX1";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 48;
const RECORD_SIZE: usize = 136;

#[derive(Debug, Clone, PartialEq)]
pub struct IndexObservation {
    pub source_id: String,
    pub classification: String,
    pub assertion: String,
    pub confidence: f32,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub evidence_hash: String,
    pub artifact_hash: String,
    pub license_id: String,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledClaim {
    pub family: u8,
    pub prefix_length: u8,
    pub network: [u8; 16],
    pub source_id: String,
    pub classification: String,
    pub assertion: String,
    pub confidence_percent: u8,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub evidence_hash: [u8; 32],
    pub artifact_hash: [u8; 32],
    pub license_id: String,
}

pub struct Snapshot {
    bytes: Box<[u8]>,
    pub manifest: InstalledManifest,
    record_count: usize,
    strings_offset: usize,
    strings_len: usize,
}

impl Snapshot {
    /// Open and verify a compiled snapshot directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest or index cannot be read, fails
    /// integrity validation, or uses an unsupported layout.
    pub fn open(directory: &Path) -> Result<Self> {
        let manifest_path = directory.join("manifest.json");
        let manifest: InstalledManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest.validate()?;
        let index_path = directory.join("snapshot.kilo");
        let bytes = fs::read(&index_path)?.into_boxed_slice();
        let actual_hash = hex::encode(Sha256::digest(&bytes));
        if actual_hash != manifest.index_sha256 {
            return Err(DatasetError::Invalid(format!(
                "compiled index hash mismatch: expected {}, got {actual_hash}",
                manifest.index_sha256
            )));
        }
        let (record_count, strings_offset, strings_len) = validate_layout(&bytes)?;
        if record_count as u64 != manifest.records {
            return Err(DatasetError::Invalid(format!(
                "manifest records {} do not match index records {record_count}",
                manifest.records
            )));
        }
        Ok(Self {
            bytes,
            manifest,
            record_count,
            strings_offset,
            strings_len,
        })
    }

    /// Return every locally compiled observation matching an address.
    ///
    /// # Errors
    ///
    /// Returns an error when a matching record contains a malformed string
    /// reference or invalid UTF-8.
    pub fn query(&self, address: IpAddr) -> Result<Vec<IndexObservation>> {
        let (family, address_bytes) = address_parts(address);
        let mut matches = Vec::new();
        for index in 0..self.record_count {
            let start = HEADER_SIZE + index * RECORD_SIZE;
            let record = &self.bytes[start..start + RECORD_SIZE];
            if record[0] != family || !contains(&record[4..20], &address_bytes, record[1]) {
                continue;
            }
            matches.push(IndexObservation {
                source_id: self.string(record, 20)?,
                classification: self.string(record, 28)?,
                assertion: self.string(record, 36)?,
                confidence: f32::from(record[2]) / 100.0,
                first_seen: self.optional_string(record, 44)?,
                last_seen: self.optional_string(record, 52)?,
                evidence_hash: hex::encode(&record[60..92]),
                artifact_hash: hex::encode(&record[92..124]),
                license_id: self.string(record, 124)?,
                prefix_length: record[1],
            });
        }
        matches.sort_by(|left, right| {
            right
                .prefix_length
                .cmp(&left.prefix_length)
                .then_with(|| left.source_id.cmp(&right.source_id))
                .then_with(|| left.evidence_hash.cmp(&right.evidence_hash))
        });
        Ok(matches)
    }

    fn string(&self, record: &[u8], at: usize) -> Result<String> {
        let offset = read_u32(record, at)? as usize;
        let length = read_u32(record, at + 4)? as usize;
        if offset > self.strings_len || length > self.strings_len.saturating_sub(offset) {
            return Err(DatasetError::Invalid(
                "index string reference is out of bounds".into(),
            ));
        }
        let start = self.strings_offset + offset;
        let value = std::str::from_utf8(&self.bytes[start..start + length])
            .map_err(|_| DatasetError::Invalid("index string is not valid UTF-8".into()))?;
        Ok(value.to_owned())
    }

    fn optional_string(&self, record: &[u8], at: usize) -> Result<Option<String>> {
        if read_u32(record, at + 4)? == 0 {
            Ok(None)
        } else {
            self.string(record, at).map(Some)
        }
    }
}

pub(crate) fn encode(mut claims: Vec<CompiledClaim>) -> Result<Vec<u8>> {
    claims.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.network.cmp(&right.network))
            .then_with(|| right.prefix_length.cmp(&left.prefix_length))
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| left.evidence_hash.cmp(&right.evidence_hash))
    });
    claims.dedup_by(|left, right| left.evidence_hash == right.evidence_hash);

    let record_bytes = claims
        .len()
        .checked_mul(RECORD_SIZE)
        .ok_or_else(|| DatasetError::Invalid("too many index records".into()))?;
    let strings_offset = HEADER_SIZE
        .checked_add(record_bytes)
        .ok_or_else(|| DatasetError::Invalid("index is too large".into()))?;
    let mut output = vec![0_u8; strings_offset];
    output[..8].copy_from_slice(MAGIC);
    write_u32(&mut output, 8, VERSION);
    write_u32(&mut output, 12, 136);
    write_u64(&mut output, 16, claims.len() as u64);
    write_u64(&mut output, 24, strings_offset as u64);

    let mut pool = StringPool::default();
    for (index, claim) in claims.iter().enumerate() {
        let start = HEADER_SIZE + index * RECORD_SIZE;
        let record = &mut output[start..start + RECORD_SIZE];
        record[0] = claim.family;
        record[1] = claim.prefix_length;
        record[2] = claim.confidence_percent;
        record[4..20].copy_from_slice(&claim.network);
        write_ref(record, 20, pool.intern(&claim.source_id)?)?;
        write_ref(record, 28, pool.intern(&claim.classification)?)?;
        write_ref(record, 36, pool.intern(&claim.assertion)?)?;
        write_ref(
            record,
            44,
            pool.intern_optional(claim.first_seen.as_deref())?,
        )?;
        write_ref(
            record,
            52,
            pool.intern_optional(claim.last_seen.as_deref())?,
        )?;
        record[60..92].copy_from_slice(&claim.evidence_hash);
        record[92..124].copy_from_slice(&claim.artifact_hash);
        write_ref(record, 124, pool.intern(&claim.license_id)?)?;
    }
    write_u64(&mut output, 32, pool.bytes.len() as u64);
    output.extend_from_slice(&pool.bytes);
    validate_layout(&output)?;
    Ok(output)
}

fn validate_layout(bytes: &[u8]) -> Result<(usize, usize, usize)> {
    if bytes.len() < HEADER_SIZE || &bytes[..8] != MAGIC {
        return Err(DatasetError::Invalid(
            "compiled index has an invalid magic header".into(),
        ));
    }
    if read_u32(bytes, 8)? != VERSION || read_u32(bytes, 12)? as usize != RECORD_SIZE {
        return Err(DatasetError::Invalid(
            "compiled index version is unsupported".into(),
        ));
    }
    let records = usize::try_from(read_u64(bytes, 16)?)
        .map_err(|_| DatasetError::Invalid("index record count is too large".into()))?;
    let strings_offset = usize::try_from(read_u64(bytes, 24)?)
        .map_err(|_| DatasetError::Invalid("index string offset is too large".into()))?;
    let strings_len = usize::try_from(read_u64(bytes, 32)?)
        .map_err(|_| DatasetError::Invalid("index string length is too large".into()))?;
    let expected_offset =
        HEADER_SIZE
            .checked_add(records.checked_mul(RECORD_SIZE).ok_or_else(|| {
                DatasetError::Invalid("compiled index record area overflows".into())
            })?)
            .ok_or_else(|| DatasetError::Invalid("compiled index layout overflows".into()))?;
    if strings_offset != expected_offset
        || strings_len != bytes.len().saturating_sub(strings_offset)
    {
        return Err(DatasetError::Invalid(
            "compiled index layout is inconsistent".into(),
        ));
    }
    Ok((records, strings_offset, strings_len))
}

#[derive(Default)]
struct StringPool {
    offsets: BTreeMap<String, (u32, u32)>,
    bytes: Vec<u8>,
}

impl StringPool {
    fn intern(&mut self, value: &str) -> Result<(u32, u32)> {
        if let Some(reference) = self.offsets.get(value) {
            return Ok(*reference);
        }
        let offset = u32::try_from(self.bytes.len())
            .map_err(|_| DatasetError::Invalid("index string pool is too large".into()))?;
        let length = u32::try_from(value.len())
            .map_err(|_| DatasetError::Invalid("index string is too large".into()))?;
        self.bytes.extend_from_slice(value.as_bytes());
        self.offsets.insert(value.to_owned(), (offset, length));
        Ok((offset, length))
    }

    fn intern_optional(&mut self, value: Option<&str>) -> Result<(u32, u32)> {
        value.map_or(Ok((0, 0)), |value| self.intern(value))
    }
}

fn address_parts(address: IpAddr) -> (u8, [u8; 16]) {
    let mut bytes = [0_u8; 16];
    match address {
        IpAddr::V4(value) => {
            bytes[..4].copy_from_slice(&value.octets());
            (4, bytes)
        }
        IpAddr::V6(value) => (6, value.octets()),
    }
}

pub(crate) fn network_parts(value: &str) -> Result<(u8, u8, [u8; 16])> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let address: IpAddr = address.parse().map_err(|error| {
        DatasetError::Invalid(format!("invalid canonical indicator {value:?}: {error}"))
    })?;
    let (family, mut bytes) = address_parts(address);
    let default_prefix = if family == 4 { 32 } else { 128 };
    let prefix = prefix.map_or(Ok(default_prefix), |prefix| {
        prefix.parse::<u8>().map_err(|error| {
            DatasetError::Invalid(format!("invalid prefix length in {value:?}: {error}"))
        })
    })?;
    if prefix > default_prefix {
        return Err(DatasetError::Invalid(format!(
            "invalid prefix length in {value:?}"
        )));
    }
    mask(&mut bytes, prefix);
    Ok((family, prefix, bytes))
}

fn mask(bytes: &mut [u8; 16], prefix: u8) {
    let full = usize::from(prefix / 8);
    let partial = prefix % 8;
    if partial != 0 {
        bytes[full] &= u8::MAX << (8 - partial);
    }
    let zero_from = full + usize::from(partial != 0);
    bytes[zero_from..].fill(0);
}

fn contains(network: &[u8], address: &[u8; 16], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    if network[..full] != address[..full] {
        return false;
    }
    let partial = prefix % 8;
    partial == 0 || (network[full] ^ address[full]) & (u8::MAX << (8 - partial)) == 0
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let value = bytes
        .get(at..at + 4)
        .ok_or_else(|| DatasetError::Invalid("compiled index is truncated".into()))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64> {
    let value = bytes
        .get(at..at + 8)
        .ok_or_else(|| DatasetError::Invalid("compiled index is truncated".into()))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("eight-byte slice"),
    ))
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_ref(bytes: &mut [u8], at: usize, reference: (u32, u32)) -> Result<()> {
    if at + 8 > bytes.len() {
        return Err(DatasetError::Invalid("index record layout overflow".into()));
    }
    write_u32(bytes, at, reference.0);
    write_u32(bytes, at + 4, reference.1);
    Ok(())
}

pub(crate) fn decode_hash(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|error| DatasetError::Invalid(format!("invalid {field}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| DatasetError::Invalid(format!("invalid {field}: expected 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn claim(value: &str, source: &str) -> CompiledClaim {
        let (family, prefix_length, network) = network_parts(value).expect("test network");
        CompiledClaim {
            family,
            prefix_length,
            network,
            source_id: source.into(),
            classification: "command-and-control".into(),
            assertion: "directly-observed".into(),
            confidence_percent: 99,
            first_seen: None,
            last_seen: Some("2026-07-13T00:00:00Z".into()),
            evidence_hash: [7; 32],
            artifact_hash: [8; 32],
            license_id: "CC0-1.0".into(),
        }
    }

    fn valid_empty_index() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        write_u32(&mut bytes, 8, VERSION);
        write_u32(&mut bytes, 12, 136);
        write_u64(&mut bytes, 24, HEADER_SIZE as u64);
        bytes
    }

    fn snapshot(bytes: Vec<u8>) -> Snapshot {
        let (record_count, strings_offset, strings_len) = validate_layout(&bytes).unwrap();
        Snapshot {
            bytes: bytes.into_boxed_slice(),
            manifest: InstalledManifest {
                schema: "kilo.snapshot.v1".into(),
                snapshot_id: "11".repeat(32),
                created_at: "2026-07-13T00:00:00Z".into(),
                base_snapshot_id: "22".repeat(32),
                edge_snapshot_id: None,
                index_sha256: "33".repeat(32),
                records: u64::try_from(record_count).unwrap(),
                sources: vec!["fixture".into()],
            },
            record_count,
            strings_offset,
            strings_len,
        }
    }

    #[test]
    fn prefix_membership_handles_ipv4_and_ipv6_edges() {
        let (_, _, v4) = network_parts("192.0.2.0/24").unwrap();
        assert!(contains(
            &v4,
            &address_parts("192.0.2.255".parse().unwrap()).1,
            24
        ));
        assert!(!contains(
            &v4,
            &address_parts("192.0.3.0".parse().unwrap()).1,
            24
        ));
        let (_, _, v6) = network_parts("2001:db8::/32").unwrap();
        assert!(contains(
            &v6,
            &address_parts("2001:db8::1".parse().unwrap()).1,
            32
        ));
        assert!(!contains(
            &v6,
            &address_parts("2001:db9::1".parse().unwrap()).1,
            32
        ));
    }

    #[test]
    fn deterministic_encoding_deduplicates_claim_hashes() {
        let first = encode(vec![
            claim("192.0.2.0/24", "source-b"),
            claim("192.0.2.0/24", "source-a"),
        ])
        .unwrap();
        let second = encode(vec![
            claim("192.0.2.0/24", "source-a"),
            claim("192.0.2.0/24", "source-b"),
        ])
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(validate_layout(&first).unwrap().0, 1);
    }

    #[test]
    fn malformed_layouts_fail_without_panicking() {
        for bytes in [Vec::new(), b"KILOIDX1".to_vec(), vec![0; HEADER_SIZE]] {
            assert!(validate_layout(&bytes).is_err());
        }
        let valid = valid_empty_index();
        assert_eq!(validate_layout(&valid).unwrap(), (0, HEADER_SIZE, 0));

        let mut wrong_version = valid.clone();
        write_u32(&mut wrong_version, 8, VERSION + 1);
        assert!(validate_layout(&wrong_version).is_err());
        let mut wrong_record_size = valid.clone();
        write_u32(&mut wrong_record_size, 12, 135);
        assert!(validate_layout(&wrong_record_size).is_err());
        let mut wrong_offset = valid.clone();
        write_u64(&mut wrong_offset, 24, (HEADER_SIZE + 1) as u64);
        assert!(validate_layout(&wrong_offset).is_err());
        let mut wrong_string_length = valid;
        write_u64(&mut wrong_string_length, 32, 1);
        assert!(validate_layout(&wrong_string_length).is_err());
    }

    #[test]
    fn encoded_observation_round_trips_confidence_and_optional_times() {
        let mut input = claim("192.0.2.7", "source-a");
        input.confidence_percent = 50;
        input.first_seen = Some("2026-07-12T23:00:00Z".into());
        input.last_seen = None;
        let snapshot = snapshot(encode(vec![input]).unwrap());
        let observations = snapshot.query("192.0.2.7".parse().unwrap()).unwrap();
        assert!((observations[0].confidence - 0.5).abs() < f32::EPSILON);
        assert_eq!(
            observations[0].first_seen.as_deref(),
            Some("2026-07-12T23:00:00Z")
        );
        assert_eq!(observations[0].last_seen, None);
    }

    #[test]
    fn string_references_enforce_each_bounds_edge() {
        let snapshot = snapshot(encode(vec![claim("192.0.2.7", "source-a")]).unwrap());
        let mut record = snapshot.bytes[HEADER_SIZE..HEADER_SIZE + RECORD_SIZE].to_vec();
        write_u32(
            &mut record,
            20,
            u32::try_from(snapshot.strings_len).unwrap(),
        );
        write_u32(&mut record, 24, 0);
        assert_eq!(snapshot.string(&record, 20).unwrap(), "");

        write_u32(
            &mut record,
            20,
            u32::try_from(snapshot.strings_len + 1).unwrap(),
        );
        assert!(snapshot.string(&record, 20).is_err());
        write_u32(&mut record, 20, 0);
        write_u32(
            &mut record,
            24,
            u32::try_from(snapshot.strings_len + 1).unwrap(),
        );
        assert!(snapshot.string(&record, 20).is_err());
    }

    #[test]
    fn optional_pool_and_reference_boundaries_are_exact() {
        let mut pool = StringPool::default();
        assert_eq!(pool.intern_optional(None).unwrap(), (0, 0));
        assert_eq!(pool.intern_optional(Some("time")).unwrap(), (0, 4));
        assert_eq!(pool.bytes, b"time");

        let mut exact = [0_u8; 8];
        write_ref(&mut exact, 0, (7, 9)).unwrap();
        assert_eq!(read_u32(&exact, 0).unwrap(), 7);
        assert_eq!(read_u32(&exact, 4).unwrap(), 9);
        assert!(write_ref(&mut [0; 7], 0, (0, 0)).is_err());
        assert!(write_ref(&mut [0; 8], 1, (0, 0)).is_err());
    }

    #[test]
    fn network_parts_assign_family_defaults_and_clear_host_bits() {
        let (family, prefix, _) = network_parts("192.0.2.1").unwrap();
        assert_eq!((family, prefix), (4, 32));
        let (family, prefix, _) = network_parts("2001:db8::1").unwrap();
        assert_eq!((family, prefix), (6, 128));

        let mut bytes = [u8::MAX; 16];
        mask(&mut bytes, 9);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[1], 0x80);
        assert!(bytes[2..].iter().all(|byte| *byte == 0));
        let (_, _, canonical) = network_parts("192.0.2.255/25").unwrap();
        assert_eq!(&canonical[..4], &[192, 0, 2, 128]);
        assert!(canonical[4..].iter().all(|byte| *byte == 0));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_048))]

        #[test]
        fn prefix_membership_matches_bitwise_definition(
            raw_network in any::<[u8; 16]>(),
            address in any::<[u8; 16]>(),
            prefix in 0_u8..=128,
        ) {
            let mut network = raw_network;
            mask(&mut network, prefix);
            let differing = network
                .iter()
                .zip(address)
                .fold(0_u128, |value, (left, right)| (value << 8) | u128::from(*left ^ right));
            let expected = prefix == 0 || differing >> (128 - u32::from(prefix)) == 0;
            prop_assert_eq!(contains(&network, &address, prefix), expected);
        }

        #[test]
        fn arbitrary_index_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = validate_layout(&bytes);
        }
    }
}
