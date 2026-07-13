use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

use arrow::array::{Array, StringArray};
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::artifact::DataManifest;
use crate::index::{CompiledClaim, decode_hash, encode, network_parts};
use crate::{DatasetError, Result};

#[derive(Debug)]
struct RawClaim {
    indicator_id: String,
    source_id: String,
    assertion: String,
    classification: String,
    first_seen: Option<String>,
    last_seen: Option<String>,
    confidence_percent: u8,
    evidence_hash: [u8; 32],
    artifact_hash: [u8; 32],
    license_id: String,
}

pub(crate) fn compile(
    base: &Path,
    base_manifest: &DataManifest,
    edge: Option<(&Path, &DataManifest)>,
) -> Result<Vec<u8>> {
    let replaced_sources = edge.map_or_else(BTreeSet::new, |(_, manifest)| {
        manifest
            .sources
            .iter()
            .map(|source| source.id.clone())
            .collect()
    });
    let mut claims = read_claims(base, base_manifest, &replaced_sources)?;
    let mut indicators = BTreeMap::new();
    let base_ids = claims
        .iter()
        .map(|claim| claim.indicator_id.clone())
        .collect::<BTreeSet<_>>();
    read_indicators(&base.join("indicators.parquet"), &base_ids, &mut indicators)?;

    if let Some((directory, manifest)) = edge {
        let edge_claims = read_claims(directory, manifest, &BTreeSet::new())?;
        let edge_ids = edge_claims
            .iter()
            .map(|claim| claim.indicator_id.clone())
            .collect::<BTreeSet<_>>();
        read_indicators(
            &directory.join("indicators.parquet"),
            &edge_ids,
            &mut indicators,
        )?;
        claims.extend(edge_claims);
    }

    let mut compiled = Vec::with_capacity(claims.len());
    for claim in claims {
        let Some(value) = indicators.get(&claim.indicator_id) else {
            return Err(DatasetError::Invalid(format!(
                "claim references missing indicator {}",
                claim.indicator_id
            )));
        };
        // ASN-only claims need route-origin correlation and are deliberately
        // omitted until that context is compiled into the runtime index.
        if !value.contains('.') && !value.contains(':') {
            continue;
        }
        let (family, prefix_length, network) = network_parts(value)?;
        compiled.push(CompiledClaim {
            family,
            prefix_length,
            network,
            source_id: claim.source_id,
            classification: claim.classification,
            assertion: claim.assertion,
            confidence_percent: claim.confidence_percent,
            first_seen: claim.first_seen,
            last_seen: claim.last_seen,
            evidence_hash: claim.evidence_hash,
            artifact_hash: claim.artifact_hash,
            license_id: claim.license_id,
        });
    }
    if compiled.is_empty() {
        return Err(DatasetError::Invalid(
            "dataset compiled to zero IP-addressable claims".into(),
        ));
    }
    encode(compiled)
}

fn read_claims(
    directory: &Path,
    manifest: &DataManifest,
    skipped_sources: &BTreeSet<String>,
) -> Result<Vec<RawClaim>> {
    let source_hashes = manifest
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let path = directory.join("claims.parquet");
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?
        .with_batch_size(8192)
        .build()?;
    let mut output = Vec::new();
    let mut seen_claims = BTreeSet::new();
    for batch in reader {
        let batch = batch?;
        let claim_ids = strings(&batch, "claim_id")?;
        let indicator_ids = strings(&batch, "indicator_id")?;
        let sources = strings(&batch, "source_id")?;
        let assertions = strings(&batch, "claim_type")?;
        let classifications = strings(&batch, "classification")?;
        let first_seen = strings(&batch, "first_seen")?;
        let last_seen = strings(&batch, "last_seen")?;
        let confidence = strings(&batch, "confidence_band")?;
        for row in 0..batch.num_rows() {
            let claim_id = required(claim_ids, row, "claim_id")?;
            if !seen_claims.insert(claim_id.to_owned()) {
                return Err(DatasetError::Invalid(format!(
                    "duplicate claim_id {claim_id:?} in {}",
                    path.display()
                )));
            }
            let source = required(sources, row, "source_id")?;
            if skipped_sources.contains(source) {
                continue;
            }
            let artifact_hash = source_hashes.get(source).ok_or_else(|| {
                DatasetError::Invalid(format!("claim source {source:?} is absent from manifest"))
            })?;
            output.push(RawClaim {
                indicator_id: required(indicator_ids, row, "indicator_id")?.to_owned(),
                source_id: source.to_owned(),
                assertion: required(assertions, row, "claim_type")?.to_owned(),
                classification: optional(classifications, row)
                    .unwrap_or("unknown-abuse")
                    .to_owned(),
                first_seen: normalize_timestamp(optional(first_seen, row))?,
                last_seen: normalize_timestamp(optional(last_seen, row))?,
                confidence_percent: confidence_percent(optional(confidence, row)),
                evidence_hash: decode_hash(claim_id, "claim_id")?,
                artifact_hash: decode_hash(artifact_hash, "source artifact hash")?,
                license_id: license_for(source).to_owned(),
            });
        }
    }
    Ok(output)
}

fn read_indicators(
    path: &Path,
    wanted: &BTreeSet<String>,
    output: &mut BTreeMap<String, String>,
) -> Result<()> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
        .with_batch_size(16_384)
        .build()?;
    for batch in reader {
        let batch = batch?;
        let ids = strings(&batch, "indicator_id")?;
        let values = strings(&batch, "canonical_value")?;
        for row in 0..batch.num_rows() {
            let id = required(ids, row, "indicator_id")?;
            if wanted.contains(id) {
                let value = required(values, row, "canonical_value")?;
                if let Some(existing) = output.insert(id.to_owned(), value.to_owned())
                    && existing != value
                {
                    return Err(DatasetError::Invalid(format!(
                        "indicator_id {id:?} maps to conflicting values {existing:?} and {value:?}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn strings<'a>(batch: &'a arrow::record_batch::RecordBatch, name: &str) -> Result<&'a StringArray> {
    batch
        .column_by_name(name)
        .ok_or_else(|| DatasetError::Invalid(format!("missing Parquet column {name:?}")))?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| DatasetError::Invalid(format!("Parquet column {name:?} is not UTF-8")))
}

fn required<'a>(array: &'a StringArray, row: usize, field: &str) -> Result<&'a str> {
    optional(array, row)
        .ok_or_else(|| DatasetError::Invalid(format!("required Parquet field {field:?} is null")))
}

fn optional(array: &StringArray, row: usize) -> Option<&str> {
    array.is_valid(row).then(|| array.value(row))
}

fn confidence_percent(value: Option<&str>) -> u8 {
    match value {
        Some("confirmed") => 99,
        Some("high") => 90,
        Some("medium") => 70,
        Some("low") => 45,
        _ => 60,
    }
}

fn license_for(source: &str) -> &'static str {
    if source.starts_with("feodo-") {
        "CC0-1.0"
    } else if source.starts_with("spamhaus-") {
        "LicenseRef-Spamhaus-DROP"
    } else if source == "tor-exits" {
        "LicenseRef-Tor-Exit-List"
    } else {
        "NOASSERTION"
    }
}

fn normalize_timestamp(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(Some(parsed.to_rfc3339_opts(SecondsFormat::Secs, true)));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return Ok(Some(
            parsed.and_utc().to_rfc3339_opts(SecondsFormat::Secs, true),
        ));
    }
    if let Ok(parsed) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Ok(Some(
            parsed
                .and_hms_opt(0, 0, 0)
                .expect("midnight is valid")
                .and_utc()
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        ));
    }
    Err(DatasetError::Invalid(format!(
        "unsupported observation timestamp {value:?}"
    )))
}
