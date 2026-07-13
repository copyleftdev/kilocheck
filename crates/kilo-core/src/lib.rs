//! Stable domain contracts shared by `KiloCheck` frontends and engines.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const COMMAND_SCHEMA: &str = "kilo.command.v1";
pub const OBSERVATION_SCHEMA: &str = "kilo.observation.v1";
pub const CAPABILITIES_SCHEMA: &str = "kilo.capabilities.v1";
pub const STATUS_SCHEMA: &str = "kilo.status.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandEnvelope<T> {
    pub schema: &'static str,
    pub command: &'static str,
    pub ok: bool,
    pub partial: bool,
    pub snapshot_id: Option<String>,
    pub data: Option<T>,
    pub warnings: Vec<Diagnostic>,
    pub errors: Vec<Diagnostic>,
    pub metrics: Metrics,
}

impl<T> CommandEnvelope<T> {
    #[must_use]
    pub fn success(command: &'static str, data: T, elapsed_us: u64) -> Self {
        Self {
            schema: COMMAND_SCHEMA,
            command,
            ok: true,
            partial: false,
            snapshot_id: None,
            data: Some(data),
            warnings: Vec::new(),
            errors: Vec::new(),
            metrics: Metrics { elapsed_us },
        }
    }

    #[must_use]
    pub fn failure(command: &'static str, error: Diagnostic, elapsed_us: u64) -> Self {
        Self {
            schema: COMMAND_SCHEMA,
            command,
            ok: false,
            partial: false,
            snapshot_id: None,
            data: None,
            warnings: Vec::new(),
            errors: vec![error],
            metrics: Metrics { elapsed_us },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Metrics {
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub value: String,
    pub version: u8,
}

impl From<IpAddr> for Target {
    fn from(address: IpAddr) -> Self {
        let version = if address.is_ipv4() { 4 } else { 6 };
        Self {
            kind: "ip",
            value: address.to_string(),
            version,
        }
    }
}

impl FromStr for Target {
    type Err = AddrParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<IpAddr>().map(Self::from)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Clean,
    Unknown,
    Observed,
    Suspicious,
    Dangerous,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendedAction {
    Allow,
    Log,
    Monitor,
    Challenge,
    RateLimit,
    Block,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub disposition: Disposition,
    pub confidence: f32,
    pub recommended_action: RecommendedAction,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckResult {
    pub schema: &'static str,
    pub target: Target,
    pub verdict: Verdict,
    pub observations: Vec<Observation>,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Observation {
    pub source_id: String,
    pub classification: String,
    pub assertion: String,
    pub confidence: f32,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub evidence_hash: String,
    pub independence_group: String,
}

/// Count distinct underlying evidence origins rather than raw feed rows.
#[must_use]
pub fn independent_group_count(observations: &[Observation]) -> usize {
    observations
        .iter()
        .map(|observation| observation.independence_group.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub source_id: String,
    pub artifact_hash: String,
    pub license_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub schema: &'static str,
    pub offline_checks: bool,
    pub deterministic: bool,
    pub commands: Vec<CommandCapability>,
    pub output_schemas: Vec<&'static str>,
    pub exit_codes: Vec<ExitCodeCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandCapability {
    pub name: &'static str,
    pub available: bool,
    pub summary: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExitCodeCapability {
    pub code: u8,
    pub meaning: &'static str,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            schema: CAPABILITIES_SCHEMA,
            offline_checks: true,
            deterministic: true,
            commands: vec![
                CommandCapability {
                    name: "check",
                    available: true,
                    summary: "Validate and query one or more IP addresses",
                },
                CommandCapability {
                    name: "status",
                    available: true,
                    summary: "Report local dataset installation state",
                },
                CommandCapability {
                    name: "capabilities",
                    available: true,
                    summary: "Describe the machine-readable command surface",
                },
                CommandCapability {
                    name: "schema",
                    available: true,
                    summary: "Print a stable JSON Schema",
                },
                CommandCapability {
                    name: "update",
                    available: false,
                    summary: "Planned: verify, compile, and atomically install Kilo Data releases",
                },
            ],
            output_schemas: vec![COMMAND_SCHEMA, OBSERVATION_SCHEMA, STATUS_SCHEMA],
            exit_codes: vec![
                ExitCodeCapability {
                    code: 0,
                    meaning: "success without policy violation",
                },
                ExitCodeCapability {
                    code: 1,
                    meaning: "operational or integrity error",
                },
                ExitCodeCapability {
                    code: 2,
                    meaning: "invalid invocation",
                },
                ExitCodeCapability {
                    code: 3,
                    meaning: "policy gate failed",
                },
                ExitCodeCapability {
                    code: 4,
                    meaning: "dataset too stale",
                },
                ExitCodeCapability {
                    code: 5,
                    meaning: "required-source result is incomplete",
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatasetStatus {
    pub schema: &'static str,
    pub installed: bool,
    pub home: String,
    pub integrity: &'static str,
    pub snapshot: Option<SnapshotSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotSummary {
    pub id: String,
    pub created_at: String,
    pub manifest_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SnapshotManifest {
    pub schema: String,
    pub snapshot_id: String,
    pub created_at: String,
}

impl SnapshotManifest {
    /// Parse and minimally validate the identity fields needed before activation.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the input is not valid JSON or an identity
    /// field is empty.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(ManifestError::Json)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        for (field, value) in [
            ("schema", self.schema.as_str()),
            ("snapshot_id", self.snapshot_id.as_str()),
            ("created_at", self.created_at.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ManifestError::EmptyField(field));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ManifestError {
    Json(serde_json::Error),
    EmptyField(&'static str),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid snapshot manifest JSON: {error}"),
            Self::EmptyField(field) => {
                write!(formatter, "snapshot manifest field {field:?} is empty")
            }
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::EmptyField(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn target_canonicalizes_ip_addresses() {
        let target = Target::from("2001:0db8::1".parse::<IpAddr>().expect("valid fixture"));
        assert_eq!(target.value, "2001:db8::1");
        assert_eq!(target.version, 6);
    }

    #[test]
    fn failure_envelope_distinguishes_missing_data() {
        let envelope = CommandEnvelope::<CheckResult>::failure(
            "check",
            Diagnostic::new("DATASET_MISSING", "no active snapshot"),
            10,
        );
        assert!(!envelope.ok);
        assert!(envelope.data.is_none());
        assert_eq!(envelope.errors[0].code, "DATASET_MISSING");
    }

    #[test]
    fn manifest_rejects_each_empty_identity_field() {
        for (field, json) in [
            (
                "schema",
                br#"{"schema":" ","snapshot_id":"abc","created_at":"now"}"#.as_slice(),
            ),
            (
                "snapshot_id",
                br#"{"schema":"v1","snapshot_id":"","created_at":"now"}"#.as_slice(),
            ),
            (
                "created_at",
                br#"{"schema":"v1","snapshot_id":"abc","created_at":"\n"}"#.as_slice(),
            ),
        ] {
            let error = SnapshotManifest::parse_json(json).expect_err("empty field must fail");
            assert!(matches!(error, ManifestError::EmptyField(actual) if actual == field));
        }
    }

    #[test]
    fn manifest_errors_preserve_diagnostic_context() {
        let json_error = SnapshotManifest::parse_json(b"not-json").expect_err("invalid JSON");
        assert!(
            json_error
                .to_string()
                .starts_with("invalid snapshot manifest JSON:")
        );
        assert!(json_error.source().is_some());

        let field_error = ManifestError::EmptyField("snapshot_id");
        assert_eq!(
            field_error.to_string(),
            "snapshot manifest field \"snapshot_id\" is empty"
        );
        assert!(field_error.source().is_none());
    }
}
