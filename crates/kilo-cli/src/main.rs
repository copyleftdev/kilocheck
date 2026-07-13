use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use kilo_core::{
    Capabilities, CheckResult, CommandEnvelope, DatasetStatus, Diagnostic, OBSERVATION_SCHEMA,
    Observation, Provenance, STATUS_SCHEMA, SnapshotSummary, Target, derive_verdict,
};
use kilo_dataset::{UpdateOptions, active_snapshot_dir, open_active, update};
use serde::Serialize;

const COMMAND_SCHEMA_JSON: &str = include_str!("../../../schemas/kilo.command.v1.json");
const OBSERVATION_SCHEMA_JSON: &str = include_str!("../../../schemas/kilo.observation.v1.json");
const STATUS_SCHEMA_JSON: &str = include_str!("../../../schemas/kilo.status.v1.json");

#[derive(Debug, Parser)]
#[command(
    name = "kilo",
    version,
    about = "Observe the evidence behind an IP address"
)]
struct Cli {
    /// Emit the stable machine-readable command envelope.
    #[arg(long, global = true)]
    json: bool,

    /// Guarantee that the command performs no network access.
    #[arg(long, global = true)]
    offline: bool,

    /// Disable terminal color (currently the default).
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Observe one or more IP addresses using the active local snapshot.
    Check {
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Report local dataset installation and integrity state.
    Status,
    /// Download, verify, compile, and atomically activate Kilo Data releases.
    Update {
        /// Read release archives and checksum files from a local directory.
        #[arg(long)]
        offline_dir: Option<PathBuf>,

        /// Install only the stable base dataset without the rolling edge overlay.
        #[arg(long)]
        no_edge: bool,

        /// Override the stable archive URL (intended for mirrors and testing).
        #[arg(long, hide = true)]
        base_url: Option<String>,

        /// Override the rolling edge archive URL (intended for mirrors and testing).
        #[arg(long, hide = true)]
        edge_url: Option<String>,
    },
    /// Describe commands, schemas, guarantees, and exit codes.
    Capabilities,
    /// Print a stable JSON Schema.
    Schema {
        #[arg(value_enum)]
        name: SchemaName,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaName {
    Command,
    Observation,
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_shorthand(env::args_os()));
    let _ = cli.no_color;

    match cli.command {
        Command::Check { targets } => check(&targets, cli.json),
        Command::Status => status(cli.json),
        Command::Update {
            offline_dir,
            no_edge,
            base_url,
            edge_url,
        } => update_command(
            cli.json,
            cli.offline,
            offline_dir,
            no_edge,
            base_url,
            edge_url,
        ),
        Command::Capabilities => capabilities(cli.json),
        Command::Schema { name } => schema(name),
    }
}

fn normalize_shorthand(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let commands = [
        "check",
        "status",
        "update",
        "capabilities",
        "schema",
        "help",
    ];

    for index in 1..args.len() {
        let Some(value) = args[index].to_str() else {
            break;
        };
        if value.starts_with('-') {
            continue;
        }
        if commands.contains(&value) {
            break;
        }
        if value.parse::<IpAddr>().is_ok() {
            args.insert(index, OsString::from("check"));
        }
        break;
    }

    args
}

fn check(targets: &[String], json: bool) -> ExitCode {
    let started = Instant::now();
    let parsed = match parse_targets(targets) {
        Ok(parsed) => parsed,
        Err(diagnostic) => {
            let envelope = CommandEnvelope::<Vec<CheckResult>>::failure(
                "check",
                diagnostic,
                elapsed_us(started),
            );
            render_failure(&envelope, json);
            return ExitCode::from(2);
        }
    };

    let home = kilo_home();
    let snapshot = match verified_fresh_snapshot(&home) {
        Ok(snapshot) => snapshot,
        Err((diagnostic, exit_code)) => {
            let envelope = CommandEnvelope::<Vec<CheckResult>>::failure(
                "check",
                diagnostic,
                elapsed_us(started),
            );
            render_failure(&envelope, json);
            return ExitCode::from(exit_code);
        }
    };

    let mut results = Vec::with_capacity(parsed.len());
    for address in parsed {
        let matches = match snapshot.query(address) {
            Ok(matches) => matches,
            Err(error) => {
                let envelope = CommandEnvelope::<Vec<CheckResult>>::failure(
                    "check",
                    Diagnostic::new("DATASET_INVALID", error.to_string()),
                    elapsed_us(started),
                );
                render_failure(&envelope, json);
                return ExitCode::from(1);
            }
        };
        let observations = matches
            .iter()
            .map(|observation| Observation {
                source_id: observation.source_id.clone(),
                classification: observation.classification.clone(),
                assertion: observation.assertion.clone(),
                confidence: observation.confidence,
                first_seen: observation.first_seen.clone(),
                last_seen: observation.last_seen.clone(),
                evidence_hash: observation.evidence_hash.clone(),
                independence_group: independence_group(&observation.source_id).into(),
            })
            .collect::<Vec<_>>();
        let provenance = matches
            .iter()
            .map(|observation| {
                (
                    observation.source_id.clone(),
                    Provenance {
                        source_id: observation.source_id.clone(),
                        artifact_hash: observation.artifact_hash.clone(),
                        license_id: observation.license_id.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect();
        results.push(CheckResult {
            schema: OBSERVATION_SCHEMA,
            target: Target::from(address),
            verdict: derive_verdict(&observations),
            observations,
            provenance,
        });
    }
    let envelope = CommandEnvelope::success_with_snapshot(
        "check",
        snapshot.manifest.snapshot_id.clone(),
        results,
        elapsed_us(started),
    );
    if json {
        render_json(&envelope);
    } else {
        render_checks(&envelope);
    }
    ExitCode::SUCCESS
}

fn parse_targets(targets: &[String]) -> Result<Vec<IpAddr>, Diagnostic> {
    targets
        .iter()
        .map(|target| {
            target.parse::<IpAddr>().map_err(|error| {
                Diagnostic::new(
                    "INVALID_TARGET",
                    format!("{target:?} is not a valid IPv4 or IPv6 address: {error}"),
                )
            })
        })
        .collect()
}

fn verified_fresh_snapshot(
    home: &std::path::Path,
) -> Result<kilo_dataset::Snapshot, (Diagnostic, u8)> {
    let snapshot = open_active(home).map_err(|error| {
        let code = match active_snapshot_dir(home) {
            Ok(None) => "DATASET_MISSING",
            Ok(Some(_)) | Err(_) => "DATASET_INVALID",
        };
        (Diagnostic::new(code, error.to_string()), 1)
    })?;
    snapshot.manifest.ensure_fresh().map_err(|error| {
        if matches!(&error, kilo_dataset::DatasetError::Stale(_)) {
            (Diagnostic::new("DATASET_STALE", error.to_string()), 4)
        } else {
            (Diagnostic::new("DATASET_INVALID", error.to_string()), 1)
        }
    })?;
    Ok(snapshot)
}

fn status(json: bool) -> ExitCode {
    let started = Instant::now();
    let home = kilo_home();
    let mut freshness = "unavailable";
    let snapshot = match active_snapshot_dir(&home) {
        Ok(None) => None,
        Ok(Some(_)) => match open_active(&home) {
            Ok(snapshot) => {
                freshness = match snapshot.manifest.ensure_fresh() {
                    Ok(()) => "fresh",
                    Err(kilo_dataset::DatasetError::Stale(_)) => "stale",
                    Err(error) => {
                        let envelope = CommandEnvelope::<DatasetStatus>::failure(
                            "status",
                            Diagnostic::new("DATASET_INVALID", error.to_string()),
                            elapsed_us(started),
                        );
                        render_failure(&envelope, json);
                        return ExitCode::from(1);
                    }
                };
                Some(SnapshotSummary {
                    id: snapshot.manifest.snapshot_id,
                    created_at: snapshot.manifest.created_at,
                    manifest_schema: snapshot.manifest.schema,
                })
            }
            Err(error) => {
                let envelope = CommandEnvelope::<DatasetStatus>::failure(
                    "status",
                    Diagnostic::new("DATASET_INVALID", error.to_string()),
                    elapsed_us(started),
                );
                render_failure(&envelope, json);
                return ExitCode::from(1);
            }
        },
        Err(error) => {
            let envelope = CommandEnvelope::<DatasetStatus>::failure(
                "status",
                Diagnostic::new("DATASET_INVALID", error.to_string()),
                elapsed_us(started),
            );
            render_failure(&envelope, json);
            return ExitCode::from(1);
        }
    };

    let installed = snapshot.is_some();
    let data = DatasetStatus {
        schema: STATUS_SCHEMA,
        installed,
        home: home.display().to_string(),
        integrity: if installed { "verified" } else { "unavailable" },
        freshness,
        snapshot,
    };
    let snapshot_id = data.snapshot.as_ref().map(|snapshot| snapshot.id.clone());
    let envelope = match snapshot_id {
        Some(snapshot_id) => {
            CommandEnvelope::success_with_snapshot("status", snapshot_id, data, elapsed_us(started))
        }
        None => CommandEnvelope::success("status", data, elapsed_us(started)),
    };

    if json {
        render_json(&envelope);
    } else {
        println!("KiloCheck dataset\n");
        println!(
            "  Installed   {}",
            if envelope.data.as_ref().is_some_and(|value| value.installed) {
                "yes"
            } else {
                "no"
            }
        );
        println!("  Home        {}", home.display());
        println!(
            "  Integrity   {}",
            envelope
                .data
                .as_ref()
                .map_or("unavailable", |value| value.integrity)
        );
        println!("  Freshness   {freshness}");
    }
    ExitCode::from(if freshness == "stale" { 4 } else { 0 })
}

fn update_command(
    json: bool,
    offline: bool,
    offline_dir: Option<PathBuf>,
    no_edge: bool,
    base_url: Option<String>,
    edge_url: Option<String>,
) -> ExitCode {
    let started = Instant::now();
    if offline && offline_dir.is_none() {
        let envelope = CommandEnvelope::<kilo_dataset::UpdateReport>::failure(
            "update",
            Diagnostic::new(
                "OFFLINE_INPUT_REQUIRED",
                "--offline update requires --offline-dir with release archives and checksums",
            ),
            elapsed_us(started),
        );
        render_failure(&envelope, json);
        return ExitCode::from(2);
    }
    let mut options = UpdateOptions {
        offline_dir,
        include_edge: !no_edge,
        ..UpdateOptions::default()
    };
    if let Some(url) = base_url {
        options.base_url = url;
    }
    if let Some(url) = edge_url {
        options.edge_url = url;
    }
    let home = kilo_home();
    match update(&home, &options) {
        Ok(report) => {
            let envelope = CommandEnvelope::success_with_snapshot(
                "update",
                report.snapshot_id.clone(),
                report,
                elapsed_us(started),
            );
            if json {
                render_json(&envelope);
            } else if let Some(report) = &envelope.data {
                println!("KiloCheck dataset installed\n");
                println!("  Snapshot    {}", report.snapshot_id);
                println!("  Claims      {}", report.records);
                println!("  Index       {} bytes", report.index_bytes);
                println!("  Created     {}", report.installed_at);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let stale = matches!(error, kilo_dataset::DatasetError::Stale(_));
            let envelope = CommandEnvelope::<kilo_dataset::UpdateReport>::failure(
                "update",
                Diagnostic::new(
                    if stale {
                        "DATASET_STALE"
                    } else {
                        "UPDATE_FAILED"
                    },
                    error.to_string(),
                ),
                elapsed_us(started),
            );
            render_failure(&envelope, json);
            ExitCode::from(if stale { 4 } else { 1 })
        }
    }
}

fn capabilities(json: bool) -> ExitCode {
    let started = Instant::now();
    let data = Capabilities::default();
    let envelope = CommandEnvelope::success("capabilities", data, elapsed_us(started));

    if json {
        render_json(&envelope);
    } else if let Some(data) = &envelope.data {
        println!("KiloCheck capabilities\n");
        for command in &data.commands {
            let state = if command.available {
                "available"
            } else {
                "planned"
            };
            println!("  {:<14} {:<10} {}", command.name, state, command.summary);
        }
    }
    ExitCode::SUCCESS
}

fn schema(name: SchemaName) -> ExitCode {
    let value = match name {
        SchemaName::Command => COMMAND_SCHEMA_JSON,
        SchemaName::Observation => OBSERVATION_SCHEMA_JSON,
        SchemaName::Status => STATUS_SCHEMA_JSON,
    };
    print!("{value}");
    ExitCode::SUCCESS
}

fn kilo_home() -> PathBuf {
    if let Some(path) = env::var_os("KILO_HOME") {
        return PathBuf::from(path);
    }
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("kilo");
    }
    env::var_os("HOME").map_or_else(
        || PathBuf::from(".kilo"),
        |path| {
            PathBuf::from(path)
                .join(".local")
                .join("share")
                .join("kilo")
        },
    )
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn render_failure<T: Serialize>(envelope: &CommandEnvelope<T>, json: bool) {
    if json {
        render_json(envelope);
    } else {
        for error in &envelope.errors {
            eprintln!("error[{}]: {}", error.code, error.message);
        }
    }
}

fn render_checks(envelope: &CommandEnvelope<Vec<CheckResult>>) {
    let Some(results) = &envelope.data else {
        return;
    };
    for (index, result) in results.iter().enumerate() {
        if index != 0 {
            println!();
        }
        println!("KiloCheck — IP observation\n");
        println!("Target");
        println!("  IP                 {}", result.target.value);
        println!("  Version            IPv{}", result.target.version);
        println!(
            "  Snapshot           {}",
            envelope.snapshot_id.as_deref().unwrap_or("unknown")
        );
        println!("\nVerdict");
        println!("  disposition        {:?}", result.verdict.disposition);
        println!("  confidence         {:.2}", result.verdict.confidence);
        println!(
            "  recommended action {:?}",
            result.verdict.recommended_action
        );
        println!(
            "  reason             {}",
            result.verdict.reason_codes.join(", ")
        );
        println!("\nObservations");
        if result.observations.is_empty() {
            println!("  none in the active snapshot");
        } else {
            for observation in &result.observations {
                println!(
                    "  {:<22} {:<32} {:.2}",
                    observation.source_id, observation.classification, observation.confidence
                );
            }
        }
    }
}

fn independence_group(source: &str) -> &str {
    if source.starts_with("spamhaus-") {
        "spamhaus-drop"
    } else if source.starts_with("feodo-") {
        "abuse-ch-feodo"
    } else if source == "tor-exits" {
        "tor-project"
    } else {
        source
    }
}

fn render_json(value: &impl Serialize) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(error) => eprintln!("error[SERIALIZATION_FAILED]: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_inserts_check_before_an_ip() {
        let args = vec![OsString::from("kilo"), OsString::from("192.0.2.1")];
        let normalized = normalize_shorthand(args);
        assert_eq!(normalized[1], "check");
        assert_eq!(normalized[2], "192.0.2.1");
    }

    #[test]
    fn explicit_commands_are_unchanged() {
        let args = vec![OsString::from("kilo"), OsString::from("status")];
        assert_eq!(normalize_shorthand(args).len(), 2);
    }

    #[test]
    fn shorthand_works_after_global_flags() {
        let args = vec![
            OsString::from("kilo"),
            OsString::from("--json"),
            OsString::from("2001:db8::1"),
        ];
        let normalized = normalize_shorthand(args);
        assert_eq!(normalized[2], "check");
    }

    #[test]
    fn malformed_active_pointer_is_invalid_not_missing() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("active.json"), b"not json").unwrap();
        let Err((diagnostic, exit_code)) = verified_fresh_snapshot(home.path()) else {
            panic!("malformed active pointer must fail");
        };
        assert_eq!(diagnostic.code, "DATASET_INVALID");
        assert_eq!(exit_code, 1);
    }
}
