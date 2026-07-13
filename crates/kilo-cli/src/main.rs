use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use kilo_core::{
    Capabilities, CheckResult, CommandEnvelope, DatasetStatus, Diagnostic, STATUS_SCHEMA,
    SnapshotSummary,
};
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
struct InstalledManifest {
    schema: String,
    snapshot_id: String,
    created_at: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_shorthand(env::args_os()));
    let _ = (cli.offline, cli.no_color);

    match cli.command {
        Command::Check { targets } => check(&targets, cli.json),
        Command::Status => status(cli.json),
        Command::Capabilities => capabilities(cli.json),
        Command::Schema { name } => schema(name),
    }
}

fn normalize_shorthand(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let commands = ["check", "status", "capabilities", "schema", "help"];

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
    let mut parsed = Vec::with_capacity(targets.len());
    for target in targets {
        match target.parse::<IpAddr>() {
            Ok(address) => parsed.push(address),
            Err(error) => {
                let diagnostic = Diagnostic::new(
                    "INVALID_TARGET",
                    format!("{target:?} is not a valid IPv4 or IPv6 address: {error}"),
                );
                let envelope = CommandEnvelope::<Vec<CheckResult>>::failure(
                    "check",
                    diagnostic,
                    elapsed_us(started),
                );
                render_failure(&envelope, json);
                return ExitCode::from(2);
            }
        }
    }

    let home = kilo_home();
    let manifest_path = active_manifest_path(&home);
    if !manifest_path.is_file() {
        let diagnostic = Diagnostic::new(
            "DATASET_MISSING",
            format!(
                "no active KiloCheck snapshot is installed at {}",
                manifest_path.display()
            ),
        );
        let envelope =
            CommandEnvelope::<Vec<CheckResult>>::failure("check", diagnostic, elapsed_us(started));
        render_failure(&envelope, json);
        return ExitCode::from(1);
    }

    let index_path = home.join("active").join("snapshot.kilo");
    if !index_path.is_file() {
        let diagnostic = Diagnostic::new(
            "SNAPSHOT_INDEX_MISSING",
            format!(
                "the active manifest exists, but its compiled index is missing at {}",
                index_path.display()
            ),
        );
        let envelope =
            CommandEnvelope::<Vec<CheckResult>>::failure("check", diagnostic, elapsed_us(started));
        render_failure(&envelope, json);
        return ExitCode::from(1);
    }

    let diagnostic = Diagnostic::new(
        "SNAPSHOT_FORMAT_UNSUPPORTED",
        "the installed snapshot format is newer than this milestone can query",
    );
    let envelope =
        CommandEnvelope::<Vec<CheckResult>>::failure("check", diagnostic, elapsed_us(started));
    render_failure(&envelope, json);
    let _ = parsed;
    ExitCode::from(1)
}

fn status(json: bool) -> ExitCode {
    let started = Instant::now();
    let home = kilo_home();
    let manifest_path = active_manifest_path(&home);

    let snapshot = if manifest_path.is_file() {
        match read_manifest(&manifest_path) {
            Ok(manifest) => Some(SnapshotSummary {
                id: manifest.snapshot_id,
                created_at: manifest.created_at,
                manifest_schema: manifest.schema,
            }),
            Err(error) => {
                let envelope = CommandEnvelope::<DatasetStatus>::failure(
                    "status",
                    Diagnostic::new("MANIFEST_INVALID", error),
                    elapsed_us(started),
                );
                render_failure(&envelope, json);
                return ExitCode::from(1);
            }
        }
    } else {
        None
    };

    let installed = snapshot.is_some();
    let data = DatasetStatus {
        schema: STATUS_SCHEMA,
        installed,
        home: home.display().to_string(),
        integrity: if installed {
            "manifest-present"
        } else {
            "unavailable"
        },
        snapshot,
    };
    let envelope = CommandEnvelope::success("status", data, elapsed_us(started));

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
    }
    ExitCode::SUCCESS
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

fn read_manifest(path: &Path) -> Result<InstalledManifest, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn active_manifest_path(home: &Path) -> PathBuf {
    home.join("active").join("manifest.json")
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
}
