use kilo_core::{COMMAND_SCHEMA, OBSERVATION_SCHEMA, STATUS_SCHEMA};

const COMMAND: &str = include_str!("../../../schemas/kilo.command.v1.json");
const OBSERVATION: &str = include_str!("../../../schemas/kilo.observation.v1.json");
const STATUS: &str = include_str!("../../../schemas/kilo.status.v1.json");

#[test]
fn every_embedded_contract_is_valid_json() {
    for (name, schema) in [
        ("command", COMMAND),
        ("observation", OBSERVATION),
        ("status", STATUS),
    ] {
        serde_json::from_str::<serde_json::Value>(schema)
            .unwrap_or_else(|error| panic!("{name} schema is invalid JSON: {error}"));
    }
}

#[test]
fn schema_files_match_the_public_rust_constants() {
    for (schema, expected) in [
        (COMMAND, COMMAND_SCHEMA),
        (OBSERVATION, OBSERVATION_SCHEMA),
        (STATUS, STATUS_SCHEMA),
    ] {
        let value: serde_json::Value = serde_json::from_str(schema).expect("validated fixture");
        assert_eq!(value["properties"]["schema"]["const"], expected);
    }
}
