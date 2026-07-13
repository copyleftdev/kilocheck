# Architecture boundary

KiloCheck has three crates whose interfaces correspond to shipped behavior.

```text
kilo-cli  → command parsing, installation discovery, rendering, exit codes
    ↓
kilo-core → stable domain types, envelopes, verdict vocabulary
    ↓
kilo-dataset → verified acquisition, compilation, activation, local lookup
```

The compact index is read into bounded memory and validated before use. Future
policy, exporter, and source-metadata boundaries should appear only with shipped
behavior; they should not be empty crates or source-specific abstractions.

## Dataset contract

KiloCheck consumes the release artifacts produced by Kilo Data. Collection and
normalization stay out of the query repository. `kilo update` uses direct
release-asset downloads without a release API, validates neighboring checksums,
manifest identity, table hashes, and freshness, compiles the runtime index in
staging, then atomically activates it.

An ordinary `check` never downloads data and never contacts an intelligence
service.
