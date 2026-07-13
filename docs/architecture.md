# Architecture boundary

KiloCheck starts with two crates and splits only when an interface has become
real enough to protect.

```text
kilo-cli  → command parsing, installation discovery, rendering, exit codes
    ↓
kilo-core → stable domain types, envelopes, verdict vocabulary
```

Planned boundaries are the snapshot format/compiler, memory-mapped indexes,
policy evaluation, provenance, source metadata, and exporters. They should not
be empty crates or source-specific abstractions.

## Dataset contract

KiloCheck consumes the release artifacts produced by Kilo Data. Collection and
normalization stay out of the query repository. Updates will use direct release
asset downloads, validate their published checksums and manifests, compile the
runtime index in staging, then atomically activate it.

An ordinary `check` never downloads data and never contacts an intelligence
service.
