# KiloCheck

> Don't query a blacklist. Observe the evidence.

KiloCheck is a local-first, deterministic IP-intelligence CLI. It is designed
to compile current threat observations into an auditable local snapshot for
fast checks by humans, agents, and enforcement systems.

Explore the mechanism at **[copyleftdev.github.io/kilocheck](https://copyleftdev.github.io/kilocheck/)**.

The intelligence engine proves. An optional AI layer may eventually interpret
only the bounded evidence the engine established.

## Product contract

- Ordinary checks never require network access.
- Data arrives as versioned release artifacts from
  [`copyleftdev/kilo-data`](https://github.com/copyleftdev/kilo-data), never as
  per-IP API lookups.
- JSON is a stable product interface, not a rendering of terminal prose.
- Missing, unknown, stale, incomplete, and operational failure remain distinct.
- Verdicts derive from typed observations and independent evidence groups—not
  a mutable reputation score.

## Current milestone

This repository establishes the executable and its public contracts:

```bash
kilo capabilities --json
kilo status --json
kilo check 192.0.2.1 --json
kilo 192.0.2.1 --json
kilo schema command
```

The current `check` command validates targets and fails explicitly when no
compiled snapshot is installed. It does not pretend that an unobserved address
is safe. The next milestone adds verified Kilo Data release installation and
the immutable memory-mapped lookup index.

## Install a release

Prebuilt archives for Linux x86-64, macOS Intel, macOS Apple Silicon, and
Windows x86-64 are published on the
[releases page](https://github.com/copyleftdev/kilocheck/releases). Every
archive has a neighboring SHA-256 file and GitHub build-provenance attestation.

```bash
sha256sum --check kilo-v0.1.0-x86_64-unknown-linux-musl.tar.gz.sha256
```

## Build

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p kilo-cli -- capabilities --json
```

## Test contract

Fast unit and property tests run on Linux, macOS, and Windows. Linux CI also
runs mutation analysis over `kilo-core` and smoke-fuzzes every untrusted-input
parser.

```bash
scripts/test-all.sh
scripts/mutate.sh
KILO_FUZZ_RUNS=10000 scripts/fuzz-smoke.sh
```

The initial properties cover the complete IPv4 and IPv6 spaces, canonical
round trips, arbitrary target text, deterministic manifest serialization, and
the invariant that duplicate upstream evidence never increases independence.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the testing policy.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Command succeeded; no policy violation |
| `1` | Operational or integrity error |
| `2` | Invalid invocation |
| `3` | Policy gate failed |
| `4` | Dataset too stale |
| `5` | Required-source result is incomplete |

## Architecture

```text
Kilo Data release artifacts
        ↓
verified snapshot compiler
        ↓
immutable local index
        ↓
deterministic evidence engine
        ↓
human and stable JSON renderers
```

The source/data pipeline is maintained separately in
[`kilo-data`](https://github.com/copyleftdev/kilo-data). KiloCheck owns local
installation, query semantics, policy, and rendering.
