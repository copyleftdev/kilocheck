# KiloCheck: plain-language contract

This document is the accessible, searchable companion to the project's
leetspeak [README](../README.md).

> Don't query a blacklist. Observe the evidence.

KiloCheck is a local-first, deterministic IP-intelligence CLI. It is designed
to compile current threat observations into an auditable local snapshot for
fast checks by humans, agents, and enforcement systems.

Explore the mechanism at
[copyleftdev.github.io/kilocheck](https://copyleftdev.github.io/kilocheck/).

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

## Dogfood workflow

Install the release archive for your platform, place `kilo` on `PATH`, then:

```bash
kilo update
kilo status --json
kilo check 162.243.103.246 --json
```

`kilo update` downloads the stable base and rolling edge assets directly from
the Kilo Data GitHub releases. It does not use the GitHub API or a reputation
API. It verifies each neighboring SHA-256 file, rejects unsafe archives,
validates manifests and table hashes, enforces freshness, compiles a compact
local index, and activates it only after every step succeeds.

`kilo check` reads only that local index. An unobserved address is `unknown`,
never clean. A snapshot with a current edge overlay expires after six hours; a
base-only snapshot expires after 72 hours. Stale data remains inspectable with
`status`, but `check` refuses to produce a verdict.

For an air-gapped update, place both release archives and their `.sha256` files
in one directory:

```bash
kilo --offline update --offline-dir ./kilo-data-release
```

## Install a release

Prebuilt archives for Linux x86-64, macOS Intel, macOS Apple Silicon, and
Windows x86-64 are published on the
[releases page](https://github.com/copyleftdev/kilocheck/releases). Every
archive has a neighboring SHA-256 file and GitHub build-provenance attestation.

Linux and macOS quick install (version-pinned, SHA-256 verified, no API):

```bash
curl -fsSL https://raw.githubusercontent.com/copyleftdev/kilocheck/v0.2.0/scripts/install.sh | sh
kilo update
```

Review the script at the tag before piping it to a shell. Manual Linux install:

```bash
sha256sum --check kilo-v0.2.0-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf kilo-v0.2.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 kilo-v0.2.0-x86_64-unknown-linux-musl/kilo ~/.local/bin/kilo
kilo update
```

## Build

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p kilo-cli -- capabilities --json
```

## Test contract

Fast unit and property tests run on Linux, macOS, and Windows. Linux CI also
runs mutation analysis over `kilo-core` and the compact index engine, then
smoke-fuzzes every untrusted-input parser.

```bash
scripts/test-all.sh
scripts/mutate.sh
KILO_FUZZ_RUNS=10000 scripts/fuzz-smoke.sh
```

The properties cover the complete IPv4 and IPv6 spaces, arbitrary 128-bit
prefix membership, arbitrary target and index bytes, canonical round trips,
deterministic compilation, and the invariant that duplicate upstream evidence
never increases independence. Archive traversal, links, checksum tampering,
index tampering, edge replacement, last-good preservation, and freshness
boundaries have explicit adversarial tests.
See [CONTRIBUTING.md](../CONTRIBUTING.md) for the testing policy.

## Exit codes currently emitted

| Code | Meaning |
| ---: | --- |
| `0` | Command succeeded; no policy violation |
| `1` | Operational or integrity error |
| `2` | Invalid invocation |
| `4` | Dataset too stale |

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
