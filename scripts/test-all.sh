#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
cargo fmt --manifest-path fuzz/Cargo.toml --all --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +nightly fuzz check
