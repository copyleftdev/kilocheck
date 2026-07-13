#!/usr/bin/env bash
set -euo pipefail

runs="${KILO_FUZZ_RUNS:-10000}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

mkdir -p "${workdir}/target_parse" "${workdir}/manifest_parse"
cp fuzz/seeds/target_parse/* "${workdir}/target_parse/"
cp fuzz/seeds/manifest_parse/* "${workdir}/manifest_parse/"

cargo +nightly fuzz run target_parse "${workdir}/target_parse" -- -runs="${runs}"
cargo +nightly fuzz run manifest_parse "${workdir}/manifest_parse" -- -runs="${runs}"
