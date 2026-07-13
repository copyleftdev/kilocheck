#!/usr/bin/env bash
set -euo pipefail

cargo mutants --workspace --output .
