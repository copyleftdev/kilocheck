#!/usr/bin/env bash
set -euo pipefail

node site/tests/site.test.mjs

test "$(find site -type f | wc -l)" -ge 8
test "$(stat -c %s site/assets/kilocheck-bbs-640.webp)" -lt 250000
test "$(stat -c %s site/assets/kilocheck-bbs.webp)" -lt 500000

echo "site validation passed"
