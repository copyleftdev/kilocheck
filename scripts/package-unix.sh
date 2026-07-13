#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <target>" >&2
  exit 2
fi

tag="$1"
target="$2"
name="kilo-${tag}-${target}"
archive="${name}.tar.gz"
binary="target/${target}/release/kilo"
stage="$(mktemp -d)"
trap 'rm -rf "${stage}"' EXIT

test -x "${binary}"
mkdir -p "dist" "${stage}/${name}"
cp "${binary}" LICENSE README.md "${stage}/${name}/"
tar -czf "dist/${archive}" -C "${stage}" "${name}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "${archive}" > "${archive}.sha256")
else
  (cd dist && shasum -a 256 "${archive}" > "${archive}.sha256")
fi
