#!/usr/bin/env sh
set -eu

version="${KILO_VERSION:-v0.2.0}"
install_dir="${KILO_INSTALL_DIR:-${HOME}/.local/bin}"
release_base="${KILO_RELEASE_BASE:-https://github.com/copyleftdev/kilocheck/releases/download/${version}}"

case "$(uname -s)" in
  Linux) os="unknown-linux-musl" ;;
  Darwin) os="apple-darwin" ;;
  *) echo "kilo: unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) echo "kilo: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "${os}" = "unknown-linux-musl" ] && [ "${arch}" != "x86_64" ]; then
  echo "kilo: no ${arch} Linux release is published yet" >&2
  exit 1
fi

target="${arch}-${os}"
name="kilo-${version}-${target}"
archive="${name}.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT HUP INT TERM

download() {
  source="$1"
  destination="$2"
  case "${source}" in
    file://*) cp "${source#file://}" "${destination}" ;;
    *)
      if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error "${source}" --output "${destination}"
      elif command -v wget >/dev/null 2>&1; then
        wget --quiet "${source}" --output-document="${destination}"
      else
        echo "kilo: curl or wget is required" >&2
        exit 1
      fi
      ;;
  esac
}

download "${release_base}/${archive}" "${work}/${archive}"
download "${release_base}/${archive}.sha256" "${work}/${archive}.sha256"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${work}" && sha256sum --check "${archive}.sha256")
elif command -v shasum >/dev/null 2>&1; then
  expected="$(awk 'NR == 1 { print $1 }' "${work}/${archive}.sha256")"
  actual="$(shasum -a 256 "${work}/${archive}" | awk '{ print $1 }')"
  [ "${expected}" = "${actual}" ] || {
    echo "kilo: checksum mismatch for ${archive}" >&2
    exit 1
  }
else
  echo "kilo: sha256sum or shasum is required" >&2
  exit 1
fi

tar -xzf "${work}/${archive}" -C "${work}"
mkdir -p "${install_dir}"
install -m 0755 "${work}/${name}/kilo" "${install_dir}/kilo"
echo "kilo ${version} installed at ${install_dir}/kilo"
echo "next: kilo update"
