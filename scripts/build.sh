#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

revision=e0472890bea827d15ca883636a77d4c10bbe843b
version="${MFG_VERSION:-$(cat VERSION)-dev}"
target_os="$(go env GOOS)"
target_arch="$(go env GOARCH)"
case "$target_os" in
  linux|freebsd) extension=so ;;
  darwin) extension=dylib ;;
  windows) extension=dll ;;
  *) printf 'Unsupported plugin target: %s\n' "$target_os" >&2; exit 1 ;;
esac
if [[ ! "$version" =~ ^[0-9][0-9A-Za-z.+-]*$ ]]; then
  printf 'Invalid plugin version: %s\n' "$version" >&2
  exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
upstream="${MFG_REFERENCE_REPO:-$scratch/upstream}"
if [[ -z "${MFG_REFERENCE_REPO:-}" ]]; then
  git init -q "$upstream"
  git -C "$upstream" fetch -q --depth 1 https://github.com/Ikaleio/lm-detector.git "$revision"
fi
mkdir -p internal/fingerprint/reference
for entry in unified_bank.json shared_detector.bin; do
  git -C "$upstream" show "$revision:data/$entry" > "$scratch/$entry"
done
python3 - "$scratch" <<'PY'
import hashlib
from pathlib import Path
import sys

expected = {
    "unified_bank.json": "06397f4ed64911abab9f3b05843f5e87fc92057040aa9aa43bc6f16eb242b1aa",
    "shared_detector.bin": "5ce8f55a6bed741c3ef2c3d9929832df949639d249834aabea168773136fd9e2",
}
root = Path(sys.argv[1])
for name, checksum in expected.items():
    with (root / name).open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != checksum:
            raise SystemExit(f"Reference checksum mismatch: {name}")
PY
for entry in unified_bank.json shared_detector.bin; do
  gzip -n -c "$scratch/$entry" > "internal/fingerprint/reference/$entry.gz"
done

dir="${MFG_DIST:-dist}/$target_os-$target_arch"
mkdir -p -- "$dir"
artifact="$dir/model-fingerprint-guard-v$version.$extension"
CGO_ENABLED=1 go build -trimpath -buildvcs=false -tags reference_embedded -buildmode=c-shared \
  -ldflags "-s -w -X main.releaseVersion=$version" -o "$artifact" ./cmd/model-fingerprint-guard
rm -f -- "${artifact%.*}.h"
printf '%s\n' "$artifact"
