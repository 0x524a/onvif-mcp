#!/usr/bin/env bash
# Cross-build onvif-mcp release archives and a SHA256SUMS file.
# Usage: scripts/build-release.sh vX.Y.Z [OUTDIR]   (OUTDIR defaults to dist)
# Only cmd/onvif-mcp ships; cmd/demo-camera is a development aid.
# Each archive holds the binary, LICENSE, NOTICE and README.md.
set -euo pipefail

tag="${1:-}"
out="${2:-dist}"
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ "$tag" =~ $semver ]] || { echo "build-release: '$tag' is not a vX.Y.Z[-pre] tag" >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
for f in LICENSE NOTICE README.md; do
  [[ -f "$f" ]] || { echo "build-release: missing $f" >&2; exit 2; }
done

rm -rf "$out"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# Fixed timestamp keeps archive bytes independent of build time.
epoch="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
ldflags="-s -w -X github.com/0x524a/onvif-mcp/internal/mcpserver.version=${tag}"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  goos="${target%/*}"; goarch="${target#*/}"
  name="onvif-mcp_${tag}_${goos}_${goarch}"
  bin="onvif-mcp"; [[ "$goos" == windows ]] && bin="onvif-mcp.exe"
  dir="$stage/$name"
  mkdir -p "$dir"
  echo "build $name" >&2
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$ldflags" -o "$dir/$bin" ./cmd/onvif-mcp
  cp LICENSE NOTICE README.md "$dir/"
  find "$stage/$name" -exec touch -d "@$epoch" {} +
  if [[ "$goos" == windows ]]; then
    (cd "$stage" && zip -q -X -r "$out/$name.zip" "$name")
  else
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
      -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
  fi
done

(cd "$out" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
echo "wrote $(ls "$out" | wc -l) files to $out" >&2
