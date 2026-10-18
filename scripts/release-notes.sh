#!/usr/bin/env bash
# Print the CHANGELOG.md section for a release tag, without its heading.
# Usage: scripts/release-notes.sh vX.Y.Z[-pre] [CHANGELOG.md]
# Fails (non-zero) if the tag is not semver, the section is missing, or it is empty.
set -euo pipefail

tag="${1:-}"
file="${2:-CHANGELOG.md}"
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

[[ "$tag" =~ $semver ]] || { echo "release-notes: '$tag' is not a vX.Y.Z[-pre] tag" >&2; exit 2; }
[[ -f "$file" ]] || { echo "release-notes: $file not found" >&2; exit 2; }

ver="${tag#v}"
notes="$(awk -v ver="$ver" '
  /^## \[/ {
    if (on) exit
    if (index($0, "## [" ver "]") == 1) { on = 1; next }
  }
  on && /^\[[^]]+\]: / { exit }
  on { print }
' "$file")"

# Trim leading and trailing blank lines.
notes="$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "release-notes: no non-empty '## [$ver]' section in $file" >&2
  exit 1
fi
printf '%s\n' "$notes"
