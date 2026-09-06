#!/usr/bin/env bash
set -euo pipefail
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
npm run build --workspace @space/extension
source_dir="apps/extension/dist"
test -f "$source_dir/manifest.json" || { echo "missing built extension manifest" >&2; exit 1; }
mkdir -p artifacts
find "$source_dir" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
(cd "$source_dir" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 zip -X -q "../../../artifacts/space-chrome.zip")
sha256sum artifacts/space-chrome.zip > artifacts/space-chrome.zip.sha256
