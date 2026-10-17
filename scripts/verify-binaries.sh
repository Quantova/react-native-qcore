#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SUMS="SHA256SUMS"
BUILT=(
  "android/src/main/jniLibs"
  "android/src/main/java/uniffi"
  "ios/QuantovaQcore.xcframework"
  "ios/generated"
)

PUBLISH=0
if [[ "${1:-}" == "--publish" ]]; then
  PUBLISH=1
fi

if [[ ! -s "$SUMS" ]]; then
  echo "no $SUMS here, refusing to ship native binaries that were not built and summed in ci" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  check() { sha256sum --check --strict --quiet "$1"; }
else
  check() { shasum -a 256 --check --strict --quiet "$1"; }
fi

for dir in "${BUILT[@]}"; do
  if [[ ! -d "$dir" ]]; then
    echo "$dir is missing, the package must carry every binary built in ci" >&2
    exit 1
  fi
done

listed="$(awk '{ name = $2; sub(/^\*/, "", name); print name }' "$SUMS" | LC_ALL=C sort)"
present="$(find "${BUILT[@]}" -type f ! -name .DS_Store | LC_ALL=C sort)"

if [[ "$listed" != "$present" ]]; then
  echo "the files on disk do not match the files in $SUMS" >&2
  diff <(echo "$listed") <(echo "$present") >&2 || true
  exit 1
fi

check "$SUMS"
echo "every native binary matches $SUMS"

if [[ "$PUBLISH" == "1" ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "publishing needs the gh command to confirm that every native binary was built and attested by the release workflow" >&2
    exit 1
  fi
  REPO="Quantova/react-native-qcore"
  while read -r built; do
    if ! gh attestation verify "$built" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" >/dev/null 2>&1; then
      echo "$built carries no attestation from the release workflow, refusing to publish it" >&2
      exit 1
    fi
  done < <(awk '{ name = $2; sub(/^\*/, "", name); print name }' "$SUMS")
  echo "every native binary is attested by the release workflow"
fi
