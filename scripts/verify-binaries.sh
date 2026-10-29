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
  VERSION="$(node -p "require('./package.json').version")"
  TAG="v$VERSION"
  if ! TAG_COMMIT="$(git rev-parse --verify --quiet "refs/tags/$TAG^{commit}")"; then
    echo "the tag $TAG is not in this checkout, publish only from the tagged release" >&2
    exit 1
  fi
  if [[ "$(git rev-parse HEAD)" != "$TAG_COMMIT" ]]; then
    echo "this checkout is not at $TAG, publish only from the tagged release" >&2
    exit 1
  fi
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "this checkout has local changes, publish only from the tagged release" >&2
    exit 1
  fi
  merged="$(gh api "repos/$REPO/compare/$TAG_COMMIT...main" --jq .status 2>/dev/null || true)"
  if [[ "$merged" != "ahead" && "$merged" != "identical" ]]; then
    echo "$TAG points at $TAG_COMMIT, which is not on main, refusing to publish it" >&2
    exit 1
  fi
  while read -r built; do
    if ! gh attestation verify "$built" --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release.yml" \
      --source-ref "refs/tags/$TAG" \
      --source-digest "$TAG_COMMIT" \
      --deny-self-hosted-runners >/dev/null 2>&1; then
      echo "$built carries no attestation from the release workflow run for $TAG at $TAG_COMMIT, refusing to publish it" >&2
      exit 1
    fi
  done < <(awk '{ name = $2; sub(/^\*/, "", name); print name }' "$SUMS")
  echo "every native binary is attested by the release workflow run for $TAG at $TAG_COMMIT"
fi
