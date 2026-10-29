#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LIB_NAME="libquantova_qcore"
HOST_EXT="dylib"
if [[ "$(uname -s)" == "Linux" ]]; then
  HOST_EXT="so"
fi
HOST_LIB="target/debug/${LIB_NAME}.${HOST_EXT}"

cargo build
cargo build --features cli --bin uniffi-bindgen

ANDROID_OUT="android/src/main/java"
IOS_OUT="ios/generated"
mkdir -p "$ANDROID_OUT" "$IOS_OUT"

./target/debug/uniffi-bindgen generate \
  --library "$HOST_LIB" \
  --language kotlin \
  --out-dir "$ANDROID_OUT"

./target/debug/uniffi-bindgen generate \
  --library "$HOST_LIB" \
  --language swift \
  --out-dir "$IOS_OUT"

echo "kotlin bindings: $ANDROID_OUT/uniffi/quantova_qcore/quantova_qcore.kt"
echo "swift bindings:  $IOS_OUT/quantova_qcore.swift"
