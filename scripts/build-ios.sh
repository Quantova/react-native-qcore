#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LIB_NAME="libquantova_qcore.a"
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"
GENERATED="ios/generated"
XCFRAMEWORK="ios/QuantovaQcore.xcframework"

cargo build --release --locked --target "$DEVICE_TARGET"
cargo build --release --locked --target "$SIM_TARGET"
cargo build --release --locked --features cli --bin uniffi-bindgen

mkdir -p "$GENERATED"
./target/release/uniffi-bindgen generate \
  --library "target/${DEVICE_TARGET}/release/${LIB_NAME}" \
  --language swift \
  --out-dir "$GENERATED"

rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/${DEVICE_TARGET}/release/${LIB_NAME}" \
  -library "target/${SIM_TARGET}/release/${LIB_NAME}" \
  -output "$XCFRAMEWORK"

echo "xcframework: $XCFRAMEWORK"
echo "swift bindings: $GENERATED/quantova_qcore.swift"
