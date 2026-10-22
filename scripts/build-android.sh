#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

JNI_LIBS="android/src/main/jniLibs"
KOTLIN_OUT="android/src/main/java"
mkdir -p "$JNI_LIBS" "$KOTLIN_OUT"

cargo ndk \
  --target aarch64-linux-android \
  --target armv7-linux-androideabi \
  --target x86_64-linux-android \
  --output-dir "$JNI_LIBS" \
  --platform 24 \
  build --release --locked

cargo build --release --locked --features cli --bin uniffi-bindgen

REF_SO="$JNI_LIBS/arm64-v8a/libquantova_qcore.so"
./target/release/uniffi-bindgen generate \
  --library "$REF_SO" \
  --language kotlin \
  --out-dir "$KOTLIN_OUT"

STRIP="$(find "${ANDROID_NDK_HOME:?}/toolchains/llvm/prebuilt" -name llvm-strip \( -type f -o -type l \) | head -n 1)"
if [[ ! -x "$STRIP" ]]; then
  echo "llvm-strip was not found in the NDK at $ANDROID_NDK_HOME" >&2
  exit 1
fi
for so in "$JNI_LIBS"/*/libquantova_qcore.so; do
  "$STRIP" --strip-all "$so"
done

echo "android .so libraries under $JNI_LIBS"
echo "kotlin bindings under $KOTLIN_OUT/uniffi/quantova_qcore"
