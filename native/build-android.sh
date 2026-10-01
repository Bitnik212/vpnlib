#!/usr/bin/env bash
# Builds libvpncore.so for every Android ABI into native/build/android/jniLibs.
#
# Requirements: Go (>= go.mod version, GOTOOLCHAIN=auto is fine) and the
# Android NDK (ANDROID_NDK_HOME or ANDROID_NDK_ROOT, r27+ recommended).
#
# Usage: native/build-android.sh [abi...]   (default: all ABIs)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/vpncore"
OUT="${VPNCORE_ANDROID_OUT:-$ROOT/build/android/jniLibs}"
API="${ANDROID_MIN_API:-24}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if [[ -z "$NDK" || ! -d "$NDK" ]]; then
  echo "error: set ANDROID_NDK_HOME to an Android NDK installation" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) HOST_TAG="linux-x86_64" ;;
  Darwin) HOST_TAG="darwin-x86_64" ;; # the NDK ships universal binaries here
  *) echo "error: unsupported host $(uname -s)" >&2; exit 1 ;;
esac
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"

ABIS=("$@")
if [[ ${#ABIS[@]} -eq 0 ]]; then
  ABIS=(arm64-v8a armeabi-v7a x86_64 x86)
fi

for abi in "${ABIS[@]}"; do
  goarm=""
  case "$abi" in
    arm64-v8a) goarch=arm64; cc="aarch64-linux-android$API-clang" ;;
    armeabi-v7a) goarch=arm; goarm=7; cc="armv7a-linux-androideabi$API-clang" ;;
    x86_64) goarch=amd64; cc="x86_64-linux-android$API-clang" ;;
    x86) goarch=386; cc="i686-linux-android$API-clang" ;;
    *) echo "error: unknown ABI $abi" >&2; exit 1 ;;
  esac

  echo "==> building libvpncore.so for $abi"
  mkdir -p "$OUT/$abi"
  (
    cd "$SRC"
    # 16 KB page alignment is required for Android 15+ devices.
    CGO_ENABLED=1 GOOS=android GOARCH="$goarch" GOARM="$goarm" \
      CC="$TOOLCHAIN/$cc" \
      go build -buildmode=c-shared -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid= -extldflags=-Wl,-z,max-page-size=16384" \
        -o "$OUT/$abi/libvpncore.so" .
  )
  rm -f "$OUT/$abi/libvpncore.h"
done

echo "done: $OUT"
