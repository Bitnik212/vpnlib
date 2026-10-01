#!/usr/bin/env bash
# Builds VpnCore.xcframework (static libvpncore.a for iOS devices and the
# simulator) into native/build/ios. macOS with Xcode and Go is required.
#
# Usage: native/build-ios.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/vpncore"
OUT="${VPNCORE_IOS_OUT:-$ROOT/build/ios}"
MIN_IOS="${IOS_MIN_VERSION:-15.0}"
WORK="$OUT/work"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: iOS builds require macOS with Xcode" >&2
  exit 1
fi

rm -rf "$WORK" "$OUT/VpnCore.xcframework"
mkdir -p "$WORK"

# build <name> <sdk> <goarch> <clang target>
build() {
  local name="$1" sdk="$2" goarch="$3" target="$4"
  local sdk_path
  sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
  echo "==> building libvpncore.a for $name"
  mkdir -p "$WORK/$name"
  (
    cd "$SRC"
    CGO_ENABLED=1 GOOS=ios GOARCH="$goarch" \
      CC="$(xcrun --sdk "$sdk" --find clang)" \
      CGO_CFLAGS="-isysroot $sdk_path -target $target" \
      CGO_LDFLAGS="-isysroot $sdk_path -target $target" \
      go build -buildmode=c-archive -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid=" \
        -o "$WORK/$name/libvpncore.a" .
  )
}

build ios-arm64 iphoneos arm64 "arm64-apple-ios$MIN_IOS"
build ios-sim-arm64 iphonesimulator arm64 "arm64-apple-ios$MIN_IOS-simulator"
build ios-sim-x86_64 iphonesimulator amd64 "x86_64-apple-ios$MIN_IOS-simulator"

mkdir -p "$WORK/ios-sim"
lipo -create "$WORK/ios-sim-arm64/libvpncore.a" "$WORK/ios-sim-x86_64/libvpncore.a" \
  -output "$WORK/ios-sim/libvpncore.a"

mkdir -p "$WORK/headers"
cp "$SRC/include/vpncore.h" "$WORK/headers/"
cat > "$WORK/headers/module.modulemap" <<'MAP'
module VpnCore {
    header "vpncore.h"
    export *
}
MAP

xcodebuild -create-xcframework \
  -library "$WORK/ios-arm64/libvpncore.a" -headers "$WORK/headers" \
  -library "$WORK/ios-sim/libvpncore.a" -headers "$WORK/headers" \
  -output "$OUT/VpnCore.xcframework"

# Static libraries per Kotlin/Native target, used when linking test binaries.
mkdir -p "$OUT/iosArm64" "$OUT/iosSimulatorArm64"
cp "$WORK/ios-arm64/libvpncore.a" "$OUT/iosArm64/"
cp "$WORK/ios-sim-arm64/libvpncore.a" "$OUT/iosSimulatorArm64/"

echo "done: $OUT/VpnCore.xcframework"
