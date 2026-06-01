#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT_DIR/dist/APKShellInspector.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
ARM_BUILD_DIR="$ROOT_DIR/.build-universal/arm64"
INTEL_BUILD_DIR="$ROOT_DIR/.build-universal/x86_64"

swift build \
  -c release \
  --product APKShellInspector \
  --scratch-path "$ARM_BUILD_DIR" \
  --triple arm64-apple-macos13.0

swift build \
  -c release \
  --product APKShellInspector \
  --scratch-path "$INTEL_BUILD_DIR" \
  --triple x86_64-apple-macos13.0

ARM_BIN_PATH="$(find "$ARM_BUILD_DIR" -path '*/release/APKShellInspector' -type f | head -n 1)"
INTEL_BIN_PATH="$(find "$INTEL_BUILD_DIR" -path '*/release/APKShellInspector' -type f | head -n 1)"

if [[ -z "$ARM_BIN_PATH" || -z "$INTEL_BIN_PATH" ]]; then
  echo "universal release binaries not found" >&2
  exit 1
fi

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
lipo -create -output "$MACOS_DIR/APKShellInspector" "$ARM_BIN_PATH" "$INTEL_BIN_PATH"

cat > "$CONTENTS_DIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>zh_CN</string>
  <key>CFBundleExecutable</key>
  <string>APKShellInspector</string>
  <key>CFBundleIdentifier</key>
  <string>org.local.apkshellinspector</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>APKShellInspector</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP_DIR" >/dev/null
echo "Built $APP_DIR"
