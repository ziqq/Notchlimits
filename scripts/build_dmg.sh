#!/bin/bash
#
# Упаковка build/Notchlimits.app в DMG: приложение + ярлык на /Applications,
# чтобы установка была «перетащи в папку».
#
#   ./scripts/build_dmg.sh              # соберёт .app, если его ещё нет
#   NOTCHLIMITS_VERSION=1.2.0 ./scripts/build_dmg.sh
#
# Sparkle использует DMG; ZIP остаётся для перехода со старого установщика.
#
set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="Notchlimits"
VOLUME_NAME="Notchlimits"
APP="build/${APP_NAME}.app"
VERSION="${NOTCHLIMITS_VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"

[ -d "$APP" ] || ./build.sh

STAGING="build/dmg"
rm -rf "$STAGING"
mkdir -p "$STAGING"
# ditto, а не cp: сохраняет подпись бандла и расширенные атрибуты.
ditto "$APP" "$STAGING/${APP_NAME}.app"
ln -s /Applications "$STAGING/Applications"

DMG="build/${APP_NAME}-${VERSION}.dmg"
rm -f "$DMG"
hdiutil create -volname "$VOLUME_NAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGING"

# Подпись бандла внутри образа должна пережить упаковку.
MOUNT=$(mktemp -d)
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT" "$DMG" >/dev/null
trap 'hdiutil detach "$MOUNT" -quiet >/dev/null 2>&1 || true; rmdir "$MOUNT" 2>/dev/null || true' EXIT
codesign --verify --deep --strict "$MOUNT/${APP_NAME}.app"
[ -L "$MOUNT/Applications" ]

echo "==> готово: ${DMG}"
