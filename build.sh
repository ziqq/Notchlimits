#!/bin/bash
#
# Сборка build/NotchLimits.app из Swift Package.
#
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="NotchLimits"
BUNDLE_ID="com.ziqq.notchlimits"
# Версия: переменная окружения важнее файла VERSION (её задаёт релизный workflow).
VERSION="${NOTCHLIMITS_VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
APP="build/${APP_NAME}.app"

echo "==> NotchLimits ${VERSION}"
echo "==> swift build -c release"
swift build -c release

echo "==> сборка бандла ${APP}"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp ".build/release/${APP_NAME}" "$APP/Contents/MacOS/${APP_NAME}"

# Иконка. Перерисовать: swift Tools/make-icon.swift
if [ -f Resources/AppIcon.icns ]; then
	cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
else
	echo "==> Resources/AppIcon.icns не найден, собираю без иконки"
fi

# Локализации: Resources/<язык>.lproj → Contents/Resources/<язык>.lproj
LOCALES=""
for LPROJ in Resources/*.lproj; do
	[ -d "$LPROJ" ] || continue
	cp -R "$LPROJ" "$APP/Contents/Resources/"
	LANG_CODE="$(basename "$LPROJ" .lproj)"
	LOCALES="${LOCALES}		<string>${LANG_CODE}</string>
"
done
echo "==> локализации: $(echo "$LOCALES" | grep -c string) шт."

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleLocalizations</key>
	<array>
${LOCALES}	</array>
	<key>CFBundleExecutable</key>
	<string>${APP_NAME}</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIconName</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>${BUNDLE_ID}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${APP_NAME}</string>
	<key>CFBundleDisplayName</key>
	<string>${APP_NAME}</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${VERSION}</string>
	<key>CFBundleVersion</key>
	<string>${VERSION}</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>NotchLimits</string>
	<key>NSSupportsAutomaticTermination</key>
	<false/>
	<key>NSSupportsSuddenTermination</key>
	<false/>
</dict>
</plist>
PLIST

IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep '"Apple Development' | head -1 | awk '{print $2}' || true)"

if [ -n "$IDENTITY" ]; then
	echo "==> codesign сертификатом Apple Development ($IDENTITY)"
	codesign --force --sign "$IDENTITY" \
		--identifier "$BUNDLE_ID" \
		--options runtime \
		--timestamp=none \
		"$APP" >/dev/null
else
	echo "==> сертификат Apple Development не найден, подписываю ad-hoc"
	echo "    ВНИМАНИЕ: при ad-hoc подписи хэш кода меняется при каждой пересборке,"
	echo "    поэтому Keychain будет заново спрашивать доступ к Claude Code-credentials."
	codesign --force --sign - --identifier "$BUNDLE_ID" "$APP" >/dev/null
fi

codesign --verify --deep --strict "$APP"
echo "==> готово: $APP"
