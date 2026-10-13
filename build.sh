#!/bin/bash
#
# Сборка build/Notchlimits.app из Swift Package.
#
set -euo pipefail
cd "$(dirname "$0")"

# Одно имя везде: исполняемый файл, .app и CFBundleName/CFBundleDisplayName —
# так же, как репозиторий на GitHub.
APP_NAME="Notchlimits"
BUNDLE_ID="dev.ustinoff.notchlimits"
SIGNING_IDENTITY="2A1CD7C372968E01732ED7B26AC5CBB9F4014D33"
# Версия: переменная окружения важнее файла VERSION (её задаёт релизный workflow).
VERSION="${NOTCHLIMITS_VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
BUILD_NUMBER="${NOTCHLIMITS_BUILD_NUMBER:-$VERSION}"
APP="build/${APP_NAME}.app"

echo "==> Notchlimits ${VERSION}"
echo "==> swift build -c release"
swift build -c release

echo "==> сборка бандла ${APP}"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks"
cp ".build/release/${APP_NAME}" "$APP/Contents/MacOS/${APP_NAME}"
FRAMEWORK="$APP/Contents/Frameworks/Sparkle.framework"
ditto ".build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework" "$FRAMEWORK"

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
	<string>${BUILD_NUMBER}</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>${APP_NAME}</string>
	<key>NSSupportsAutomaticTermination</key>
	<false/>
	<key>NSSupportsSuddenTermination</key>
	<false/>
	<key>SUFeedURL</key>
	<string>https://github.com/ziqq/Notchlimits/releases/latest/download/appcast.xml</string>
	<key>SUPublicEDKey</key>
	<string>MdPhsOYcTVln6CAvBuyTH0i0sT95jv1gUhm4JaRWis4=</string>
	<key>SUEnableAutomaticChecks</key>
	<false/>
	<key>SUVerifyUpdateBeforeExtraction</key>
	<true/>
	<key>SURequireSignedFeed</key>
	<true/>
</dict>
</plist>
PLIST

IDENTITY="${NOTCHLIMITS_CODE_SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
	if security find-identity -v -p codesigning 2>/dev/null | grep -q "$SIGNING_IDENTITY"; then
		IDENTITY="$SIGNING_IDENTITY"
	else
		IDENTITY="-"
	fi
fi
if [ "$IDENTITY" != "$SIGNING_IDENTITY" ] && [ "$IDENTITY" != "-" ]; then
	echo "==> ошибка: для Notchlimits разрешён только сертификат a.a.ustinoff ($SIGNING_IDENTITY)"
	exit 1
fi

SIGN_ARGS=(--force --sign "$IDENTITY" --timestamp=none --preserve-metadata=identifier,entitlements)
if [ "$IDENTITY" != "-" ]; then
	echo "==> codesign сертификатом Apple Development ($IDENTITY)"
	SIGN_ARGS+=(--options runtime)
else
	echo "==> локальная сборка ad-hoc"
	echo "    ВНИМАНИЕ: при ad-hoc подписи хэш кода меняется при каждой пересборке,"
	echo "    поэтому Keychain будет заново спрашивать доступ к Claude Code-credentials."
fi

for HELPER in "$FRAMEWORK/Versions/B/XPCServices/"*.xpc "$FRAMEWORK/Versions/B/Updater.app"; do
	codesign "${SIGN_ARGS[@]}" "$HELPER" >/dev/null
done
codesign "${SIGN_ARGS[@]}" "$FRAMEWORK/Versions/B/Autoupdate" >/dev/null
codesign "${SIGN_ARGS[@]}" "$FRAMEWORK" >/dev/null
codesign "${SIGN_ARGS[@]}" --identifier "$BUNDLE_ID" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"
if [ "$IDENTITY" != "-" ]; then
	python3 scripts/verify_signing.py "$APP" --identity "$SIGNING_IDENTITY"
fi
echo "==> готово: $APP"
