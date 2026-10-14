# Release signing

Notchlimits uses Sparkle 2.10.0 for manual update checks. The app verifies the
signed appcast and the archive signature before extraction. The feed remains a
GitHub release asset; no separate update server is needed.

Tags must point to a commit in `main`; manual runs must select `main`.
Before importing signing keys, the workflow requires the push CI run for the
exact release commit and waits for it to finish successfully (up to 20 minutes).
A missing, failed or cancelled CI run prevents publication.

The app and Sparkle helpers use the Apple Development certificate for
`a.a.ustinoff@gmail.com`, SHA1 `2A1CD7C372968E01732ED7B26AC5CBB9F4014D33`.
The build rejects a different signing identity for release builds. Local CI
builds without the certificate may use ad-hoc signing. Apple Development signing
does not provide Developer ID notarization.

The Release workflow requires these repository Actions secrets:

- `APPLE_SIGNING_CERTIFICATE_BASE64`: the selected certificate and private key
  exported as an encrypted PKCS12, then base64-encoded.
- `APPLE_SIGNING_CERTIFICATE_PASSWORD`: the PKCS12 password.
- `SPARKLE_PRIVATE_KEY`: the separate Notchlimits Ed25519 signing key.

The Sparkle key belongs to the Keychain account `dev.ustinoff.notchlimits`.
Its public key is embedded in the generated `Info.plist`. Keep a secure backup
of the private key; it is required to sign later updates. Never commit private
keys, certificates containing private keys, or passwords. Pass signing keys
through standard input in CI rather than command-line arguments.

The workflow imports the Apple certificate into a temporary runner keychain,
signs the embedded code and app, verifies the pinned certificate, and cleans up
the keychain. Sparkle's pinned package tools sign the DMG and `appcast.xml`.
Before publication, the workflow verifies both signatures and checks that
same-size modified copies of the feed and DMG are rejected.
`CFBundleVersion` uses the workflow run number to order releases.

Release assets include the DMG, signed appcast, ZIP and `SHA256SUMS.txt`. Sparkle
uses the DMG. The ZIP is retained so existing versions using the previous
GitHub/SHA-256 updater can install the first Sparkle-enabled release.
