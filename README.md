# Notchlimits

**English** · [Русский](README.ru.md)

A panel that slides out of the MacBook notch with **Claude Code** and **Codex** (OpenAI) rate limits. Native macOS app in Swift/SwiftUI, built with one script — no Xcode project.

![Expanded panel](docs/panel.png)

*Screenshots use generated sample data — the emails, the `Opus` window and the percentages are illustrative, not a real account.*

## Features

- One column per account — every Claude and Codex profile at once.
- Limit windows aren't hardcoded: whatever the API returns is drawn, including windows that didn't exist yesterday.
- Lives in the notch — the collapsed panel matches the cutout pixel-for-pixel and stays invisible.
- Works without a notch too (external display, Mac mini, iMac).
- **Keep Awake** (context menu): keep the Mac from sleeping and keep the display on — two independent modes on standard
  IOKit power assertions, no admin password. Their state shows as chips in the panel footer.
- **Power and port indicators** in the panel footer: charge and battery temperature, charging port (MagSafe / USB-C)
  with input watts, USB-C ports in use. Hover a chip for the charger contract, port protocols, battery health. Read from
  IORegistry while the panel is open; the battery chip is hidden without a battery. Right-click → **Settings** → **Show telemetry**
  hides these indicators and stops polling them. The choice survives restarts; telemetry is on by default.
  Click an indicator for details, or open the panel with the hotkey and reach it with **Tab**. On narrow panels,
  the indicators occupy a separate row so the update caption stays intact.
- Notifications when any window crosses 80 % and 95 %, and when a heavily-used window resets and frees up.
- A burn-rate forecast: if the current pace would hit 100 % before the window resets, the row shows when.
- Updates through Sparkle: **Check for updates** fetches a signed appcast from GitHub, verifies the update archive with Ed25519, installs it and relaunches. Checks remain manual.
- Survives restarts: last percentages are cached and shown with an age note.
- One account's error or rate limit never touches the other columns.
- UI in 14 languages, picked from the system language.
- Long window titles wrap instead of truncating; the panel grows to fit.

## Requirements

- macOS 13+
- Swift 5.9+ (Xcode Command Line Tools)
- `claude` and/or `codex` CLI, logged in

## Build & run

```bash
./build.sh && open build/Notchlimits.app
```

`build.sh` runs `swift build -c release`, assembles `build/Notchlimits.app` with an `Info.plist` (`LSUIElement = true`, `CFBundleIdentifier = dev.ustinoff.notchlimits`) and signs it. The app is background-only — no Dock or menu-bar icon; quit from the panel's context menu.

Restart after a rebuild:

```bash
pkill -x Notchlimits; open build/Notchlimits.app
```

A drag-to-Applications DMG (the app plus an `Applications` shortcut) is packed from the built bundle:

```bash
./scripts/build_dmg.sh   # → build/Notchlimits-<version>.dmg
```

## Usage

| Action | Result |
| --- | --- |
| Hover the notch | Panel expands |
| Move the cursor away | Closes after 0.1 s |
| Click the panel | Pin it open |
| Click again, click outside, **Esc** | Close |
| **⌘P** (configurable) | Toggle from any app |
| Right-click | Context menu |

On a notch-less screen the panel sits top-center; collapsed, it's a small pill with one dot per account, colored by that account's busiest window:

![Collapsed panel](docs/collapsed.png)

The context menu is separated into groups: **About Notchlimits** (native panel with the running version); **Refresh** (force-poll, bypassing timers and backoff), **Settings**, **Check for updates…** (signed updates through Sparkle); **Claude account**, **Codex account** (switch the app's account or **Add account…**), **Remove account** (with a confirmation — deletes the account's login and profile); **Hide column**, **Rename column**, **Show hidden columns**; **Quit Notchlimits**. **Settings** contains **Show telemetry**, **Keep Mac awake**, **Keep display on**, **Launch at login** (`SMAppService`), **Switch CLI**, and **Hotkey**.

### Claude account switching and renewal

**Settings → Switch CLI** is on by default: switching a Claude Desktop account also selects its existing Claude Code profile. Turn it off to switch Desktop alone; the CLI keeps its previous selection. This does not change Codex switching. The exact config-path spelling is preserved, including trailing slashes and symlink variants, so the CLI selects the same Keychain service. The prepared CLI selection is published only after Desktop opens successfully; a failed launch leaves CLI routing unchanged. Before publication, the account must still exist and its exact CLI profile path must still match; removal during launch preserves the previous CLI selection and reports the CLI failure while retaining the successful Desktop marker. The CLI setting is checked again when launch completes, including when enabled during launch. Simultaneous switches of the same application are rejected. Successful account removal retires and removes its managed Desktop data directory. Re-adding the same CLI profile uses a fresh Desktop directory, even if an old Desktop process recreates the retired path; an already-prepared launch keeps its actual Desktop marker and cannot select the replacement CLI account.

On the first CLI switch, Notchlimits appends a source line to `.zshrc` (for bash, `.bashrc` and its existing login startup file) without replacing existing contents. Open a new terminal once to load it. The shell function reads the selected profile on each new `claude` invocation, including when Notchlimits is closed. Running CLI sessions keep their account, and an explicitly set `CLAUDE_CONFIG_DIR` or `CLAUDE_SECURESTORAGE_CONFIG_DIR` takes precedence. A missing selected profile fails instead of silently using another account. Other shells are not supported for CLI switching; Desktop-only switching remains available.

Sleeping Claude profiles renew directly over HTTP using their existing credentials, without another Notchlimits login or a background Claude process. With Claude Code 2.1.278 or later, renewal holds both native OAuth locks from the credential reread through persistence, maintains their heartbeats and takes the storage lock for each write. A busy or lost lock defers renewal. If saving rotated credentials fails, renewal keeps the OAuth locks and retries only persistence. Normal quit waits for active renewal to finish; if credentials cannot be saved within 25 seconds, quit is cancelled and the write retries continue. A stable sidecar OS file lock proves a live Notchlimits owner. An immutable extended-attribute marker is set on a private empty directory before publishing the native lock path atomically without replacement. A crash during preparation cannot leave an unmarked native lock; the marker needs no heartbeat rewrites and keeps native rmdir recovery compatible. Previous JSON owner records remain readable. Recovery reads the marker through a pinned directory descriptor and checks that the native path still names that inode before removal. Unmarked CLI locks and replacement owners are preserved. Explicit account removal takes both OAuth locks and the storage lock before deleting credentials. A native writer makes removal fail with a retryable busy message; a renewal lease already held by Notchlimits can be borrowed for the synchronous deletion. If the CLI directory cannot be identified, removal fails instead of deleting outside the lock protocol. Successful explicit account removal discards its pending credentials and invalidates late refresh responses; failed deletion retains the grant and its save retries. A replacement login waits for the removed generation to finish, then resolves its own credentials; concurrent callers share only that generation's result. OAuth and storage lock acquisition cannot recreate a removed extra profile; only the main config directory may be bootstrapped. Usage results belong to the column generation that started the request, so a late reply cannot overwrite a replacement account's column, cache, history or schedule. Keychain operations inside the critical section cannot request user interaction. Network errors and regional/proxy 403 responses preserve the login. This coordinates cooperating clients through the CLI's lease protocol; it does not provide an atomic Keychain compare-and-swap against arbitrary external writers or a process suspended beyond the leases.

## Column names

The primary profile of both providers is labeled `main`, so headers don't diverge into "CLAUDE · main" vs "CODEX · default". Extra profiles take their folder name. Rename any column via right-click → **Rename column**; an empty field restores the profile name. The name lives in `UserDefaults` separately from the column id, so renaming doesn't drop the cache or notification state.

## Hotkey

Default is **⌘P**. Being a global hotkey, it overrides "Print" elsewhere while Notchlimits runs — so it's configurable via right-click → **Settings** → **Hotkey**:

- **Change…** captures the next keypress. At least one of ⌘, ⌥, ⌃ is required, or a global hotkey would swallow ordinary input.
- **Default (⌘P)** / **Disable** (leaves only hover and click).

The binding uses the physical key code, so switching layout doesn't affect it. If the combo is already taken, the panel says so and keeps the previous setting.

## Languages

14 languages: English, Russian, Ukrainian, German, French, Spanish, Portuguese (Brazil), Italian, Polish, Turkish, Japanese, Korean, Simplified and Traditional Chinese. Chosen from the system's preferred-languages list; English is the fallback. LTR only — the layout isn't mirrored, so Hebrew and Arabic are intentionally omitted.

Check any language without changing system settings:

```bash
./build/Notchlimits.app/Contents/MacOS/Notchlimits -AppleLanguages "(ja)"
```

Translations have a single source of truth — `Tools/make-strings.py` — which lays them out into `Resources/<lang>.lproj/Localizable.strings` and fails if any key is missing or extra. Durations and the percent sign are localized too: `42 %` in French, `42%` in Japanese, `%42` in Turkish.

## Panel size

Width is 250 pt per column, no less than 500 pt and no wider than the screen minus 40 pt. Height adapts to content: titles like "GPT-5.3-Codex-Spark · Weekly window" wrap rather than truncate — the layout reports its real height and the window resizes to it, between 252 pt and 560 pt.

## Column states

![Column states](docs/states.png)

- **Fresh data** — progress bar and time to reset. Green up to 60 %, yellow 60–85 %, red above.
- **`re-auth: run claude` / `codex`** — no usable token and no way to renew it: the refresh token is gone or rejected (Claude), or auth is missing/expired (Codex).
- **`data N min ago`** — grey note: no fresh response right now (rate limit, network, just launched); last known values shown.
- **`updating…`** — no data yet.

A re-auth or error message is shown **on top of** cached numbers, not instead of them — otherwise an expired token just looks like old percentages and there's no hint that you need to log in again.

Each row keeps a short local history of its percentage (in `UserDefaults`, no tokens). From those samples a **burn-rate forecast** is computed by least-squares slope: if the current pace would reach 100 % *before* the window resets, the reset line gains a `· full ≈ <time>` suffix — yellow, or red when it's under 45 minutes away. The reset countdown itself stays visible, and hovering gives the exact reset time. Flat or falling windows, and ones that comfortably reset first, show just the reset line. The forecast needs a few samples spanning at least five minutes, so it appears a little after launch, not immediately.

Below the windows, whatever extra numbers the endpoint returns are listed: credit balance, early resets available, usage billed beyond the plan. Lines with a zero or missing value are omitted.

## Switching the active account

Right-click → **Claude account** or **Codex account** to choose a Desktop account. Claude Desktop keeps a separate Electron data directory per account. **Switch CLI** controls whether the same action selects an existing Claude Code profile, as described above. Codex swaps only credentials in the base home’s configured backend, preserving its projects and threads. Its Desktop and CLI selection remains independent of the Claude **Switch CLI** setting.

## Multiple accounts

Menu → **Add Claude account…** or **Add Codex account…**. The dialog asks for a short profile name and previews the result live (`Folder: ~/.claude-profiles/work`); the Create button stays disabled until the name is valid. The panel then creates `~/.claude-profiles/<name>` (or `~/.codex-profiles/<name>`), drops a `login.command` there and opens it in Terminal.app. Passwords are never seen or asked — the CLI handles login. New profiles are picked up automatically, no restart. A profile whose login never completed shows up in **Remove account** as “… — not signed in”, so an accidentally created one can still be deleted.

The equivalent by hand:

```bash
CLAUDE_CONFIG_DIR=~/.claude-profiles/work claude
CODEX_HOME=~/.codex-profiles/work codex login
```

Binaries are found not via `PATH` (nearly empty for a GUI app) but at known install locations: `~/.local/bin`, `~/.claude/local`, `/opt/homebrew/bin`, `/usr/local/bin`, the VS Code `anthropic.claude-code-*` extension, and `/Applications/ChatGPT.app` for `codex`.

## Data sources

**Claude Code.** Credentials are read from Keychain (generic password, service `Claude Code-credentials`; extra profiles as `Claude Code-credentials-<hash>` where the hash is the sha256 of `CLAUDE_CONFIG_DIR`), with the native macOS `.credentials.json` fallback under the CLI config directory. File-backed profiles participate in discovery, renewal, Desktop/CLI selection and explicit removal. Renewal stays on the backend that supplied the grant, preserves unknown fields and keeps file permissions at 0600. Removing the primary account deletes both credential stores while preserving its other CLI configuration.

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <accessToken>
anthropic-beta: oauth-2025-04-20
User-Agent: claude-code/<CLI version from the install path>
```

The native `User-Agent` matters — without it the endpoint returns 429 far more often. Any field-object with a numeric `utilization` counts as a window, so new windows appear on their own, including internal model code-names. Windows that are inert — `0 %` **and** no reset date, like the `nimbus_quill` placeholder the endpoint returns in reserve — are hidden until they come alive, so they don't clutter the column with a row you can't act on. Titles: `five_hour`/`seven_day` get friendly labels, known prefixes expand (`seven_day_opus` → "Weekly window · Opus", shown to Max/Opus accounts), the rest are shown as words rather than raw snake_case. `extra_usage` (pay-as-you-go beyond the plan) is not a window — it's spend, not a share of a quota — so it goes to the stats line, but **only while `is_enabled` is true**: `used_credits` is then a live spend meter (shown as money, since the amount is minor units — `10308` at `decimal_places: 2` is `$103.08`, plus the `monthly_limit` cap when set). When extra usage is off (`out_of_credits`), the same number is just historical depleted credits and would read as an active charge, so it's hidden.

The subtitle is `plan · email`, matching Codex. The plan (`Pro`, `Max`) comes from the credential record; the email isn't in either endpoint, so it's read straight from the CLI's config file — `~/.claude.json` (or `<CLAUDE_CONFIG_DIR>/.claude.json` for extra profiles), field `oauthAccount.emailAddress`. That's a plain file read, no Keychain and no subprocess, so it never triggers a password prompt.

### Token refresh

A Claude access token lives a few hours. If the CLI isn't run, it expires and the column freezes — so when the token is expired and the credential record holds a live `refreshToken`, the panel renews it itself, exactly as the CLI does:

```
POST https://platform.claude.com/v1/oauth/token
Content-Type: application/json

{"grant_type": "refresh_token", "refresh_token": "…",
 "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e", "scope": "<scopes from the entry>"}
```

`client_id` is Claude Code's public client identifier — no secret involved. Scopes are taken from the entry rather than hardcoded, so the set is never silently narrowed.

Three details that matter:

- **The refresh token rotates.** When the response carries a new one, the old one stops working, so the result is written back to the original credential backend — not writing it back would break the CLI's own login. The write merges into a *freshly read* entry, preserving `subscriptionType`, `rateLimitTier` and every field the panel doesn't know about.
- **Renewed credentials are saved when the server returns a refresh token.** Otherwise the new access token stays in memory. A write preflight runs before the HTTP refresh; if a quiet Keychain update is not allowed, renewal is deferred before spending the refresh token.
- **A 401 marks that exact token as rejected**, so the next cycle renews instead of re-reading the same dead token from the Keychain. If the entry meanwhile holds a different token, the CLI refreshed first and that one is used.

Renewal happens on expiry or after a usage 401. Automatic Claude renewal requires Claude Code 2.1.278 or newer and the native OAuth and storage locks described above. Profiles have independent locks. Older or unidentified CLI versions retain usage polling with valid tokens and require CLI login after expiry.

**Codex.** The root `cli_auth_credentials_store` setting selects `file`, `keyring` or `auto` for each `CODEX_HOME`. The default is `file`. On macOS, direct Keychain storage uses the native `Codex Auth` service and `cli|` plus the first 16 SHA-256 hex characters of the canonical home path. `auto` reads Keychain first and falls back to `auth.json` when absent or unreadable. Renewal writes back to the backend that supplied the grant; a denied Keychain update keeps rotated credentials pending and never issues another refresh POST. A renewal reserves its profile from the initial read until persistence succeeds or the response is discarded. Desktop/CLI switching reports a retryable busy error while either affected profile has an in-flight refresh or unsaved rotation. Successful removal retires the reservation, so a late response cannot overwrite pending credentials of a re-added profile; denied removal preserves them. Discovery checks metadata without reading Keychain secrets. Configuration uses a full TOML decoder, including multiline strings, quoted/dotted keys and inline tables. System config, legacy managed config, local requirements and forced macOS preferences are respected; per-invocation CLI overrides are outside this process. The opt-in encrypted secrets backend is rejected rather than confused with direct Keychain storage. `ephemeral` is process-local: Notchlimits cannot read another process’s memory, ignores leftover persistent credentials and refuses persistent switching in this mode. No extra Notchlimits login is introduced. Auth from the selected backend; `apikey` mode can't reach the usage endpoint — ChatGPT login is required. Token lifetime from the JWT `exp` claim, email for the column subtitle from `id_token`.

Normal quit drains both Claude and Codex renewals, including accepted refresh requests and unsaved rotated grants. If persistence still fails after 25 seconds, quit is cancelled; only persistence is retried, without another refresh POST. Codex switching verifies the owner with a strict Keychain read: temporary Keychain errors stop the switch instead of archiving the current grant as an unrelated login.

Removing the selected or primary Codex account waits for Desktop to exit before changing base credentials. A refused exit preserves credentials, and concurrent Codex switches/removals are rejected until removal finishes. Managed Claude/Codex profile directories are moved to a hidden sibling before credential deletion. A refused move preserves the login; a refused credential deletion restores the directory. Failed cleanup may leave a hidden logged-out directory, while the original name remains available for re-addition.

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <access_token>
ChatGPT-Account-ID: <account_id>
User-Agent: codex_cli_rs/<version>
```

`rate_limit.primary_window`, `secondary_window` and every `additional_rate_limits[]` are drawn — the latter prefixed by `limit_name` or `metered_feature`. Those extra entries are per-model buckets the API reports separately from the main quota (e.g. `GPT-5.3-Codex-Spark`, a specific model tier); the app shows whatever names come back, so the list tracks OpenAI's without code changes. Window title derives from `limit_window_seconds` (`18000` → 5-hour, `604800` → weekly). The subtitle is `plan_type · email`; `credits.balance` and `rate_limit_reset_credits.available_count` become stats lines (the count of available “full reset” credits, matching the ChatGPT app; `applicable_available_count` is ignored — it stays 0 even when every credit is available).

## Refresh & resilience

- Each account polls independently every 3 minutes, staggered 4 s apart — not in a burst.
- Expanding the panel refreshes only columns older than two minutes.
- 10 s request timeout; usage requests retry once on 5xx and network errors. Refresh POSTs do not retry automatically.
- **HTTP 429 isn't an error.** Backoff comes from `Retry-After`, else grows 2 → 4 → 8 → 15 min; last data stays with an age note.
- Last successful values are cached in `UserDefaults` and shown right after a restart.
- A threshold notification fires once per window and re-arms when `resets_at` changes (a new window began). When a window that reached ≥ 50 % rolls over, a "limit reset" notification fires — you were throttled, now you're free.

## Permissions

- **Keychain.** On the first Claude refresh macOS asks for access to `Claude Code-credentials` — click **Always Allow**. The Keychain is reread each cycle to detect a new CLI login; valid tokens avoid unnecessary refresh requests. Writes inside renewal never display a dialog.
- **Signing.** Release builds use the pinned Apple Development certificate for `a.a.ustinoff@gmail.com`. `build.sh` selects that identity, including for Sparkle helpers. Local builds without it use ad-hoc signing. Moving from ad-hoc or another identity may require a fresh Keychain grant; subsequent releases keep the same certificate requirement.
- **Notifications.** Requested on first launch.
- **No Accessibility needed** — the hotkey uses Carbon `RegisterEventHotKey`, and login runs via a `.command` file, not AppleScript.

## Privacy

The app makes no automatic request beyond the usage endpoints and token renewal described above. Update checks are manual: Sparkle fetches the signed `appcast.xml` from GitHub on click, and downloads the update archive only after you choose **Install Update**. Automatic checks and system profiling are disabled by default. Archive signatures are verified before extraction. Tokens are never logged. Refreshed Claude tokens are written into the same Keychain entry or native fallback file the CLI already owns; Codex writes follow its configured storage mode. The `claude` binary is never run (running it makes the CLI read its credentials via `/usr/bin/security`, popping a Keychain prompt) — its version for the User-Agent comes from the install path, and the account email from the CLI's `~/.claude.json`. Only `codex --version` is executed automatically. Codex credentials remain in the configured file or direct Keychain backend; file credentials keep mode 0600. Switching can transfer credentials between the explicitly configured source and destination backends. Primary-account backups retain their original backend. Only settings and last percentages (with reset times) go to `UserDefaults`, without a single token. Usage requests use an ephemeral `URLSession`, with no cookies or disk cache.

## CI & releases

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push to `main`, every PR, and on demand: regenerate translations and check `Resources/*.lproj` didn't drift, `plutil -lint` the strings, regression-test the generator against all committed translations and repeat generation, verify the icon generator produces a valid `.icns`, `./build.sh`, self-test, and bundle checks (`Info.plist` validity, signature, `LSUIElement`, icon, all 14 locales), then upload the `.app` artifact.

The self-test (`NOTCHLIMITS_SELFTEST=1`) needs no network, Keychain, or window server, and covers Claude/Codex parsing (garbage, `null` windows, unknown keys), window order and titles, JWT claims, time/age/percent formatting, cache and hotkey serialization, and localization completeness — matching key sets, no empty values, and **format specifiers matching English**, or `String(format:)` would crash in another language.

Run the regression suite with `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s Tools -p 'test_*.py'`.
It compiles the production Swift sources with synthetic API/Keychain boundaries and temporary profiles, checks the
release steps before signing, and verifies that reset and stale-age labels change without new usage data.
The two UI checks require a macOS desktop session; the suite makes no API requests and uses no real credentials.

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs on a pre-created `v*` tag or manually from `main` with an existing tag's version. A trusted main policy verifies the tag and its main push CI; signing requires approval in the protected `release` environment. The signing job checks out the verified SHA, imports the pinned Apple Development certificate into a temporary keychain, builds and self-tests, packages a DMG and ZIP, signs the DMG and appcast with Sparkle, and publishes them with `SHA256SUMS.txt`. Publication rechecks the remote tag. Sparkle uses the DMG; the ZIP remains for migration from the previous updater. `CFBundleVersion` uses the workflow run number. See [release signing](docs/RELEASE.md) for the required secrets and key handling.

Version comes from `NOTCHLIMITS_VERSION`, else the [`VERSION`](VERSION) file:

```bash
NOTCHLIMITS_VERSION=1.2.0 ./build.sh    # build
git tag v1.2.0 && git push origin v1.2.0    # release
```

## Debug modes

Environment variables for running the binary directly (`./build/Notchlimits.app/Contents/MacOS/Notchlimits`):

| Variable | Effect |
| --- | --- |
| `NOTCHLIMITS_PROBE=1` | Checks hotkeys and the Claude parser, polls real accounts, prints results without GUI |
| `NOTCHLIMITS_RENDER=<dir>` | Renders `panel.png`, `states.png`, `collapsed.png` — the images in this README |
| `NOTCHLIMITS_SNAPSHOT=<file.png>` | Snapshots the real panel window (no Screen Recording needed) |
| `NOTCHLIMITS_MOCK=1` | Mock data instead of providers |
| `NOTCHLIMITS_SELFTEST=1` | Offline self-test for CI, nonzero exit on failure |
| `-AppleLanguages "(ja)"` | An argument, not a variable: launch in a chosen language |

## Icon

`Resources/AppIcon.icns` isn't stored as-is — it's drawn in code:

```bash
swift Tools/make-icon.swift
```

The script renders all ten iconset sizes and assembles the `.icns` via `iconutil`, using the same bar palette as `Theme.swift`.

## Architecture

```
Sources/Notchlimits/
  App/        entry point, delegate, context menu, debug modes
  Notch/      notch geometry, NSPanel, hover logic and animations
  UI/         SwiftUI panel layout
  Model/      column and limit-window types
  Providers/  Claude (Keychain + api.anthropic.com), Codex (file/Keychain + chatgpt.com)
  Core/       poll scheduler, cache, history + burn-rate, notifications, hotkeys, account setup
Tools/
  make-strings.py   translations for every language
  make-icon.swift   app icon
```

A few spots where the implementation is subtle and needs care:

- `NotchPanel.constrainFrameRect(_:to:)` returns the frame unchanged. Otherwise AppKit shoves the window out from under the menu bar and it stops hugging the notch.
- Window level is `.popUpMenu`, not `.statusBar + 1`: on recent macOS the menu bar draws higher and the panel would fall behind menu items.
- `NotchHostingView.safeAreaInsets` is zeroed: the window already sits over the cutout, and an extra safe area would push content down by the notch height again.
- On close, the window frame shrinks 0.35 s after the animation starts, so its last frames aren't clipped.

## License

Notchlimits is free software under the [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`). Copyright (C) 2026 Anton Ustinoff.
