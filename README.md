# NotchLimits

**English** · [Русский](README.ru.md)

A panel that slides out of the MacBook notch with **Claude Code** and **Codex** (OpenAI) rate limits. Native macOS app in Swift/SwiftUI, built with one script — no Xcode project.

![Expanded panel](docs/panel.png)

## Features

- One column per account — every Claude and Codex profile at once.
- Limit windows aren't hardcoded: whatever the API returns is drawn, including windows that didn't exist yesterday.
- Lives in the notch — the collapsed panel matches the cutout pixel-for-pixel and stays invisible.
- Works without a notch too (external display, Mac mini, iMac).
- Notifications when any window crosses 80 % and 95 %, and when a heavily-used window resets and frees up.
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
./build.sh && open build/NotchLimits.app
```

`build.sh` runs `swift build -c release`, assembles `build/NotchLimits.app` with an `Info.plist` (`LSUIElement = true`, `CFBundleIdentifier = com.ziqq.notchlimits`) and signs it. The app is background-only — no Dock or menu-bar icon; quit from the panel's context menu.

Restart after a rebuild:

```bash
pkill -x NotchLimits; open build/NotchLimits.app
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

The context menu covers: **Refresh** (force-poll, bypassing timers and backoff), **Add Claude / Codex account…**, **Hide** / **Rename column** submenus, **Show hidden columns**, **Hotkey** submenu, **Launch at login** (`SMAppService`), and **Quit**.

## Column names

The primary profile of both providers is labeled `main`, so headers don't diverge into "CLAUDE · main" vs "CODEX · default". Extra profiles take their folder name. Rename any column via right-click → **Rename column**; an empty field restores the profile name. The name lives in `UserDefaults` separately from the column id, so renaming doesn't drop the cache or notification state.

## Hotkey

Default is **⌘P**. Being a global hotkey, it overrides "Print" elsewhere while NotchLimits runs — so it's configurable via right-click → **Hotkey**:

- **Change…** captures the next keypress. At least one of ⌘, ⌥, ⌃ is required, or a global hotkey would swallow ordinary input.
- **Default (⌘P)** / **Disable** (leaves only hover and click).

The binding uses the physical key code, so switching layout doesn't affect it. If the combo is already taken, the panel says so and keeps the previous setting.

## Languages

14 languages: English, Russian, Ukrainian, German, French, Spanish, Portuguese (Brazil), Italian, Polish, Turkish, Japanese, Korean, Simplified and Traditional Chinese. Chosen from the system's preferred-languages list; English is the fallback. LTR only — the layout isn't mirrored, so Hebrew and Arabic are intentionally omitted.

Check any language without changing system settings:

```bash
./build/NotchLimits.app/Contents/MacOS/NotchLimits -AppleLanguages "(ja)"
```

Translations have a single source of truth — `Tools/make-strings.py` — which lays them out into `Resources/<lang>.lproj/Localizable.strings` and fails if any key is missing or extra. Durations and the percent sign are localized too: `42 %` in French, `42%` in Japanese, `%42` in Turkish.

## Panel size

Width is 250 pt per column, no less than 500 pt and no wider than the screen minus 40 pt. Height adapts to content: titles like "GPT-5.3-Codex-Spark · Weekly window" wrap rather than truncate — the layout reports its real height and the window resizes to it, between 252 pt and 560 pt.

## Column states

![Column states](docs/states.png)

- **Fresh data** — progress bar and time to reset. Green up to 60 %, yellow 60–85 %, red above.
- **`re-auth: run claude` / `codex`** — no token, expired, or a 401. The panel never refreshes tokens itself; the CLI does.
- **`data N min ago`** — grey note: no fresh response right now (rate limit, network, just launched); last known values shown.
- **`updating…`** — no data yet.

## Multiple accounts

Menu → **Add Claude account…** or **Add Codex account…**. The dialog asks for a short profile name and previews the result live (`Folder: ~/.claude-profiles/work`); the Create button stays disabled until the name is valid. The panel then creates `~/.claude-profiles/<name>` (or `~/.codex-profiles/<name>`), drops a `login.command` there and opens it in Terminal.app. Passwords are never seen or asked — the CLI handles login. New profiles are picked up automatically, no restart.

The equivalent by hand:

```bash
CLAUDE_CONFIG_DIR=~/.claude-profiles/work claude
CODEX_HOME=~/.codex-profiles/work codex login
```

Binaries are found not via `PATH` (nearly empty for a GUI app) but at known install locations: `~/.local/bin`, `~/.claude/local`, `/opt/homebrew/bin`, `/usr/local/bin`, the VS Code `anthropic.claude-code-*` extension, and `/Applications/ChatGPT.app` for `codex`.

## Data sources

**Claude Code.** Token read from Keychain (generic password, service `Claude Code-credentials`; extra profiles as `Claude Code-credentials-<hash>` where the hash is the sha256 of `CLAUDE_CONFIG_DIR`).

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <accessToken>
anthropic-beta: oauth-2025-04-20
User-Agent: claude-code/<installed CLI version>
```

The native `User-Agent` matters — without it the endpoint returns 429 far more often. Any field-object with a numeric `utilization` counts as a window (`extra_usage` ignored), so new windows appear on their own, including internal model code-names like `nimbus_quill`. Titles: `five_hour`/`seven_day` get friendly labels, known prefixes expand (`seven_day_opus` → "Weekly window · Opus"), the rest are shown as words rather than raw snake_case. The subtitle shows the plan (`Pro`, `Max`) from the Keychain entry — Anthropic exposes no email anywhere.

**Codex.** Auth from `~/.codex/auth.json` (or `$CODEX_HOME/auth.json`); `apikey` mode can't reach the usage endpoint — ChatGPT login is required. Token lifetime from the JWT `exp` claim, email for the column subtitle from `id_token`.

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <access_token>
ChatGPT-Account-ID: <account_id>
User-Agent: codex_cli_rs/<version>
```

`rate_limit.primary_window`, `secondary_window` and every `additional_rate_limits[]` are drawn — the latter prefixed by `limit_name` or `metered_feature`. Window title derives from `limit_window_seconds`.

## Refresh & resilience

- Each account polls independently every 3 minutes, staggered 4 s apart — not in a burst.
- Expanding the panel refreshes only columns older than two minutes.
- 10 s request timeout, one retry on 5xx and network errors.
- **HTTP 429 isn't an error.** Backoff comes from `Retry-After`, else grows 2 → 4 → 8 → 15 min; last data stays with an age note.
- Last successful values are cached in `UserDefaults` and shown right after a restart.
- A threshold notification fires once per window and re-arms when `resets_at` changes (a new window began). When a window that reached ≥ 50 % rolls over, a "limit reset" notification fires — you were throttled, now you're free.

## Permissions

- **Keychain.** On the first Claude refresh macOS asks for access to `Claude Code-credentials` — click **Always Allow**. The token is cached in memory until `expiresAt` or a 401, so Keychain isn't hit each cycle.
- **Signing.** With an "Apple Development" certificate, `build.sh` signs with it and the Keychain grant survives rebuilds. Without one, signing is ad-hoc — the code hash changes each build, so **Keychain re-asks after every rebuild**. The script warns about this.
- **Notifications.** Requested on first launch.
- **No Accessibility needed** — the hotkey uses Carbon `RegisterEventHotKey`, and login runs via a `.command` file, not AppleScript.

## Privacy

The app's only network requests are the two official usage endpoints above. Nowhere else. Tokens live in memory only — never logged, never written to disk, never cached. Only settings and last percentages (with reset times) go to `UserDefaults`, without a single token. `URLSession` runs ephemeral, no cookies, no disk cache.

## CI & releases

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push to `main`, every PR, and on demand: regenerate translations and check `Resources/*.lproj` didn't drift, `plutil -lint` the strings, verify the icon generator produces a valid `.icns`, `./build.sh`, self-test, and bundle checks (`Info.plist` validity, signature, `LSUIElement`, icon, all 14 locales), then upload the `.app` artifact.

The self-test (`NOTCHLIMITS_SELFTEST=1`) needs no network, Keychain, or window server, and covers Claude/Codex parsing (garbage, `null` windows, unknown keys), window order and titles, JWT claims, time/age/percent formatting, cache and hotkey serialization, and localization completeness — matching key sets, no empty values, and **format specifiers matching English**, or `String(format:)` would crash in another language.

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs on a `v*` tag or manually with a version: builds, self-tests, checks the `Info.plist` version against the tag, packs with `ditto` (plain `zip` breaks the signature), computes SHA-256, and publishes a release with the `.zip` and `SHA256SUMS.txt`. Release notes are generated: install steps (including the mandatory quarantine removal for ad-hoc builds), commits since the last tag, a spec table, and the checksum.

Version comes from `NOTCHLIMITS_VERSION`, else the [`VERSION`](VERSION) file:

```bash
NOTCHLIMITS_VERSION=1.2.0 ./build.sh    # build
git tag v1.2.0 && git push origin v1.2.0    # release
```

## Debug modes

Environment variables for running the binary directly (`./build/NotchLimits.app/Contents/MacOS/NotchLimits`):

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
Sources/NotchLimits/
  App/        entry point, delegate, context menu, debug modes
  Notch/      notch geometry, NSPanel, hover logic and animations
  UI/         SwiftUI panel layout
  Model/      column and limit-window types
  Providers/  Claude (Keychain + api.anthropic.com), Codex (auth.json + chatgpt.com)
  Core/       poll scheduler, cache, notifications, hotkeys, account setup
Tools/
  make-strings.py   translations for every language
  make-icon.swift   app icon
```

A few spots where the implementation is subtle and needs care:

- `NotchPanel.constrainFrameRect(_:to:)` returns the frame unchanged. Otherwise AppKit shoves the window out from under the menu bar and it stops hugging the notch.
- Window level is `.popUpMenu`, not `.statusBar + 1`: on recent macOS the menu bar draws higher and the panel would fall behind menu items.
- `NotchHostingView.safeAreaInsets` is zeroed: the window already sits over the cutout, and an extra safe area would push content down by the notch height again.
- On close, the window frame shrinks 0.35 s after the animation starts, so its last frames aren't clipped.
