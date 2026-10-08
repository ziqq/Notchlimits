# Changelog


## Unreleased
- **REMOVED**: Unused translations — the old CLI account switcher (`switch.*`), `menu.liquidGlass` and
  `update.checking` — from the generator and all 14 languages.


## 1.2.2 - 05/10/2026
- **FIXED**: Semantic label events queue per issue, pull request, or discussion instead of in one shared queue, so a
  burst of events (for example a pull request closing together with a comment) no longer cancels pending runs. Push,
  branch, and manual runs still share the queue with release issue completion.
- **CHANGED**: Every workflow pins the labeler to the same version.


## 1.2.1 - 05/10/2026
- **FIXED**: Renewing a Claude token no longer risks losing the login. NotchLimits checks it can write to the Keychain
  entry before renewing, keeps a renewed token it failed to save and retries, so a revoked refresh token is never left
  behind for Claude Code to wipe.
- **FIXED**: A network failure while renewing a Claude token shows as a network error instead of "re-auth".
- **FIXED**: "re-auth" on a Claude column signs in with `claude auth login` and prints `claude auth status` right
  after, so you can see whether it worked. Interactive `claude` + `/login` could leave the account signed out silently.
- **FIXED**: The translation generator now preserves all existing keys and current account-switching text in
  all 14 languages; CI verifies complete, repeatable generation without dropping translations.
- **CHANGED**: Release notes are written in English.
- **ADDED**: Self-tests for Codex and Claude token renewal, cleared Claude Keychain entries, and the re-auth scripts;
  the debug probe shows each Claude Keychain entry's fields and whether it is writable, never the values.


## 1.2.0 - 30/09/2026
- **ADDED**: Codex accounts that aren't open in the desktop app renew their sign-in in the background, two days before
  the 10-day token runs out, so they no longer go stale until you switch the app to them. The sign-in in `~/.codex` is
  left to the app and the CLI.
- **CHANGED**: "re-auth" in a column is now a small button: it opens Terminal and signs in to exactly that account
  (`codex login` / `claude` in its own folder), without switching or restarting the desktop app.


## 1.1.2 - 24/09/2026
- **ADDED**: Releases ship a drag-to-Applications DMG (`scripts/build_dmg.sh`) next to the `.zip`, which the in-app
  updater keeps using; `SHA256SUMS.txt` covers both.
- **CHANGED**: README screenshots are re-rendered in English and show the current panel: plan in the subtitle, the
  active-account highlight, and Codex "Early resets".


## 1.1.1 - 23/09/2026
- **CHANGED**: The refresh button now sits right after "Updated … ago" as a light inline icon instead of a boxed button
  in the far corner.
- **FIXED**: "Early resets" lines up with the next limit window in neighbouring columns.


## 1.1.0 - 23/09/2026
- **ADDED**: Desktop app account submenus for Claude and Codex. The list mirrors the panel columns; picking an account
  quits the app and reopens it under that account.
- **ADDED**: Claude desktop app keeps a separate data folder per account; the first switch to an account asks you to
  sign in once.
- **ADDED**: Codex desktop app switching swaps only `~/.codex/auth.json`, so projects, threads, and the sidebar stay in
  place; the plain `codex` CLI uses the same account as the app.
- **ADDED**: The column of the account open in the desktop app is highlighted; the highlight moves only after the app
  has actually relaunched.
- **ADDED**: Adding an account with an empty name (or `main`) signs in to the CLI's standard location (`~/.claude` /
  `~/.codex`) instead of creating a profile, with a warning when it replaces an existing sign-in.
- **ADDED**: Clear errors when switching fails: the app did not quit, or the account has no sign-in.
- **FIXED**: A phantom Claude "main" column no longer appears: a Keychain entry without a login (bare `claude` writes
  one) is not treated as an account until someone signs in to it.
- **FIXED**: Limit windows without a reset date keep their row height, so columns no longer shift against each other.
- **FIXED**: Codex "Early resets" shows the real number of available resets.
- **FIXED**: Dialogs open above the notch panel instead of under it.
- **FIXED**: Incomplete profiles (folder without a sign-in) can be removed from the menu.
- **REMOVED**: The CLI "active account" switcher that swapped the base credentials; it clashed with the app account and
  corrupted the shared Claude sign-in.
- **CHANGED**: Release notes now include the version's section from `CHANGELOG.md`.


## 1.0.2 - 11/09/2026
- **ADDED**: "About Notch Limits" menu item showing the running version.
