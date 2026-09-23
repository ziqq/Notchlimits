# Changelog


## Unreleased
- **ADDED**: Releases ship a drag-to-Applications DMG (`scripts/build_dmg.sh`) next to the `.zip`, which the in-app
  updater keeps using; `SHA256SUMS.txt` covers both.


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
