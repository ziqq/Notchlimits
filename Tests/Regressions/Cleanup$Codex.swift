private enum BackupSignals {
  static var deleted: ((String) -> Void)?
  static var nativeRead: ((String) -> Void)?
}
@main enum Cleanup$Codex {
  static let manager = Foundation.FileManager.default
  static func main() async {
    do {
      Fixture.keychainExists = false
      let p = CommandLine.arguments[1].split(separator: ":").map(String.init)
      if p[0] == "empty" {
        try empty(mode: p[1])
      } else if p[0] == "publication" {
        try publication(mode: p[1])
      } else if p[0] == "destination" {
        try destination(mode: p[1])
      } else if p[0] == "stash" {
        try stash(mode: p[1], denied: p[2] == "denied")
      } else if p[0] == "orphan" {
        try orphan(mode: p[1], denied: p[2] == "denied")

      } else {
        try restore(
          mode: p[1], change: p[2], removing: p[0] == "remove", phase: p.count > 3 ? p[3] : "unlink"
        )
      }
    } catch {
      print("FAIL: \(error)")
      exit(1)
    }
  }
  static func empty(mode: String) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    try Fixture.codexMode(native, mode)
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    let original = try AuthSwap$Codex.authData(home: selected)
    try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
    try expect(
      try AuthStorage$Codex(home: AuthSwap$Codex.stashHome).mode.rawValue == mode,
      "an empty primary changed its configured CLI storage mode")
    try AuthSwap$Codex.restoreDefault()
    try expect(
      try AuthSwap$Codex.authData(home: native) == nil
        && AuthSwap$Codex.authData(home: selected) == original,
      "restoring an empty primary lost the selected profile or kept its native login")
  }
  static func publication(mode: String) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
    try Cleanup$Authentication.login(native, name: "primary", mode: mode)
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    try Cleanup$Authentication.login(other, name: "other", mode: "file")
    Fixture.denyCodexWrite = mode == "auto-file"
    try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
    Fixture.denyCodexWrite = false
    try Cleanup$Authentication.login(native, name: "independent-native", mode: mode)
    let previous = try Cleanup$Authentication.bytes(native, mode: mode)!
    var reached = false
    var replacement: Data?
    Fixture.beforeDirectoryCreate = { url in
      guard url.lastPathComponent.hasPrefix("orphaned-") else { return }
      Fixture.beforeDirectoryCreate = nil
      reached = true
      try Cleanup$Authentication.login(native, name: "late-native", mode: mode)
      replacement = try Cleanup$Authentication.bytes(native, mode: mode)
    }
    var success = false
    do {
      try AuthSwap$Codex.activate(columnID: "codex:other", home: other)
      success = true
    } catch {}
    let archives = try manager.contentsOfDirectory(
      at: AuthSwap$Codex.stashHome.deletingLastPathComponent(), includingPropertiesForKeys: nil
    ).filter { $0.lastPathComponent.hasPrefix("orphaned-") }
    let preserved = archives.contains { (try? AuthSwap$Codex.authData(home: $0)) == previous }
    try expect(
      reached && !success && (try AuthSwap$Codex.authData(home: native)) == replacement
        && preserved,
      "publication replaced a native login that completed during backup preparation")
  }
  static func destination(mode: String) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    try Cleanup$Authentication.login(native, name: "primary", mode: mode)
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    let primary = try Cleanup$Authentication.bytes(native, mode: mode)!
    let backup = AuthSwap$Codex.stashHome
    try Fixture.codexMode(backup, mode == "auto-file" ? "auto" : mode)
    if mode == "file" || mode == "auto-file" {
      try primary.write(to: backup.appendingPathComponent("auth.json"))
    } else {
      Fixture.codexKeychain[Fixture.codexKey(backup)] = primary
    }
    let nativeKey = Fixture.codexKey(native)
    var armed = false
    var reads = 0
    var reached = false
    var replacement: Data?
    let observe = {
      guard armed else { return }
      reads += 1
      guard reads == 2 else { return }
      BackupSignals.nativeRead = nil
      CleanupSignals.io = nil
      Fixture.beforeDirectoryCreate = nil
      reached = true
      try! Cleanup$Authentication.login(backup, name: "late-backup", mode: mode)
      replacement = try! Cleanup$Authentication.bytes(backup, mode: mode)
    }
    Fixture.beforeDirectoryCreate = { url in
      if url.path == backup.path {
        armed = true
        reads = 0
      }
    }
    if mode == "file" || mode == "auto-file" {
      CleanupSignals.io = { path in
        if path == native.appendingPathComponent("auth.json").path { observe() }
      }
    } else {
      BackupSignals.nativeRead = { key in if key == nativeKey { observe() } }
    }
    var success = false
    do {
      try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
      success = true
    } catch {}
    let current = try Cleanup$Authentication.bytes(backup, mode: mode)
    try expect(
      reached && !success && current == replacement
        && (try AuthSwap$Codex.authData(home: native)) == primary,
      "first backup publication replaced a login completed during preparation")
  }
  static func stash(mode: String, denied: Bool) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    try Cleanup$Authentication.login(native, name: "primary", mode: mode)
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    let original = Fixture.codexKeychain[Fixture.codexKey(native)]!
    try expect(
      !manager.fileExists(atPath: native.appendingPathComponent("auth.json").path),
      "source was not keychain-only")
    Fixture.denyCodexWrite = denied
    var success = false
    do {
      try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
      success = true
    } catch { print("Refused: \(error)") }
    Fixture.denyCodexWrite = false
    let backup = AuthSwap$Codex.stashHome
    let exported = (try? Data(contentsOf: backup.appendingPathComponent("auth.json"))) == original
    if success && mode == "auto" {
      try expect(
        try AuthStorage$Codex(home: backup).mode == .auto,
        "a Keychain-backed auto primary lost shared-fallback ownership checks")
    }
    print(
      "STASH mode=\(mode) denied=\(denied) success=\(success) keychainExportedToFile=\(exported)")
    try expect(
      !exported,
      "first primary backup exported a Keychain-only login to plaintext after a denied write")
  }
  static func orphan(mode: String, denied: Bool) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
    try Cleanup$Authentication.login(native, name: "primary", mode: mode)
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    try Cleanup$Authentication.login(other, name: "other", mode: "file")
    try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
    try Cleanup$Authentication.login(native, name: "independent-native", mode: mode)
    let original = Fixture.codexKeychain[Fixture.codexKey(native)]!
    try expect(
      !manager.fileExists(atPath: native.appendingPathComponent("auth.json").path),
      "source was not keychain-only")
    Fixture.denyCodexWrite = denied
    var success = false
    do {
      try AuthSwap$Codex.activate(columnID: "codex:other", home: other)
      success = true
    } catch { print("Refused: \(error)") }
    Fixture.denyCodexWrite = false
    let parent = AuthSwap$Codex.stashHome.deletingLastPathComponent()
    let orphans = try manager.contentsOfDirectory(at: parent, includingPropertiesForKeys: nil)
      .filter { $0.lastPathComponent.hasPrefix("orphaned-") }
    let plaintext = orphans.filter {
      (try? Data(contentsOf: $0.appendingPathComponent("auth.json"))) == original
    }
    print(
      "ORPHAN mode=\(mode) denied=\(denied) success=\(success) archives=\(orphans.count) keychainExportedToFile=\(!plaintext.isEmpty)"
    )
    try expect(!orphans.isEmpty, "orphan preservation path not reached")
    try expect(
      plaintext.isEmpty,
      "orphan recovery exported a Keychain-only native login to plaintext after a denied write")
  }
  static func restore(
    mode: String, change: String, removing: Bool = false, phase: String = "unlink"
  ) throws {
    let native = AuthSwap$Codex.baseHome
    let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
    try Cleanup$Authentication.login(native, name: "primary", mode: mode)
    let primary = try Cleanup$Authentication.bytes(native, mode: mode)!
    try Cleanup$Authentication.login(selected, name: "selected", mode: "file")
    Fixture.denyCodexWrite = mode == "auto-file"
    try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
    Fixture.denyCodexWrite = false
    let backup = AuthSwap$Codex.stashHome
    // Exercise the supported two-store cleanup path for keyring/auto too.
    try primary.write(to: backup.appendingPathComponent("auth.json"))
    var reached = false
    var replacement: Data?
    let mutate = {
      CleanupSignals.removed = nil
      BackupSignals.deleted = nil
      reached = true
      if change == "native" {
        try! Cleanup$Authentication.login(native, name: "replacement", mode: mode)
        replacement = try! Cleanup$Authentication.bytes(native, mode: mode)
      } else if change == "backup" {
        try! Cleanup$Authentication.login(backup, name: "replacement", mode: "file")
        replacement = try! Cleanup$Authentication.bytes(backup, mode: "file")
      }
    }
    if phase == "completed" {
      BackupSignals.deleted = { key in
        if key == Fixture.codexKey(backup) {
          BackupSignals.nativeRead = { observed in
            if observed == Fixture.codexKey(backup) {
              BackupSignals.nativeRead = nil
              mutate()
            }
          }
        }
      }
    } else if phase == "keychain" {
      BackupSignals.deleted = { key in if key == Fixture.codexKey(backup) { mutate() } }
    } else {
      CleanupSignals.removed = { url in
        if url.path == backup.appendingPathComponent("auth.json").path { mutate() }
      }
    }
    let marker = native.appendingPathComponent("projects-marker")
    try Data("preserve-projects-and-threads".utf8).write(to: marker)
    var success = false
    do {
      if removing {
        let account = DiscoveredAccount(
          id: "codex:selected", provider: .codex, profileName: "selected",
          source: .codexHome(selected))
        try AccountRemoval.remove(account)
      } else {
        try AuthSwap$Codex.restoreDefault()
      }
      success = true
    } catch { print("Refused: \(error)") }
    CleanupSignals.removed = nil
    BackupSignals.deleted = nil
    BackupSignals.nativeRead = nil
    let accounts = Discovery$Real().discover().filter { $0.provider == .codex }
    let visible = accounts.compactMap { a -> Data? in
      guard case .codexHome(let home) = a.source else { return nil }
      return try? AuthSwap$Codex.authData(columnID: a.id, home: home)
    }
    let nativeNow = try? AuthSwap$Codex.authData(home: native)
    let backupNow = try? AuthSwap$Codex.authData(home: backup)
    print(
      "RESTORE removing=\(removing) mode=\(mode) change=\(change) reached=\(reached) success=\(success) active=\(AuthSwap$Codex.activeColumnID) visible=\(accounts.map{$0.id}) primaryVisible=\(visible.contains(primary)) replacementVisible=\(replacement.map{visible.contains($0)} ?? false) nativeNew=\(nativeNow==replacement) backupNew=\(backupNow==replacement)"
    )
    if phase != "completed" {
      try expect(reached, "backup cleanup boundary not reached")
    }
    try expect(
      try Data(contentsOf: marker) == Data("preserve-projects-and-threads".utf8),
      "cleanup changed native projects or threads")
    if change == "stable" || phase == "completed" && !reached {
      try expect(success && visible.contains(primary), "stable default restoration failed")
    } else {
      if change == "native" {
        try expect(
          nativeNow == replacement && visible.contains(primary),
          "late native login or primary backup was lost")
      } else {
        try expect(
          backupNow == replacement && visible.contains(replacement!),
          "late backup file login became undiscoverable")
      }
      try expect(!success, "cleanup accepted a late credential replacement")
    }
  }
}
