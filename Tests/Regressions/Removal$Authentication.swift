private enum AuditSignals {
  static var beforeFileRestore: (() -> Void)?
  static var afterConfigRestore: ((Int32) -> Void)?
  static var deleted: ((String) -> Void)?
  static var blockedKey: String?
  static var read: ((String) -> Void)?
}
@main enum Removal$Authentication {
  static let manager = Foundation.FileManager.default
  static func main() async {
    do {
      Fixture.keychainExists = false
      let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
      if parts[0] == "managed" {
        try managed(takeover: parts[1] == "lost", bootstrap: parts[2])
      } else if parts[0] == "claude" {
        try claude(takeover: parts[1] == "takeover", denied: parts[2] == "denied")
      } else if parts[0] == "file-rollback" {
        try fileToAuto(state: parts[1])
      } else if parts[0] == "metadata" {
        try metadata(
          mode: parts[1], failure: parts.last != "stable",
          replacement: parts.contains("readd"), unreadable: parts.contains("unreadable"))
      } else if parts[0] == "unlink" || parts[0] == "opaque" {
        try unlink(mode: parts[1], failure: parts[2] == "fail", unreadable: parts[0] == "opaque")
      } else {
        try await shared(target: parts[1], phase: parts[2])
      }
    } catch {
      print("FAIL: \(error)")
      exit(1)
    }
  }
  static func claude(takeover: Bool, denied: Bool) throws {
    Fixture.keychainExists = true
    Fixture.keychain = Fixture.claudeLogin("original", expired: false)
    let directory = Fixture.storageDirectory
    try manager.createDirectory(at: directory, withIntermediateDirectories: true)
    let file = directory.appendingPathComponent(".credentials.json")
    let original = try JSONSerialization.data(withJSONObject: Fixture.keychain)
    try original.write(to: file)
    let account = DiscoveredAccount(
      id: "claude:" + Fixture.service, provider: .claude, profileName: "Primary",
      source: .claudeKeychain(service: Fixture.service, configDir: nil))
    let fresh = Fixture.claudeLogin("replacement", expired: false)
    let replacement = try JSONSerialization.data(withJSONObject: fresh)
    var reached = false
    let mutate = {
      CleanupSignals.io = nil
      Fixture.beforeCredentialDelete = nil
      reached = true
      if takeover {
        for path in [Fixture.storageLock, Fixture.oauthLock, Fixture.legacyLock] {
          try! manager.moveItem(at: path, to: path.appendingPathExtension("retired"))
          try! manager.createDirectory(at: path, withIntermediateDirectories: false)
        }
        Fixture.keychain = fresh
        Fixture.keychainExists = true
        try! replacement.write(to: file)
      }
    }
    if denied {
      Fixture.beforeCredentialDelete = mutate
      Fixture.denyKeychainDelete = true
    } else {
      CleanupSignals.io = { path in
        if path == file.path && Fixture.holdsOAuthLocks
          && manager.fileExists(atPath: Fixture.storageLock.path)
        {
          mutate()
        }
      }
    }
    var success = false
    do {
      try AccountRemoval.remove(account)
      success = true
    } catch { print("Refused: \(error)") }
    let retainedFile = try? Data(contentsOf: file)
    let retainedKeychain =
      Fixture.keychainExists && NSDictionary(dictionary: Fixture.keychain).isEqual(to: fresh)
    let replacementLocks = [Fixture.storageLock, Fixture.oauthLock, Fixture.legacyLock].allSatisfy {
      manager.fileExists(atPath: $0.path)
    }
    print(
      "CLAUDE takeover=\(takeover) denied=\(denied) reached=\(reached) success=\(success) freshFile=\(retainedFile==replacement) freshKeychain=\(retainedKeychain) replacementLocks=\(replacementLocks)"
    )
    try expect(reached, "Claude removal mutation boundary not reached")
    if takeover {
      try expect(
        !success && retainedKeychain && retainedFile == replacement && replacementLocks,
        "Claude removal overwrote or deleted a new login after losing both native leases")
    } else {
      try expect(success != denied, "stable Claude removal control failed")
    }
  }
  static func managed(takeover: Bool, bootstrap: String) throws {
    let home = ProfileDirectories.claudeRoot.appendingPathComponent("account")
    try manager.createDirectory(at: home, withIntermediateDirectories: true)
    let file = home.appendingPathComponent(".credentials.json")
    let original = try JSONSerialization.data(
      withJSONObject: Fixture.claudeLogin("original", expired: false))
    try original.write(to: file)
    let service =
      AuthStorage$Claude.baseService + "-"
      + SHA256.hash(data: Data(home.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(
        8)
    let account = DiscoveredAccount(
      id: "claude:" + service, provider: .claude, profileName: "account",
      source: .claudeKeychain(service: service, configDir: home))
    var reached = false
    CleanupSignals.moved = { from, to in
      guard from == home, to.lastPathComponent.hasPrefix(".removed-") else { return }
      CleanupSignals.moved = nil
      reached = true
      if takeover {
        for path in [
          to.appendingPathComponent(".storage-write.lock"),
          to.appendingPathComponent(".oauth_refresh.lock"),
          URL(fileURLWithPath: home.path + ".lock"),
        ] {
          try! manager.moveItem(at: path, to: path.appendingPathExtension("retired"))
          try! manager.createDirectory(at: path, withIntermediateDirectories: false)
        }
      }
      if bootstrap == "retarget" {
        let root = ProfileDirectories.claudeRoot
        try! manager.moveItem(at: root, to: root.appendingPathExtension("retired"))
        try! manager.createDirectory(at: root, withIntermediateDirectories: false)
      }
      if bootstrap != "absent" {
        try! manager.createDirectory(at: home, withIntermediateDirectories: true)
      }
      if bootstrap == "login" || bootstrap == "retarget" {
        try! JSONSerialization.data(
          withJSONObject: Fixture.claudeLogin("replacement", expired: false)
        ).write(to: file)
      }
    }
    var success = false
    do {
      try AccountRemoval.remove(account)
      success = true
    } catch { print("Refused: \(error)") }
    let retained = try? Data(contentsOf: file)
    let discovered = Discovery$Real().discover().contains { $0.id == account.id }
    print(
      "MANAGED lost=\(takeover) bootstrap=\(bootstrap) reached=\(reached) success=\(success) file=\(retained==original) discovered=\(discovered)"
    )
    try expect(reached, "staging not reached")
    if takeover {
      let expected =
        bootstrap == "login" || bootstrap == "retarget"
        ? try JSONSerialization.data(
          withJSONObject: Fixture.claudeLogin("replacement", expired: false)) : original
      // Compare tokens rather than generated expiry timestamps.
      let expectedLogin = try JSONSerialization.jsonObject(with: expected) as! [String: Any]
      let currentLogin = retained.flatMap {
        try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
      }
      let token = (currentLogin?["claudeAiOauth"] as? [String: Any])?["refreshToken"] as? String
      let expectedToken =
        (expectedLogin["claudeAiOauth"] as! [String: Any])["refreshToken"] as? String
      try expect(
        !success && token == expectedToken && discovered,
        "refused managed Claude removal hid or replaced its file login")
    } else {
      try expect(success, "stable managed removal failed")
    }
  }
  static func fileToAuto(state: String) throws {
    let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
    let configConflict = state == "config-conflict"
    if configConflict {
      let system = Fixture.root.appendingPathComponent("system")
      try manager.createDirectory(at: system, withIntermediateDirectories: true)
      try Data("cli_auth_credentials_store = 'auto'\n".utf8).write(to: system.appendingPathComponent("config.toml"))
    }
    try Cleanup$Authentication.login(home, name: "original", mode: "file")
    let original = try Cleanup$Authentication.bytes(home, mode: "file")!
    guard let account = Discovery$Real().discover().first(where: {
      $0.id == AuthSwap$Codex.profileColumnID(home.lastPathComponent)
    }) else { throw Failure(description: "Original login was not discovered") }
    var staged: URL?
    CleanupSignals.moved = { from, to in
      guard from.path == home.path && to.lastPathComponent.hasPrefix(".removed-") else { return }
      CleanupSignals.moved = nil
      staged = to
      if state == "login" {
        try! Cleanup$Authentication.login(home, name: "replacement", mode: "auto")
      } else {
        try! manager.createDirectory(at: home, withIntermediateDirectories: true)
        try! Fixture.codexMode(home, "auto")
        if state == "denied" { AuditSignals.blockedKey = Fixture.codexKey(home) }
      }
      if state == "during-rename" || configConflict {
        if configConflict { try! manager.removeItem(at: home.appendingPathComponent("config.toml")) }
        let key = Fixture.codexKey(home)
        let elsewhere = Fixture.root.appendingPathComponent("native-new-login")
        try! Cleanup$Authentication.login(elsewhere, name: "replacement", mode: "auto")
        let newLogin = try! Cleanup$Authentication.bytes(elsewhere, mode: "auto")!
        let publishLogin = {
          Fixture.codexKeychain[key] = newLogin
          try! Data("updated-keychain".utf8).write(to: Fixture.classicKeychainDatabase(), options: .atomic)
        }
        if configConflict {
          AuditSignals.afterConfigRestore = { descriptor in
            let file = Darwin.openat(descriptor, "config.toml", O_WRONLY | O_CREAT | O_EXCL, 0o600)
            precondition(file >= 0, "Fixture could not recreate the staged config")
            let handle = FileHandle(fileDescriptor: file, closeOnDealloc: true)
            try! handle.write(contentsOf: Data("# Concurrent staged settings\n".utf8))
            try! handle.close()
            publishLogin()
          }
        } else {
          AuditSignals.beforeFileRestore = publishLogin
        }
      }
      Fixture.denyCredentialFileRemovalPath = to.appendingPathComponent("auth.json").path
    }
    let removal = Result { try AccountRemoval.remove(account) }
    guard case .failure = removal, let staged else {
      throw Failure(description: "Fixture did not trigger a refused removal after the profile was re-added")
    }
    if state == "empty" {
      try expect(try AuthSwap$Codex.authData(home: home) == original,
                 "Rollback did not restore the original login into an empty profile")
      return
    }
    if state == "during-rename" {
      try expect(AuditSignals.beforeFileRestore == nil, "Did not reach the file publication syscall")
    }
    if configConflict {
      try expect(AuditSignals.afterConfigRestore == nil, "Did not publish the original configuration")
      try expect(!manager.fileExists(atPath: home.appendingPathComponent("config.toml").path)
                   && !manager.fileExists(atPath: home.appendingPathComponent("auth.json").path),
                 "Rollback left the previous storage mode or login active")
      let stagedConfig = try String(contentsOf: staged.appendingPathComponent("config.toml"))
      try expect(stagedConfig == "# Concurrent staged settings\n", "Rollback overwrote the concurrent staged config")
      let stagedNames = try manager.contentsOfDirectory(atPath: staged.path)
      try expect(stagedNames.contains { name in
        name.hasPrefix(".rollback-") && name.hasSuffix("-config.toml")
          && (try? String(contentsOf: staged.appendingPathComponent(name))) == "cli_auth_credentials_store = \"file\"\n"
      }, "Rollback did not preserve the withdrawn config separately")
    }
    if state == "login" || state == "during-rename" || configConflict {
      let fresh = try Cleanup$Authentication.bytes(home, mode: "auto")
      try expect(fresh != nil && fresh != original && (try AuthSwap$Codex.authData(home: home)) == fresh,
                 "The re-added Keychain login changed during rollback")
      Fixture.denyCodexRead = true
    }
    let fallback = try AuthSwap$Codex.authData(home: home)
    try expect(fallback == nil && (try Cleanup$Authentication.bytes(staged, mode: "file")) == original,
               "Rollback installed the staged file grant into a profile without a proven empty Keychain")
  }

  static func metadata(
    mode: String, failure: Bool, replacement: Bool = false, unreadable: Bool = false
  ) throws {
    let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
    try Cleanup$Authentication.login(home, name: "original", mode: mode)
    let original = try Cleanup$Authentication.bytes(home, mode: mode)!
    let account = DiscoveredAccount(
      id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(home))
    Fixture.denyCodexRead = unreadable
    var fresh: Data?
    var reached = false
    AuditSignals.deleted = { key in
      AuditSignals.deleted = nil
      reached = true
      if replacement {
        try! Cleanup$Authentication.login(home, name: "replacement", mode: "file")
        fresh = try! Cleanup$Authentication.bytes(home, mode: "file")
      }
      if failure { AuditSignals.blockedKey = key }
    }
    var success = false
    do {
      try AccountRemoval.remove(account)
      success = true
    } catch { print("Refused: \(error)") }
    Fixture.denyCodexRead = false
    AuditSignals.blockedKey = nil
    let retained = Fixture.codexKeychain.values.contains(original)
    let discovered = Discovery$Real().discover().contains { $0.id == account.id }
    print(
      "METADATA mode=\(mode) failure=\(failure) reached=\(reached) success=\(success) retained=\(retained) discovered=\(discovered)"
    )
    try expect(reached, "post-delete Keychain boundary not reached")
    if replacement {
      let current = try AuthSwap$Codex.authData(home: home)
      let visibleRecovery = Discovery$Real().discover().contains { account in
        guard case .codexHome(let directory) = account.source,
          let data = try? AuthSwap$Codex.authData(columnID: account.id, home: directory)
        else { return false }
        return data == original
      }
      try expect(
        fresh != nil && current == fresh && discovered,
        "rollback replaced or hid the re-added file login")
      try expect(
        retained && visibleRecovery, "rollback hid the former login after file re-addition")
    }
    if !failure {
      try expect(success && !retained && !discovered, "explicit removal did not commit")
    }
    try expect(
      success || retained,
      "a failed final metadata check discarded the reserved credential without rollback")
  }
  static func unlink(mode: String, failure: Bool, unreadable: Bool = false) throws {
    let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
    try Cleanup$Authentication.login(home, name: "original", mode: mode)
    let original = try Cleanup$Authentication.bytes(home, mode: mode)!
    if mode != "file" { try original.write(to: home.appendingPathComponent("auth.json")) }
    let account = DiscoveredAccount(
      id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(home))
    Fixture.denyCodexRead = unreadable
    var reached = false
    CleanupSignals.removed = { url in
      guard url.lastPathComponent == "auth.json",
        url.deletingLastPathComponent().lastPathComponent.hasPrefix(".removed-")
      else { return }
      CleanupSignals.removed = nil
      reached = true
      if failure {
        Fixture.managedCodex["config_toml_base64"] = Data(
          "cli_auth_credentials_store = \"ephemeral\"\n".utf8
        ).base64EncodedString()
      }
    }
    var success = false
    do {
      try AccountRemoval.remove(account)
      success = true
    } catch { print("Refused: \(error)") }
    Fixture.managedCodex = [:]
    Fixture.denyCodexRead = false
    let retained =
      (try? Cleanup$Authentication.bytes(home, mode: mode)) == original
      || Fixture.codexKeychain.values.contains(original)
    print(
      "UNLINK mode=\(mode) failure=\(failure) reached=\(reached) success=\(success) retained=\(retained)"
    )
    try expect(reached, "unlink boundary not reached")
    if unreadable {
      try expect(success != failure, "opaque removal crossed its pre-commit refusal")
      try expect(
        Fixture.codexKeychain.values.contains(original) == failure,
        "opaque pre-commit refusal deleted the reserved Keychain login")
    }
    try expect(
      success || retained, "failed post-unlink validation did not restore the deleted file login")
  }
  static func shared(target: String, phase: String) async throws {
    let native = AuthSwap$Codex.baseHome
    let source = ProfileDirectories.codexRoot.appendingPathComponent("source")
    let copy = ProfileDirectories.codexRoot.appendingPathComponent("copy")
    let peer = ProfileDirectories.codexRoot.appendingPathComponent("peer")
    try Cleanup$Authentication.login(native, name: "native", mode: "file")
    try Cleanup$Authentication.login(
      source, name: "sleeping", mode: target == "source" ? "auto" : "file", expired: true)
    let original = try Cleanup$Authentication.bytes(
      source, mode: target == "source" ? "auto" : "file")!
    let home = target == "source" ? source : copy
    if target == "copy" {
      try Fixture.codexMode(copy, "auto")
      Fixture.codexKeychain[Fixture.codexKey(copy)] = original
    }
    let alternate = Fixture.root.appendingPathComponent("alternate")
    try Cleanup$Authentication.login(alternate, name: "independent-fallback", mode: "file")
    let independent = try Cleanup$Authentication.bytes(alternate, mode: "file")!
    // A late alias must be injected while an otherwise removable copy is
    // checked. The stable scenario still covers the independent file owner.
    let fallback = phase == "late" || phase == "read" ? original : independent
    try fallback.write(to: home.appendingPathComponent("auth.json"))
    let dataHome = URL(fileURLWithPath: "/System/Volumes/Data" + home.path)
    try expect(manager.fileExists(atPath: dataHome.path), "Data-volume alias unavailable")
    let key = Fixture.codexKey(home)
    var published = false
    var reached = false
    CleanupSignals.written = { written in if written == key { published = true } }
    let addPeer = {
      CleanupSignals.io = nil
      AuditSignals.read = nil
      reached = true
      try! manager.createSymbolicLink(at: peer, withDestinationURL: dataHome)
    }
    if phase == "read" {
      AuditSignals.read = { observed in if published && observed == key { addPeer() } }
    } else if phase == "late" {
      CleanupSignals.io = { path in
        if published && path == home.appendingPathComponent("auth.json").path { addPeer() }
      }
    } else {
      addPeer()
    }
    let result = await Renewal$Codex.shared.renew(
      columnID: "codex:source", home: source, force: true)
    let retained = try? AuthSwap$Codex.authData(home: peer)
    print(
      "SHARED target=\(target) phase=\(phase) reached=\(reached) result=\(result) fallbackPreserved=\(retained==fallback)"
    )
    try expect(reached, "late shared owner boundary not reached")
    try expect(
      retained == fallback,
      "post-publication cleanup removed a file login owned by the shared alias")
  }
}
