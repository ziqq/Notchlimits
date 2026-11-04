private enum AuditSignals {
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
      if parts[0] == "claude" {
        try claude(takeover: parts[1] == "takeover", denied: parts[2] == "denied")
      } else if parts[0] == "metadata" {
        try metadata(mode: parts[1], failure: parts[2] == "fail")
      } else if parts[0] == "unlink" {
        try unlink(mode: parts[1], failure: parts[2] == "fail")
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
  static func metadata(mode: String, failure: Bool) throws {
    let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
    try Cleanup$Authentication.login(home, name: "original", mode: mode)
    let original = try Cleanup$Authentication.bytes(home, mode: mode)!
    let account = DiscoveredAccount(
      id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(home))
    var reached = false
    AuditSignals.deleted = { key in
      AuditSignals.deleted = nil
      reached = true
      if failure { AuditSignals.blockedKey = key }
    }
    var success = false
    do {
      try AccountRemoval.remove(account)
      success = true
    } catch { print("Refused: \(error)") }
    AuditSignals.blockedKey = nil
    let retained = Fixture.codexKeychain.values.contains(original)
    let discovered = Discovery$Real().discover().contains { $0.id == account.id }
    print(
      "METADATA mode=\(mode) failure=\(failure) reached=\(reached) success=\(success) retained=\(retained) discovered=\(discovered)"
    )
    try expect(reached, "post-delete Keychain boundary not reached")
    try expect(
      success || retained,
      "a failed final metadata check discarded the reserved credential without rollback")
  }
  static func unlink(mode: String, failure: Bool) throws {
    let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
    try Cleanup$Authentication.login(home, name: "original", mode: mode)
    let original = try Cleanup$Authentication.bytes(home, mode: mode)!
    if mode != "file" { try original.write(to: home.appendingPathComponent("auth.json")) }
    let account = DiscoveredAccount(
      id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(home))
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
    let retained =
      (try? Cleanup$Authentication.bytes(home, mode: mode)) == original
      || Fixture.codexKeychain.values.contains(original)
    print(
      "UNLINK mode=\(mode) failure=\(failure) reached=\(reached) success=\(success) retained=\(retained)"
    )
    try expect(reached, "unlink boundary not reached")
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
    let fallback = try Cleanup$Authentication.bytes(alternate, mode: "file")!
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
      "post-publication cleanup removed an independent newly shared file login")
  }
}
