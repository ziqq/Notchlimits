private enum CleanupSignals {
    static var removed: ((URL) -> Void)?
    static var attributes: ((String) -> Void)?
    static var read: ((String) -> Void)?
    static var io: ((String) -> Void)?
    static var moved: ((URL, URL) -> Void)?
    static var listed: ((URL) -> Void)?
    static var written: ((String) -> Void)?
}
@main enum Cleanup$Authentication {
    static let manager = Foundation.FileManager.default
    static func main() async {
        do {
            Fixture.keychainExists = false
            let p = CommandLine.arguments[1].split(separator: ":").map(String.init)
            if p[0] == "claudeAlias" {
                try claudeAlias(kind: p[1])
                return
            }
            if p[0] == "claude" {
                try claude(operation: p[1], change: p[2])
                return
            }
            if p[0] == "backup" {
                try backup(mode: p[1], change: p[2])
                return
            }
            if p[0] == "remove" {
                try removal(mode: p[1], phase: p[2], change: p[3])
            } else {
                try await cleanup(target: p[1], mode: p[2], phase: p[3], change: p[4])
            }
        } catch {
            print("FAIL: \(error)")
            exit(1)
        }
    }
    static func login(_ home: URL, name: String, mode: String, expired: Bool = false) throws {
        try Fixture.codexLogin(home, account: name, mode: mode == "auto-file" ? "auto" : mode, expired: expired)
        if mode == "auto-file" {
            let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home))!
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }
    static func bytes(_ home: URL, mode: String) throws -> Data? {
        if mode == "file" || mode == "auto-file" {
            return try? Data(contentsOf: home.appendingPathComponent("auth.json"))
        }
        return Fixture.codexKeychain[Fixture.codexKey(home)]
    }
    static func removal(mode: String, phase: String, change: String) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("account")
        try login(home, name: "original", mode: mode)
        if phase == "unlink" { try bytes(home, mode: mode)!.write(to: home.appendingPathComponent("auth.json")) }
        let account = DiscoveredAccount(
            id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(home))
        var reached = false
        var replacement: Data?
        let mutation = {
            Fixture.beforeDirectoryMove = nil
            CleanupSignals.moved = nil
            reached = true
            if change == "login" { try! login(home, name: "replacement", mode: mode) }
            if change == "metadata" { try! Data("keep".utf8).write(to: home.appendingPathComponent("settings-marker")) }
            replacement = try! bytes(home, mode: mode)
        }
        if phase == "before" {
            Fixture.beforeDirectoryMove = { _, to in if to.lastPathComponent.hasPrefix(".removed-") { mutation() } }
        } else if phase == "unlink" {
            CleanupSignals.removed = { url in
                guard
                    url.lastPathComponent == "auth.json"
                        && url.deletingLastPathComponent().lastPathComponent.hasPrefix(".removed-")
                else { return }
                CleanupSignals.removed = nil
                reached = true
                if change == "login" {
                    let fresh = Fixture.root.appendingPathComponent("fresh-session")
                    try! login(fresh, name: "replacement", mode: "keyring")
                    replacement = Fixture.codexKeychain[Fixture.codexKey(fresh)]
                    // An already running Keychain login can finish without recreating CODEX_HOME.
                    Fixture.codexKeychain[Fixture.codexKey(home)] = replacement
                }
            }
        } else {
            CleanupSignals.moved = { _, to in if to.lastPathComponent.hasPrefix(".removed-") { mutation() } }
        }
        var success = false
        do {
            try AccountRemoval.remove(account)
            success = true
        } catch { print("Refused: \(error)") }
        let discovered = Discovery$Real().discover().contains { $0.id == account.id }
        let retained = try phase == "unlink" ? AuthSwap$Codex.authData(home: home) : bytes(home, mode: mode)
        print(
            "REMOVE mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) success=\(success) fileProfile=\(manager.fileExists(atPath:home.path)) discovered=\(discovered) retained=\(retained==replacement)"
        )
        try expect(reached, "managed staging boundary not reached")
        if change == "login" {
            try expect(
                retained == replacement && discovered,
                "removal consumed or orphaned the login created at directory staging")
            if phase != "after" {
                try expect(!success, "removal accepted a login changed before its directory was staged")
            } else {
                try expect(success, "a same-name re-addition prevented retiring the original profile")
            }
        } else {
            try expect(success && !discovered, "stable or metadata-only removal failed")
        }
    }
    static func claudeAlias(kind: String) throws {
        let native = Fixture.storageDirectory
        let root = ProfileDirectories.claudeRoot
        let profile: URL
        if kind == "separate" {
            try manager.createDirectory(at: native, withIntermediateDirectories: true)
            try manager.createDirectory(at: root, withIntermediateDirectories: true)
            profile = root.appendingPathComponent("profile")
            try manager.createDirectory(at: profile, withIntermediateDirectories: true)
        } else {
            let physicalParent = Fixture.root.appendingPathComponent("claude-owners")
            let physical = physicalParent.appendingPathComponent("shared")
            try manager.createDirectory(at: physical, withIntermediateDirectories: true)
            try manager.createSymbolicLink(at: native, withDestinationURL: physical)
            let destination =
                kind == "data" ? URL(fileURLWithPath: "/System/Volumes/Data" + physicalParent.path) : physicalParent
            try expect(manager.fileExists(atPath: destination.path), "physical alias is not available")
            try manager.createSymbolicLink(at: root, withDestinationURL: destination)
            profile = root.appendingPathComponent("shared")
        }
        let file = native.appendingPathComponent(".credentials.json")
        let original = try JSONSerialization.data(
            withJSONObject: Fixture.claudeLogin("native-file-owner", expired: false))
        try original.write(to: file)
        let hash = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = AuthStorage$Claude.baseService + "-" + hash
        Fixture.claudeEntries = [service: Fixture.claudeLogin("profile-keychain-owner", expired: false)]
        let account = DiscoveredAccount(
            id: "claude:" + service, provider: .claude, profileName: "profile",
            source: .claudeKeychain(service: service, configDir: profile))
        let isBase = ProfileDirectories.isClaudeBase(profile)
        let owners = AuthStorage$Claude.keychainServices(in: profile) ?? []
        let sourceOwner = DirectoryIdentity.capture(native)!
        let profileOwner = DirectoryIdentity.capture(profile)!
        var success = false
        do {
            try AccountRemoval.remove(account)
            success = true
        } catch { print("Refused: \(error)") }
        let retained = try? Data(contentsOf: file)
        print(
            "CLAUDE_ALIAS kind=\(kind) physicalNative=\(sourceOwner.isSameDirectory(as:profileOwner)) classifiedBase=\(isBase) services=\(owners) success=\(success) nativePreserved=\(retained==original)"
        )
        try expect(retained == original, "removing a Claude Data-volume alias deleted the native file login")
        if kind != "data" { try expect(success, "ordinary profile or canonical native alias cleanup failed") }
    }
    static func claude(operation: String, change: String) throws {
        let directory = Fixture.storageDirectory
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent(".credentials.json")
        let original = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("original", expired: true))
        try original.write(to: file)
        guard let credentials = AuthStorage$Claude.credentials(service: Fixture.service),
            let lease = AuthStorage$Claude.refreshLock(service: Fixture.service, directory: credentials.directory)
        else { throw Failure(description: "missing native lease") }
        defer { lease.release() }
        var reached = false
        var replacement = original
        CleanupSignals.attributes = { path in
            guard URL(fileURLWithPath: path).lastPathComponent.hasPrefix(".credentials-") else { return }
            CleanupSignals.attributes = nil
            reached = true
            let paths =
                change == "login"
                ? [Fixture.storageLock, Fixture.oauthLock, Fixture.legacyLock]
                : change == "storage"
                    ? [Fixture.storageLock] : change == "oauth" ? [Fixture.oauthLock, Fixture.legacyLock] : []
            for lock in paths {
                try! manager.moveItem(at: lock, to: lock.appendingPathExtension("retired"))
                try! manager.createDirectory(at: lock, withIntermediateDirectories: false)
            }
            if change == "login" {
                try! JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false)).write(
                    to: file)
            }
            replacement = try! Data(contentsOf: file)
        }
        let fresh = OAuth$Claude.Tokens(
            accessToken: "synthetic-new-access", expiresAt: Date().addingTimeInterval(7200),
            refreshToken: "synthetic-rotated", refreshTokenExpiresAt: nil, scopes: nil)
        let success =
            operation == "preflight"
            ? AuthStorage$Claude.canWrite(service: Fixture.service, renewalLock: lease, expected: credentials)
            : AuthStorage$Claude.save(
                service: Fixture.service, tokens: fresh, expected: credentials, renewalLock: lease) == .saved
        let current = try Data(contentsOf: file)
        print("CLAUDE operation=\(operation) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "private file preparation was not reached")
        if change == "stable" {
            try expect(success, "stable private file publication failed")
        } else {
            try expect(!success && current == replacement, "late native lease takeover overwrote the current login")
        }
    }
    static func backup(mode: String, change: String) throws {
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try login(native, name: "primary", mode: mode)
        let primary = try bytes(native, mode: mode)
        try login(selected, name: "selected", mode: "file")
        Fixture.denyCodexWrite = mode == "auto-file"
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        Fixture.denyCodexWrite = false
        let backup = AuthSwap$Codex.stashHome
        let account = DiscoveredAccount(
            id: "codex:selected", provider: .codex, profileName: "selected", source: .codexHome(selected))
        let key = Fixture.codexKey(backup)
        var reached = false
        var read = false
        var reads = 0
        var replacement: Data?
        let mutation = {
            CleanupSignals.read = nil
            CleanupSignals.io = nil
            CleanupSignals.listed = nil
            reached = true
            if ["owner", "identical", "retarget"].contains(change) {
                try! manager.moveItem(at: backup, to: backup.appendingPathExtension("retired"))
                if change == "retarget" {
                    let fresh = Fixture.root.appendingPathComponent("fresh-primary")
                    try! login(fresh, name: "replacement-primary", mode: mode)
                    try! manager.createSymbolicLink(at: backup, withDestinationURL: fresh)
                } else {
                    try! login(backup, name: "replacement-primary", mode: mode)
                }
                if change == "identical" {
                    if mode == "file" || mode == "auto-file" {
                        try! primary!.write(to: backup.appendingPathComponent("auth.json"))
                    } else {
                        Fixture.codexKeychain[Fixture.codexKey(backup)] = primary
                    }
                }
            }
            if change == "login" { try! login(backup, name: "replacement-primary", mode: mode) }
            if change == "metadata" {
                try! Data("keep".utf8).write(to: backup.appendingPathComponent("settings-marker"))
            }
            replacement = try! bytes(backup, mode: mode)
        }
        CleanupSignals.read = { observed in
            if UserDefaults.standard.string(forKey: "codexAppAccountID") == nil && observed == key { read = true }
        }
        CleanupSignals.io = { path in
            guard
                UserDefaults.standard.string(forKey: "codexAppAccountID") == nil
                    && path == backup.appendingPathComponent("auth.json").path
            else { return }
            reads += 1
            if reads == 2 { mutation() }
        }
        CleanupSignals.listed = { url in
            if UserDefaults.standard.string(forKey: "codexAppAccountID") == nil && read
                && url.resolvingSymlinksInPath().path == ProfileDirectories.codexRoot.resolvingSymlinksInPath().path
            {
                mutation()
            }
        }
        var success = false
        do {
            try AccountRemoval.remove(account)
            success = true
        } catch { print("Refused: \(error)") }
        CleanupSignals.read = nil
        CleanupSignals.io = nil
        CleanupSignals.listed = nil
        let retained = try bytes(backup, mode: mode)
        print(
            "BACKUP mode=\(mode) change=\(change) reached=\(reached) success=\(success) replacementPreserved=\(retained==replacement)"
        )
        try expect(reached, "primary backup deletion boundary not reached")
        if ["login", "owner", "identical", "retarget"].contains(change) {
            try expect(
                !success && retained == replacement,
                "active-profile removal consumed or abandoned a replacement primary backup")
            let discovered = Discovery$Real().discover()
            let originalSurvives = try discovered.contains { account in
                guard case .codexHome(let home) = account.source else { return false }
                let data = try AuthSwap$Codex.authData(columnID: account.id, home: home)
                return data.flatMap(AuthSwap$Codex.authIdentity) == primary.flatMap(AuthSwap$Codex.authIdentity)
            }
            try expect(originalSurvives, "Refused backup cleanup hid the former primary after native rollback")
        } else {
            try expect(
                success && retained == nil && (try AuthSwap$Codex.authData(home: native)) == primary,
                "stable selected-profile removal did not preserve primary")
        }
        try expect(Fixture.refreshCalls == 0, "profile removal issued a refresh POST")
    }
    static func cleanup(target: String, mode: String, phase: String, change: String) async throws {
        let native = AuthSwap$Codex.baseHome
        let source = ProfileDirectories.codexRoot.appendingPathComponent("source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("copy")
        try login(native, name: "native", mode: "file")
        try login(source, name: "sleeping", mode: target == "source" ? mode : "file", expired: true)
        let original = try bytes(source, mode: target == "source" ? mode : "file")!
        let home = target == "source" ? source : copy
        if target == "copy" {
            try Fixture.codexMode(copy, mode)
            Fixture.codexKeychain[Fixture.codexKey(copy)] = original
        }
        // The normal path removes an obsolete fallback after Keychain publication.
        try original.write(to: home.appendingPathComponent("auth.json"))
        let key = Fixture.codexKey(home)
        var published = false
        var reached = false
        var replacement: Data?
        CleanupSignals.written = { written in if written == key { published = true } }
        let mutation = {
            CleanupSignals.listed = nil
            CleanupSignals.io = nil
            reached = true
            if change == "login" { try! login(home, name: "replacement", mode: "file") }
            if change == "metadata" { try! Data("keep".utf8).write(to: home.appendingPathComponent("settings-marker")) }
            replacement = try? Data(contentsOf: home.appendingPathComponent("auth.json"))
        }
        if phase == "scan" {
            CleanupSignals.listed = { url in
                if published
                    && url.resolvingSymlinksInPath().path == ProfileDirectories.codexRoot.resolvingSymlinksInPath().path
                {
                    mutation()
                }
            }
        } else {
            CleanupSignals.io = { path in
                if published && path == home.appendingPathComponent("auth.json").path { mutation() }
            }
        }
        let result = await Renewal$Codex.shared.renew(columnID: "codex:source", home: source, force: true)
        let retained = try? Data(contentsOf: home.appendingPathComponent("auth.json"))
        let keychain = Fixture.codexKeychain[key]!
        let json = try JSONSerialization.jsonObject(with: keychain) as! [String: Any]
        let grant = (json["tokens"] as! [String: Any])["refresh_token"] as? String
        print(
            "CLEANUP target=\(target) mode=\(mode) change=\(change) reached=\(reached) result=\(result) fileRetained=\(retained==replacement) grant=\(grant ?? "nil")"
        )
        try expect(reached && Fixture.refreshCalls == 1, "post-Keychain ownership enumeration not reached")
        try expect(grant == "synthetic-rotated", "Keychain lost the accepted rotation")
        if change == "login" {
            try expect(retained == replacement, "Keychain cleanup deleted a newer file-mode CLI login")
        } else {
            try expect(retained == nil, "stable cleanup failed to remove the obsolete fallback")
        }
    }
}
