// The harness prepends Authentication.swift's unchanged assertions and OS fakes.
@main
enum Ownership$Codex {
    static func main() async {
        do {
            let args = CommandLine.arguments[1].split(separator: ":").map(String.init)
            switch args[0] {
            case "post": try await submission(mode: args[1], change: args[2])
            case "switch": try await configuration(mode: args[1], change: args[2] == "retarget", switching: true)
            case "storage": try await configuration(mode: args[1], change: args[2] == "retarget", switching: false)
            case "remove": try removal(mode: args[1], change: args[2])
            default: throw Failure(description: "Unknown Codex ownership scenario")
            }
        } catch { print("FAIL: \(error)"); exit(1) }
    }

    private static func login(_ home: URL, account: String, mode: String, expired: Bool = false) throws {
        try Fixture.codexLogin(home, account: account, mode: mode == "auto-file" ? "auto" : mode, expired: expired)
        if mode == "auto-file" {
            guard let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home)) else {
                throw Failure(description: "Missing auto fallback fixture")
            }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }

    private static func native(_ mode: String) throws -> (URL, URL, URL, URL) {
        Fixture.keychainExists = false
        let old = Fixture.root.appendingPathComponent("native-old")
        let fresh = Fixture.root.appendingPathComponent("native-new")
        let link = Fixture.root.appendingPathComponent("native-link")
        let source = ProfileDirectories.codexRoot.appendingPathComponent("source")
        try login(old, account: "old-native", mode: mode)
        try login(fresh, account: "fresh-native", mode: mode)
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
        Fixture.codexHome = link.path
        return (old, fresh, link, source)
    }

    private static func retarget(_ link: URL, to target: URL) throws {
        try Foundation.FileManager.default.removeItem(at: link)
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    }

    private static func submission(mode: String, change: String) async throws {
        let (old, fresh, link, source) = try native(mode)
        try login(source, account: "sleeping", mode: "file", expired: true)
        let original = try Data(contentsOf: source.appendingPathComponent("auth.json"))
        let nativeLogin = try AuthSwap$Codex.authData(home: old)
        let otherLogin = try AuthSwap$Codex.authData(home: fresh)
        var boundary = false
        Fixture.beforeDefaultsSynchronization = {
            guard !(UserDefaults.standard.dictionary(forKey: "codexRefreshAttempts") ?? [:]).isEmpty else { return }
            Fixture.beforeDefaultsSynchronization = nil
            boundary = true
            switch change {
            case "promote": try! retarget(link, to: source)
            case "retarget": try! retarget(link, to: fresh)
            case "mode": try! Fixture.codexMode(old, mode == "keyring" ? "file" : "keyring")
            case "source-login": try! login(source, account: "replacement", mode: "file", expired: true)
            case "source-owner":
                try! Foundation.FileManager.default.moveItem(at: source, to: source.appendingPathExtension("retired"))
                try! Foundation.FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
                try! original.write(to: source.appendingPathComponent("auth.json"))
            case "stable": break
            default: preconditionFailure("Unknown submission mutation")
            }
        }
        let result = await Renewal$Codex.shared.renew(columnID: "codex:source", home: source, force: false)
        print("POST mode=\(mode) change=\(change) boundary=\(boundary) calls=\(Fixture.refreshCalls) result=\(result)")
        try expect(boundary, "The actual quarantine synchronization was not reached")
        if change == "stable" {
            try expect(result == .renewed && Fixture.refreshCalls == 1, "An independent sleeping session could not renew")
        } else {
            try expect(Fixture.refreshCalls == 0 && result != .renewed,
                       "A stale reservation spent a grant after quarantine persistence")
            let attempts = UserDefaults.standard.dictionary(forKey: "codexRefreshAttempts") ?? [:]
            try expect(attempts.isEmpty, "A refused admission quarantined an unspent grant")
            if change == "promote" || change == "retarget" { try retarget(link, to: old) }
            if change == "mode" { try Fixture.codexMode(old, mode == "auto-file" ? "auto" : mode) }
            let retry = await Renewal$Codex.shared.renew(columnID: "codex:source", home: source, force: false)
            try expect(retry == .renewed && Fixture.refreshCalls == 1,
                       "A refused admission stranded its reservation or prevented a valid retry")
            try expect(Fixture.refreshInput == "synthetic-refresh-" + (change == "source-login" ? "replacement" : "sleeping"),
                       "Retry submitted a previous owner's grant instead of the current login")
        }
        try expect(try AuthSwap$Codex.authData(home: old) == nativeLogin
                   && AuthSwap$Codex.authData(home: fresh) == otherLogin,
                   "Renewal changed an independent native login")
    }

    private static func configuration(mode: String, change: Bool, switching: Bool) async throws {
        let (old, fresh, link, source) = try native(mode)
        try login(source, account: "incoming", mode: "file")
        let original = try AuthSwap$Codex.authData(home: old)
        let replacement = try AuthSwap$Codex.authData(home: fresh)
        let incoming = try AuthSwap$Codex.authData(home: source)
        Fixture.pauseAuthReadPath = old.appendingPathComponent("config.toml").path
        if switching {
            Fixture.authReadRequiresPath = AuthSwap$Codex.stashHome.appendingPathComponent("config.toml").path
        }
        let task = Task.detached { () -> Bool in
            do {
                if switching { try AuthSwap$Codex.activate(columnID: "codex:source", home: source) }
                else { _ = try AuthStorage$Codex(home: link).load(verifyingOwner: true) }
                return true
            } catch { return false }
        }
        defer { Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock() }
        for _ in 0..<400 {
            if Fixture.authReadPaused { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.authReadPaused, "The configuration read was not gated")
        if switching {
            let backup = try Data(contentsOf: AuthSwap$Codex.stashHome.appendingPathComponent("config.toml"))
            try expect(!backup.isEmpty, "The final verification gate preceded copyback")
        }
        if change { try retarget(link, to: fresh) }
        Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock()
        let succeeded = await task.value
        print("CONFIG mode=\(mode) retarget=\(change) switching=\(switching) success=\(succeeded)")
        try expect(succeeded == !change, "A configuration snapshot survived retargeting, or a stable context was refused")
        if change || !switching {
            try expect(try AuthSwap$Codex.authData(home: old) == original
                       && AuthSwap$Codex.authData(home: fresh) == replacement,
                       "A refused configuration snapshot changed either native login")
            try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "A refused configuration snapshot published an active marker")
        } else {
            try expect(try AuthSwap$Codex.authData(home: link) == incoming
                       && AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) == original,
                       "A stable switch failed to publish incoming auth and preserve primary")
        }
        try expect(Fixture.refreshCalls == 0, "Configuration verification issued a refresh POST")
    }

    private static func removal(mode: String, change: String) throws {
        Fixture.keychainExists = false
        let manager = Foundation.FileManager.default
        let oldRoot = Fixture.root.appendingPathComponent("profiles-old")
        let newRoot = Fixture.root.appendingPathComponent("profiles-new")
        let old = oldRoot.appendingPathComponent("account")
        let fresh = newRoot.appendingPathComponent("account")
        try login(old, account: "old-managed", mode: mode)
        try login(fresh, account: "new-managed", mode: "file")
        try manager.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: oldRoot)
        let logical = ProfileDirectories.codexRoot.appendingPathComponent("account")
        let account = DiscoveredAccount(id: "codex:account", provider: .codex, profileName: "account", source: .codexHome(logical))
        let expected = try Data(contentsOf: fresh.appendingPathComponent("auth.json"))
        let originalKey = Fixture.codexKey(old)
        let originalSecret = Fixture.codexKeychain[originalKey]
        var boundary = false
        var replacement: Data?
        let replaceLeaf: () throws -> Void = {
            try manager.moveItem(at: old, to: old.appendingPathExtension("retired"))
            try login(old, account: "replacement-leaf", mode: "file")
            replacement = try Data(contentsOf: old.appendingPathComponent("auth.json"))
        }
        if change == "move-root" || change == "move-owner" {
            Fixture.beforeDirectoryMove = { _, to in
                guard to.lastPathComponent.hasPrefix(".removed-") else { return }
                Fixture.beforeDirectoryMove = nil
                boundary = true
                if change == "move-root" { try retarget(ProfileDirectories.codexRoot, to: newRoot) }
                else { try replaceLeaf() }
            }
        } else {
            Fixture.beforeDirectoryCreate = { url in
                guard url.lastPathComponent.hasPrefix("recovered-") else { return }
                Fixture.beforeDirectoryCreate = nil
                boundary = true
                if change == "root" || change == "root-rollback" { try retarget(ProfileDirectories.codexRoot, to: newRoot) }
                if change == "leaf" { try replaceLeaf() }
            }
        }
        Fixture.denyCodexDelete = change == "root-rollback"
        var success = false
        do { try AccountRemoval.remove(account); success = true } catch { print("Removal refused: \(error)") }
        let retained = try? Data(contentsOf: fresh.appendingPathComponent("auth.json"))
        print("REMOVE mode=\(mode) change=\(change) boundary=\(boundary) success=\(success) independent=\(retained == expected)")
        try expect(boundary, "The actual recovery or directory-move boundary was not reached")
        try expect(retained == expected, "Account removal deleted an independent replacement file login")
        if let replacement {
            try expect(!success && (try? Data(contentsOf: old.appendingPathComponent("auth.json"))) == replacement,
                       "Removal consumed a replacement directory after recovery creation or move")
            try expect(Fixture.codexKeychain.values.contains { $0 == originalSecret },
                       "A refused replacement removal lost the reserved original Keychain login")
        } else if change == "root-rollback" {
            try expect(!success && account.codexHomeOwner?.matches(old) == true
                       && Fixture.codexKeychain[originalKey] == originalSecret,
                       "A refused deletion failed to restore its pinned directory or Keychain owner")
        } else {
            try expect(success && !manager.fileExists(atPath: old.path) && Fixture.codexKeychain[originalKey] == nil,
                       "Stable or redirected-root removal did not remove its original owner")
        }
        try expect(Fixture.refreshCalls == 0, "Removing an account issued a refresh POST")
    }
}
