// The Python harness prepends Authentication.swift's unchanged OS boundary support.
@main
enum Persistence$Codex {
    static func main() async {
        do {
            switch CommandLine.arguments[1] {
            case "codex-source-parent-file": try await sourceAccess(mode: "file", parent: true)
            case "codex-source-self-file": try await sourceAccess(mode: "file", parent: false)
            case "codex-source-parent-keyring": try await sourceAccess(mode: "keyring", parent: true)
            case "codex-source-parent-auto-file": try await sourceAccess(mode: "auto-file", parent: true)
            case "codex-source-parent-auto-keyring": try await sourceAccess(mode: "auto", parent: true)
            case "codex-source-self-no-execute": try await sourceAccess(mode: "file", parent: false, permission: 0o400)
            case "codex-copy-no-execute-file": try await copyAccess(mode: "file", permission: 0o400)
            case "codex-copy-no-access-file": try await copyAccess(mode: "file", permission: 0)
            case "codex-copy-no-execute-keyring": try await copyAccess(mode: "keyring", permission: 0o400)
            case "codex-copy-no-execute-auto-file": try await copyAccess(mode: "auto-file", permission: 0o400)
            case "codex-copy-no-execute-auto-keyring": try await copyAccess(mode: "auto", permission: 0o400)
            case "codex-source-removed-file": try await sourceRemoved()
            case "codex-source-replaced-keyring-same": try await sourceReplaced(freshLogin: false)
            case "codex-source-replaced-keyring-new": try await sourceReplaced(freshLogin: true)
            case "codex-quarantine-lost-file": try await restart(mode: "file", outcome: "lost")
            case "codex-quarantine-lost-keyring": try await restart(mode: "keyring", outcome: "lost")
            case "codex-quarantine-lost-auto": try await restart(mode: "auto", outcome: "lost")
            case "codex-quarantine-temporary-file": try await restart(mode: "file", outcome: "temporary")
            case "codex-quarantine-temporary-auto": try await restart(mode: "auto", outcome: "temporary")
            case "codex-quarantine-new-login": try await restart(mode: "file", outcome: "lost", freshLogin: true)
            case "codex-quarantine-rejected-file": try await restart(mode: "file", outcome: "rejected")
            case "codex-quarantine-rejected-keyring": try await restart(mode: "keyring", outcome: "rejected")
            case "codex-quarantine-unreadable-file": try await restart(mode: "file", outcome: "unreadable")
            case "codex-quarantine-unreadable-auto": try await restart(mode: "auto", outcome: "unreadable")
            case "codex-quarantine-fresh-access": try await restart(mode: "file", outcome: "lost", freshAccess: true)
            case "codex-quarantine-metadata": try await restart(mode: "file", outcome: "lost", metadataOnly: true)
            case "codex-quarantine-rotated-old-copy": try await restart(mode: "file", outcome: "rotated", restoreOld: true)
            case "codex-quarantine-rotated-current": try await restart(mode: "file", outcome: "rotated")
            case "codex-quarantine-nonrotating": try await restart(mode: "file", outcome: "nonrotating")
            case "codex-quarantine-write-refused": try await quarantineWriteRefused()
            case "codex-quarantine-flush-temporary": try await quarantineFlush(temporary: true)
            case "codex-quarantine-flush-success": try await quarantineFlush(temporary: false)
            case "codex-auth-file-missing": try await missingFile()
            case "codex-file-rollback-pending": try await fileRollback(pending: true)
            case "codex-file-rollback-inflight": try await fileRollback(pending: false)
            case "codex-copy-bootstrap-keyring": try await copyBootstrap(mode: "keyring")
            case "codex-copy-bootstrap-auto": try await copyBootstrap(mode: "auto")
            case "codex-copy-bootstrap-keyring-new-login": try await copyBootstrap(mode: "keyring", replacement: "new-login")
            case "codex-copy-bootstrap-auto-new-login": try await copyBootstrap(mode: "auto", replacement: "new-login")
            case "codex-copy-bootstrap-keyring-retarget": try await copyBootstrap(mode: "keyring", replacement: "retarget")
            case "codex-copy-bootstrap-auto-retarget": try await copyBootstrap(mode: "auto", replacement: "retarget")
            case "codex-copy-bootstrap-file": try await copyBootstrap(mode: "file")
            case "codex-copy-bootstrap-keyring-readded": try await copyBootstrap(mode: "keyring", replacement: "readded")
            case "codex-copy-bootstrap-auto-readded": try await copyBootstrap(mode: "auto", replacement: "readded")
            case "codex-copy-bootstrap-keyring-pending": try await copyBootstrap(mode: "keyring", pending: true)
            case "codex-copy-bootstrap-auto-pending": try await copyBootstrap(mode: "auto", pending: true)
            case "codex-copy-native-bootstrap-keyring": try await copyNativeRotation(mode: "keyring", primary: false)
            case "codex-copy-native-bootstrap-auto": try await copyNativeRotation(mode: "auto", primary: false)
            case "codex-copy-primary-bootstrap-keyring": try await copyNativeRotation(mode: "keyring", primary: true)
            case "codex-copy-primary-bootstrap-auto": try await copyNativeRotation(mode: "auto", primary: true)
            case "codex-copy-source-replaced-keyring": try await copySourceReplacement(mode: "keyring", denied: false)
            case "codex-copy-source-replaced-auto": try await copySourceReplacement(mode: "auto", denied: false)
            case "codex-copy-source-replaced-keyring-denied": try await copySourceReplacement(mode: "keyring", denied: true)
            case "codex-copy-source-replaced-auto-denied": try await copySourceReplacement(mode: "auto", denied: true)
            case "codex-quarantine-child": try await restartChild()
            default: throw Failure(description: "Unknown persistence scenario")
            }
        } catch { print("FAIL: \(error)"); exit(1) }
    }
    @MainActor
    private static func sourceAccess(mode: String, parent: Bool, permission: mode_t = 0) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("source-access")
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "native-other", mode: "file", expired: false)
        try Fixture.codexLogin(home, account: "source-access", mode: mode == "auto-file" ? "auto" : mode, expired: true)
        if mode == "auto-file" {
            let key = Fixture.codexKey(home)
            guard let data = Fixture.codexKeychain.removeValue(forKey: key) else { throw Failure(description: "Missing auto fixture") }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
        let account = DiscoveredAccount(id: "codex:source-access", provider: .codex,
                                       profileName: "source-access", source: .codexHome(home))
        let provider = Provider$Codex()
        Fixture.response = .heldRenewed
        let request = Task { await provider.fetch(account) }
        defer { Fixture.releaseRefresh() }
        for _ in 0..<400 {
            if Fixture.refreshCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.refreshCalls == 1, "POST did not reach the held response")
        let denied = parent ? ProfileDirectories.codexRoot : home
        try expect(chmod(denied.path, permission) == 0, "Could not restrict source access")
        if parent || permission == 0 {
            try expect(DirectoryIdentity.capture(home) == nil, "Source directory did not become unavailable")
        } else {
            try expect(DirectoryIdentity.capture(home) != nil, "The source directory itself should remain readable")
        }
        defer { _ = chmod(denied.path, 0o700) }
        Fixture.releaseRefresh()
        _ = await request.value
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        try expect(chmod(denied.path, 0o700) == 0, "Could not restore source permissions")
        _ = await provider.fetch(account)
        let fresh = Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated"
        print("REGRESSION source mode=\(mode) parent=\(parent) quit=\(quit) fresh=\(fresh) posts=\(Fixture.refreshCalls)")
        try expect(!quit, "Unavailable source was treated as retired: normal quit could lose the accepted rotation")
        try expect(fresh && Fixture.refreshCalls == 1, "Restored source lost its accepted rotation or replayed the POST")
    }

    @MainActor
    private static func copyAccess(mode: String, permission: mode_t) async throws {
        let source = ProfileDirectories.codexRoot.appendingPathComponent("copy-source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("copy-unavailable")
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "native-other", mode: "file", expired: false)
        try Fixture.codexLogin(source, account: "shared-copy", mode: "file", expired: true)
        let original = try Data(contentsOf: source.appendingPathComponent("auth.json"))
        try Fixture.codexMode(copy, mode == "auto-file" ? "auto" : mode)
        let copyKey = Fixture.codexKey(copy)
        if mode == "file" || mode == "auto-file" { try original.write(to: copy.appendingPathComponent("auth.json")) }
        else { Fixture.codexKeychain[copyKey] = original }
        guard let owner = DirectoryIdentity.capture(copy) else { throw Failure(description: "Missing copied owner") }
        let account = DiscoveredAccount(id: "codex:copy-source", provider: .codex,
                                       profileName: "copy-source", source: .codexHome(source))
        Fixture.response = .heldRenewed
        let request = Task { await Provider$Codex().fetch(account) }
        defer { Fixture.releaseRefresh() }
        for _ in 0..<400 {
            if Fixture.refreshCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.refreshCalls == 1, "POST did not reach the held response")
        try expect(chmod(copy.path, permission) == 0, "Could not change copy permissions")
        defer { _ = chmod(copy.path, 0o700) }
        if permission != 0 {
            try expect(owner.matches(copy), "Readable directory capture unexpectedly required execute permission")
            try expect(!Foundation.FileManager.default.fileExists(atPath: copy.appendingPathComponent("auth.json").path),
                       "The OS did not hide the inaccessible file")
        }
        Fixture.releaseRefresh()
        _ = await request.value
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        try expect(chmod(copy.path, 0o700) == 0, "Could not restore copy access")
        let freshBeforeRetry = Renewal$Codex.refreshToken(copy.appendingPathComponent("auth.json")) == "synthetic-rotated"
        print("REGRESSION copy mode=\(mode) permission=\(permission) quit=\(quit) fresh=\(freshBeforeRetry) posts=\(Fixture.refreshCalls)")
        try expect(!quit || freshBeforeRetry, "Inaccessible copied file was treated as absent: normal quit leaves a spent grant")
        if !freshBeforeRetry {
            _ = await Provider$Codex().fetch(account)
            try expect(Renewal$Codex.refreshToken(copy.appendingPathComponent("auth.json")) == "synthetic-rotated",
                       "Restoring copy access did not persist the accepted rotation")
        }
        try expect(Fixture.refreshCalls == 1, "Copy persistence replayed its POST")
    }

    @MainActor
    private static func waitForPOST() async throws {
        for _ in 0..<400 {
            if Fixture.refreshCalls == 1 { return }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        throw Failure(description: "Refresh did not reach the response barrier")
    }

    @MainActor
    private static func sourceRemoved() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("removed-source")
        try Fixture.codexLogin(home, account: "removed-source", mode: "file", expired: true)
        let account = DiscoveredAccount(id: "codex:removed-source", provider: .codex,
                                       profileName: "removed-source", source: .codexHome(home))
        Fixture.response = .heldRenewed
        let request = Task { await Provider$Codex().fetch(account) }
        defer { Fixture.releaseRefresh() }
        try await waitForPOST()
        try AccountRemoval.remove(account)
        Fixture.releaseRefresh()
        _ = await request.value
        try expect(!Foundation.FileManager.default.fileExists(atPath: home.path),
                   "The accepted result recreated an explicitly removed source")
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit && Fixture.refreshCalls == 1, "Confirmed removal could not retire its pending owner")
    }

    @MainActor
    private static func sourceReplaced(freshLogin: Bool) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("replaced-source")
        try Fixture.codexLogin(home, account: "replaced-source", mode: "keyring", expired: true)
        let key = Fixture.codexKey(home)
        guard let original = Fixture.codexKeychain[key], let owner = DirectoryIdentity.capture(home) else {
            throw Failure(description: "Missing original source")
        }
        Fixture.response = .heldRenewed
        let request = Task { await Renewal$Codex.shared.renew(columnID: "codex:replaced-source", home: home, force: true) }
        defer { Fixture.releaseRefresh() }
        try await waitForPOST()
        try Foundation.FileManager.default.removeItem(at: home)
        try Fixture.codexMode(home, "keyring")
        var replacement = original
        if freshLogin {
            var root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            var tokens = root["tokens"] as! [String: Any]
            tokens["refresh_token"] = "independent-replacement-grant"
            root["tokens"] = tokens
            replacement = try JSONSerialization.data(withJSONObject: root)
        }
        Fixture.codexKeychain[key] = replacement
        try expect(!owner.matches(home), "The replacement reused the original directory owner")
        Fixture.releaseRefresh()
        _ = await request.value
        if freshLogin {
            try expect(Fixture.codexKeychain[key] == replacement, "Renewal overwrote an independent Keychain login")
        } else {
            // A recreated directory keeps the same native Keychain namespace.
            try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated",
                       "Directory bootstrap discarded the unchanged Keychain owner's accepted rotation")
        }
        try expect(Fixture.refreshCalls == 1, "Replacement handling replayed the original grant")
    }

    private static func strings(in value: Any) -> [String] {
        if let string = value as? String { return [string] }
        if let data = value as? Data { return String(data: data, encoding: .utf8).map { [$0] } ?? [] }
        if let dictionary = value as? [String: Any] {
            return dictionary.flatMap { [$0.key] + strings(in: $0.value) }
        }
        if let array = value as? [Any] { return array.flatMap { strings(in: $0) } }
        return []
    }

    @MainActor
    private static func restart(mode: String, outcome: String, freshLogin: Bool = false,
                                freshAccess: Bool = false, metadataOnly: Bool = false,
                                restoreOld: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("restart-source")
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "native-other", mode: "file", expired: false)
        try Fixture.codexMode(home, mode)
        let grant = outcome == "nonrotating" ? "synthetic-rotated" : "synthetic-already-spent"
        try Fixture.writeAuth(home, account: "restart-source", refresh: grant, expired: true)
        let original = try Data(contentsOf: home.appendingPathComponent("auth.json"))
        if mode != "file" {
            Fixture.codexKeychain[Fixture.codexKey(home)] = original
            try Foundation.FileManager.default.removeItem(at: home.appendingPathComponent("auth.json"))
        }
        switch outcome {
        case "temporary": Fixture.response = .temporary
        case "lost": Fixture.response = .lost
        case "unreadable": Fixture.response = .unreadable
        case "rejected": Fixture.rejectSpentRefresh = true
        default: Fixture.response = .renewed
        }
        _ = await Renewal$Codex.shared.renew(columnID: "codex:restart-source", home: home, force: true)
        if ["lost", "unreadable", "rejected"].contains(outcome) {
            _ = await Renewal$Codex.shared.renew(columnID: "codex:restart-source", home: home, force: true)
            try expect(Fixture.refreshCalls == 1, "Same-process quarantine replayed its grant")
        }
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit, "A durable attempt could not terminate normally")
        let values = UserDefaults.standard.dictionaryRepresentation()
        let originalAccess = Provider$Codex.parseAuth(original)!.accessToken
        try expect(!strings(in: values).contains(where: { $0.contains(grant) || $0.contains(originalAccess) }),
                   "Preferences contain a raw refresh or access token")
        let state: [String: Any] = ["defaults": values, "keychain": Fixture.codexKeychain,
            "mode": mode, "outcome": outcome, "freshLogin": freshLogin, "freshAccess": freshAccess,
            "metadataOnly": metadataOnly, "restoreOld": restoreOld, "original": original]
        try PropertyListSerialization.data(fromPropertyList: state, format: .binary, options: 0)
            .write(to: Fixture.root.appendingPathComponent("quarantine-checkpoint.plist"))
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = ["codex-quarantine-child", Fixture.root.path]
        let output = Pipe(); process.standardOutput = output; process.standardError = output
        try process.run(); process.waitUntilExit()
        let diagnostic = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        print(diagnostic)
        try expect(process.terminationStatus == 0, "Normal restart violated grant ownership: " + diagnostic)
    }

    @MainActor
    private static func restartChild() async throws {
        let checkpoint = try Data(contentsOf: Fixture.root.appendingPathComponent("quarantine-checkpoint.plist"))
        guard let state = try PropertyListSerialization.propertyList(from: checkpoint, format: nil) as? [String: Any],
              let defaults = state["defaults"] as? [String: Any], let keychain = state["keychain"] as? [String: Data],
              let mode = state["mode"] as? String, let outcome = state["outcome"] as? String,
              let freshLogin = state["freshLogin"] as? Bool, let freshAccess = state["freshAccess"] as? Bool,
              let metadataOnly = state["metadataOnly"] as? Bool, let restoreOld = state["restoreOld"] as? Bool,
              let original = state["original"] as? Data else { throw Failure(description: "Invalid restart checkpoint") }
        for (key, value) in defaults { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = keychain
        Fixture.rejectSpentRefresh = outcome != "temporary" && outcome != "nonrotating"
        let home = ProfileDirectories.codexRoot.appendingPathComponent("restart-source")
        if freshLogin || freshAccess || metadataOnly || restoreOld {
            var root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            var tokens = root["tokens"] as! [String: Any]
            if freshLogin { tokens["refresh_token"] = "independent-new-grant" }
            if freshAccess { tokens["access_token"] = Fixture.accessToken(expiresAt: Date().addingTimeInterval(86_400).timeIntervalSince1970) }
            root["tokens"] = tokens
            if metadataOnly { root["local_metadata"] = "changed after restart" }
            let data = try JSONSerialization.data(withJSONObject: root)
            if mode == "file" { try data.write(to: home.appendingPathComponent("auth.json")) }
            else { Fixture.codexKeychain[Fixture.codexKey(home)] = data }
        }
        let result = await Renewal$Codex.shared.renew(columnID: "codex:restart-source", home: home, force: true)
        let canPost = freshLogin || outcome == "temporary" || outcome == "nonrotating" || outcome == "rotated" && !restoreOld
        print("RESTART mode=\(mode) outcome=\(outcome) newLogin=\(freshLogin) posts=\(Fixture.refreshCalls) result=\(result)")
        try expect(Fixture.refreshCalls == (canPost ? 1 : 0), "Restart replayed a quarantined grant or blocked an independent grant")
        if !canPost {
            let expected: Renewal$Codex.Result = freshAccess ? .renewed : (outcome == "rejected" ? .rejected : .uncertain)
            try expect(result == expected, "Restart classified another session or metadata change as the rejected login")
        } else { try expect(result == .renewed, "The independently usable grant could not renew") }
    }

    @MainActor
    private static func quarantineWriteRefused() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("ledger-refused")
        try Fixture.codexLogin(home, account: "ledger-refused", mode: "file", expired: true)
        Fixture.failDefaultsSynchronization = true
        let first = await Renewal$Codex.shared.renew(columnID: "codex:ledger-refused", home: home, force: true)
        try expect(first == .unavailable && Fixture.refreshCalls == 0,
                   "A grant was submitted before its quarantine became durable")
        let deniedQuit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        try expect(!deniedQuit, "Quit discarded an unconfirmed preference cleanup")
        Fixture.failDefaultsSynchronization = false
        let second = await Renewal$Codex.shared.renew(columnID: "codex:ledger-refused", home: home, force: true)
        try expect(second == .renewed && Fixture.refreshCalls == 1,
                   "Restored preference storage required another login or replayed a POST")
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit, "A recovered quarantine could not drain")
    }

    @MainActor
    private static func quarantineFlush(temporary: Bool) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("ledger-flush")
        try Fixture.codexLogin(home, account: "ledger-flush", mode: "file", expired: true)
        Fixture.response = temporary ? .heldTemporary : .heldRenewed
        let request = Task { await Renewal$Codex.shared.renew(columnID: "codex:ledger-flush", home: home, force: true) }
        defer { Fixture.releaseRefresh(); Fixture.failDefaultsSynchronization = false }
        try await waitForPOST()
        Fixture.failDefaultsSynchronization = true
        Fixture.releaseRefresh()
        _ = await request.value
        let deniedQuit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        try expect(!deniedQuit, "Normal quit ignored a refused quarantine update")
        Fixture.failDefaultsSynchronization = false
        let ready = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        try expect(ready, "Recovered preference storage could not drain")
        if temporary {
            Fixture.response = .renewed
            let result = await Renewal$Codex.shared.renew(columnID: "codex:ledger-flush", home: home, force: true)
            try expect(result == .renewed && Fixture.refreshCalls == 2, "Known temporary refusal left a false quarantine")
        } else {
            try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated"
                       && Fixture.refreshCalls == 1, "Quarantine flush replayed or lost a successful rotation")
        }
    }

    @MainActor
    private static func missingFile() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("missing-auth-file")
        try Fixture.codexMode(home, "file")
        let account = DiscoveredAccount(id: "codex:missing-auth-file", provider: .codex,
                                       profileName: "missing-auth-file", source: .codexHome(home))
        let result = await Provider$Codex().fetch(account)
        guard case .reauth = result else { throw Failure(description: "Confirmed missing auth became an I/O failure") }
        try expect(Fixture.refreshCalls == 0, "Missing credentials submitted an OAuth request")
    }

    @MainActor
    private static func fileRollback(pending: Bool) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("file-rollback")
        try Fixture.codexMode(home, "auto")
        try Fixture.writeAuth(home, account: "file-rollback", refresh: "file-rollback-grant", expired: true)
        let account = DiscoveredAccount(id: "codex:file-rollback", provider: .codex,
                                       profileName: "file-rollback", source: .codexHome(home))
        let provider = Provider$Codex()
        var request: Task<FetchOutcome, Never>?
        if pending {
            Fixture.failCodexFileWrite = true
            _ = await provider.fetch(account)
        } else {
            Fixture.response = .heldRenewed
            request = Task { await provider.fetch(account) }
            try await waitForPOST()
        }
        defer { Fixture.releaseRefresh(); Fixture.failCodexFileWrite = false; Fixture.denyCodexDelete = false }
        try expect(Fixture.refreshCalls == 1, "The original rotation was not submitted")
        Fixture.denyCodexDelete = true
        Fixture.beforeCredentialDelete = {
            try! Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            try! Data("native-bootstrap".utf8).write(to: home.appendingPathComponent("native-settings"))
        }
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        try expect(refused && Provider$Codex.readAuth(codexHome: home)?.accountID == "file-rollback",
                   "Refused removal did not restore its own file login")
        Fixture.denyCodexDelete = false
        Fixture.failCodexFileWrite = false
        if let request { Fixture.releaseRefresh(); _ = await request.value }
        _ = await provider.fetch(account)
        try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated"
                   && Fixture.refreshCalls == 1, "Authorized file rollback discarded or replayed its accepted rotation")
        try expect(try String(contentsOf: home.appendingPathComponent("native-settings")) == "native-bootstrap",
                   "Renewal after rollback changed the native bootstrap data")
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit, "Restored file owner could not drain")
    }

    @MainActor
    private static func copyBootstrap(mode: String, replacement: String = "same", pending: Bool = false) async throws {
        let source = ProfileDirectories.codexRoot.appendingPathComponent("bootstrap-source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("bootstrap-copy")
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "independent-native", mode: "file")
        try Fixture.codexLogin(source, account: "shared-session", mode: "file", expired: true)
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: source.appendingPathComponent("auth.json"))) as! [String: Any]
        var tokens = json["tokens"] as! [String: Any]
        tokens["account_id"] = "copy-routing"
        json["tokens"] = tokens
        json["local_metadata"] = "preserved"
        let original = try JSONSerialization.data(withJSONObject: json)
        try Fixture.codexMode(copy, mode)
        let key = Fixture.codexKey(copy)
        if mode == "file" { try original.write(to: copy.appendingPathComponent("auth.json")) }
        else { Fixture.codexKeychain[key] = original }
        guard let owner = DirectoryIdentity.capture(copy) else { throw Failure(description: "Missing copy owner") }
        let account = DiscoveredAccount(id: "codex:bootstrap-copy", provider: .codex,
                                       profileName: "bootstrap-copy", source: .codexHome(copy))
        let sourceAccount = DiscoveredAccount(id: "codex:bootstrap-source", provider: .codex,
                                             profileName: "bootstrap-source", source: .codexHome(source))
        defer { Fixture.releaseRefresh(); Fixture.denyCodexWriteAccount = nil }
        var request: Task<Renewal$Codex.Result, Never>?
        if pending {
            Fixture.denyCodexWriteAccount = key
            let result = await Renewal$Codex.shared.renew(columnID: sourceAccount.id, home: source, force: true)
            try expect(result == .unavailable && Fixture.refreshCalls == 1, "Copy write refusal did not retain the accepted rotation")
            let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
            await Renewal$Codex.shared.cancelTermination()
            try expect(!quit, "Pending copy was discarded before its namespace became writable")
        } else {
            Fixture.response = .heldRenewed
            request = Task { await Renewal$Codex.shared.renew(columnID: sourceAccount.id, home: source, force: true) }
            try await waitForPOST()
        }
        if replacement == "readded" { try AccountRemoval.remove(account) }
        else { try Foundation.FileManager.default.removeItem(at: copy) }
        let target = Fixture.root.appendingPathComponent("independent-copy-target")
        if replacement == "retarget" {
            try Fixture.codexLogin(target, account: "independent-target", mode: "file")
            try Foundation.FileManager.default.createSymbolicLink(at: copy, withDestinationURL: target)
        } else { try Fixture.codexMode(copy, mode) }
        try expect(!owner.matches(copy) && (Fixture.codexKey(copy) == key) == (replacement != "retarget"),
                   "Bootstrap did not establish its expected native namespace")
        if replacement == "new-login" {
            tokens["refresh_token"] = "independent-new-login"
            json["tokens"] = tokens
        }
        json["local_metadata"] = "changed-during-request"
        let expected: Data
        if replacement == "retarget" { expected = try Data(contentsOf: target.appendingPathComponent("auth.json")) }
        else {
            expected = try JSONSerialization.data(withJSONObject: json)
            if mode == "file" { try expected.write(to: copy.appendingPathComponent("auth.json")) }
            else { Fixture.codexKeychain[key] = expected }
        }
        Fixture.denyCodexWriteAccount = nil
        if let request { Fixture.releaseRefresh(); _ = await request.value }
        else { _ = await Renewal$Codex.shared.renew(columnID: sourceAccount.id, home: source, force: false) }
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        await Renewal$Codex.shared.cancelTermination()
        guard let stored = try AuthStorage$Codex(home: copy).load()?.data else {
            throw Failure(description: "Copy credentials disappeared after bootstrap")
        }
        let preserved = replacement != "same" || mode == "file"
        print("BOOTSTRAP mode=\(mode) replacement=\(replacement) pending=\(pending) quit=\(quit) posts=\(Fixture.refreshCalls)")
        if replacement == "retarget" {
            try expect(stored == expected && Fixture.codexKeychain[key] == original,
                       "A retargeted path changed another native namespace or its file login")
        } else if preserved {
            try expect(stored == expected, "A retired file owner or independent/re-added Keychain login was overwritten")
            if replacement != "new-login" {
                let replay = await Renewal$Codex.shared.renew(columnID: account.id, home: copy, force: false)
                try expect(Fixture.refreshCalls == 1 && replay != .renewed, "A replacement replayed the spent grant")
            }
        } else {
            let value = try JSONSerialization.jsonObject(with: stored) as! [String: Any]
            let fresh = (value["tokens"] as? [String: Any])?["refresh_token"] as? String
            try expect(fresh == "synthetic-rotated", "The unchanged Keychain namespace retained its spent copied grant")
            try expect(Provider$Codex.parseAuth(stored)?.accountID == "copy-routing"
                       && value["local_metadata"] as? String == "changed-during-request",
                       "Copy renewal changed routing or current metadata")
            try AccountRemoval.remove(sourceAccount)
            try AuthSwap$Codex.activate(columnID: account.id, home: copy)
            try expect(Renewal$Codex.refreshToken(AuthSwap$Codex.baseHome.appendingPathComponent("auth.json")) == fresh,
                       "Removing the source or switching published the spent copy")
        }
        try expect(quit && Fixture.refreshCalls == 1, "Bootstrap lost a pending rotation or repeated its POST")
    }

    @MainActor
    private static func copyNativeRotation(mode: String, primary: Bool) async throws {
        let base = AuthSwap$Codex.baseHome
        let source = ProfileDirectories.codexRoot.appendingPathComponent("native-source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("native-copy")
        try Fixture.codexLogin(base, account: primary ? "shared-primary" : "independent-native", mode: "file")
        try Fixture.codexLogin(source, account: primary ? "independent-source" : "shared-selected", mode: "file")
        let shared = primary ? base : source
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: shared.appendingPathComponent("auth.json"))) as! [String: Any]
        var tokens = json["tokens"] as! [String: Any]
        tokens["account_id"] = "native-copy-routing"
        json["tokens"] = tokens
        json["local_metadata"] = "native-copy-metadata"
        try Fixture.codexMode(copy, mode)
        let key = Fixture.codexKey(copy)
        Fixture.codexKeychain[key] = try JSONSerialization.data(withJSONObject: json)
        guard let owner = DirectoryIdentity.capture(copy) else { throw Failure(description: "Missing native copy owner") }
        try AuthSwap$Codex.activate(columnID: "codex:native-source", home: source)
        if primary { try AuthSwap$Codex.restoreDefault() }
        try Fixture.writeAuth(base, account: primary ? "shared-primary" : "shared-selected",
                              refresh: "native-client-rotation", expired: false)
        try Foundation.FileManager.default.removeItem(at: copy)
        try Fixture.codexMode(copy, mode)
        try expect(!owner.matches(copy) && Fixture.codexKey(copy) == key, "Native copy bootstrap retained its directory owner")
        if primary {
            _ = await Renewal$Codex.shared.renew(columnID: "codex:native-copy", home: copy, force: true)
        } else { try AuthSwap$Codex.restoreDefault() }
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        guard let stored = Fixture.codexKeychain[key],
              let value = try JSONSerialization.jsonObject(with: stored) as? [String: Any] else {
            throw Failure(description: "Native copy credentials disappeared")
        }
        let refresh = (value["tokens"] as? [String: Any])?["refresh_token"] as? String
        print("NATIVE BOOTSTRAP mode=\(mode) primary=\(primary) quit=\(quit) posts=\(Fixture.refreshCalls)")
        try expect(quit && Fixture.refreshCalls == 0 && refresh == "native-client-rotation",
                   "Native rotation left a spent Keychain copy or submitted its old grant")
        try expect(Provider$Codex.parseAuth(stored)?.accountID == "native-copy-routing"
                   && value["local_metadata"] as? String == "native-copy-metadata",
                   "Native copyback changed routing or metadata")
    }

    @MainActor
    private static func copySourceReplacement(mode: String, denied: Bool) async throws {
        let source = ProfileDirectories.codexRoot.appendingPathComponent("replaced-copy-source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("surviving-copy")
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "independent-native", mode: "file")
        try Fixture.codexLogin(source, account: "old-source", mode: "file", expired: true)
        var json = try JSONSerialization.jsonObject(with: Data(contentsOf: source.appendingPathComponent("auth.json"))) as! [String: Any]
        var tokens = json["tokens"] as! [String: Any]
        tokens["account_id"] = "surviving-copy-routing"
        json["tokens"] = tokens
        json["local_metadata"] = "surviving-copy-metadata"
        try Fixture.codexMode(copy, mode)
        let key = Fixture.codexKey(copy)
        Fixture.codexKeychain[key] = try JSONSerialization.data(withJSONObject: json)
        guard let oldSource = DirectoryIdentity.capture(source), let oldCopy = DirectoryIdentity.capture(copy) else {
            throw Failure(description: "Missing original copy owners")
        }
        Fixture.response = .heldRenewed
        let request = Task { await Renewal$Codex.shared.renew(columnID: "codex:replaced-copy-source", home: source, force: true) }
        defer { Fixture.releaseRefresh(); Fixture.denyCodexWriteAccount = nil }
        try await waitForPOST()
        try Foundation.FileManager.default.removeItem(at: source)
        try Fixture.codexLogin(source, account: "independent-replacement", mode: "file")
        let independent = try Data(contentsOf: source.appendingPathComponent("auth.json"))
        try Foundation.FileManager.default.removeItem(at: copy)
        try Fixture.codexMode(copy, mode)
        try expect(!oldSource.matches(source) && !oldCopy.matches(copy) && Fixture.codexKey(copy) == key,
                   "Replacement did not change both directory owners within the copied Keychain namespace")
        if denied { Fixture.denyCodexWriteAccount = key }
        Fixture.releaseRefresh()
        let result = await request.value
        if denied {
            try expect(result == .unavailable, "Source replacement discarded the refused copy's accepted rotation")
            let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
            await Renewal$Codex.shared.cancelTermination()
            try expect(!quit, "Normal quit abandoned the only live copy after source replacement")
            Fixture.denyCodexWriteAccount = nil
        }
        _ = await Renewal$Codex.shared.renew(columnID: "codex:surviving-copy", home: copy, force: false)
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        guard let stored = Fixture.codexKeychain[key],
              let value = try JSONSerialization.jsonObject(with: stored) as? [String: Any] else {
            throw Failure(description: "Surviving copy credentials disappeared")
        }
        let refresh = (value["tokens"] as? [String: Any])?["refresh_token"] as? String
        try expect(quit && refresh == "synthetic-rotated" && Fixture.refreshCalls == 1,
                   "The surviving copy lost or replayed the accepted refresh after source replacement")
        try expect(Provider$Codex.parseAuth(stored)?.accountID == "surviving-copy-routing"
                   && value["local_metadata"] as? String == "surviving-copy-metadata",
                   "Surviving copy persistence changed routing or metadata")
        try expect(try Data(contentsOf: source.appendingPathComponent("auth.json")) == independent,
                   "Copy persistence overwrote the replacement source login")
    }

}
