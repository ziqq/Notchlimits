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

}
