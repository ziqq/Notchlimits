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
            case "codex-native-grant-fresh-replaced-file": try await nativeGrant(mode: "file", action: "replace", expired: false)
            case "codex-native-grant-fresh-replaced-auto-file": try await nativeGrant(mode: "auto-file", action: "replace", expired: false)
            case "codex-native-grant-fresh-stable-file": try await nativeGrant(mode: "file", action: "stable", expired: false)
            case "codex-native-grant-fresh-replaced-keyring": try await nativeGrant(mode: "keyring", action: "replace", expired: false)
            case "codex-native-grant-fresh-independent-file": try await nativeGrant(mode: "file", action: "independent", expired: false)
            case "codex-native-grant-fresh-independent-auto-file": try await nativeGrant(mode: "auto-file", action: "independent", expired: false)
            case "codex-native-grant-fresh-late-routing-file": try await nativeGrant(mode: "file", action: "late-routing", expired: false)
            case "codex-native-grant-fresh-late-routing-keyring": try await nativeGrant(mode: "keyring", action: "late-routing", expired: false)
            case "codex-native-grant-fresh-late-same-routing-file": try await nativeGrant(mode: "file", action: "late-same", expired: false)
            case "codex-native-grant-fresh-late-same-routing-keyring": try await nativeGrant(mode: "keyring", action: "late-same", expired: false)
            case "codex-native-grant-expired-replaced-file": try await nativeGrant(mode: "file", action: "replace", expired: true)
            case "codex-native-grant-expired-replaced-auto-file": try await nativeGrant(mode: "auto-file", action: "replace", expired: true)
            case "codex-native-grant-expired-stable-file": try await nativeGrant(mode: "file", action: "stable", expired: true)
            case "codex-native-grant-expired-replaced-keyring": try await nativeGrant(mode: "keyring", action: "replace", expired: true)
            case "codex-native-grant-expired-independent-file": try await nativeGrant(mode: "file", action: "independent", expired: true)
            case "codex-native-grant-expired-independent-auto-file": try await nativeGrant(mode: "auto-file", action: "independent", expired: true)
            case "codex-native-grant-expired-late-routing-file": try await nativeGrant(mode: "file", action: "late-routing", expired: true)
            case "codex-native-grant-expired-late-routing-keyring": try await nativeGrant(mode: "keyring", action: "late-routing", expired: true)
            case "codex-native-grant-expired-late-same-routing-file": try await nativeGrant(mode: "file", action: "late-same", expired: true)
            case "codex-native-grant-expired-late-same-routing-keyring": try await nativeGrant(mode: "keyring", action: "late-same", expired: true)
            case "codex-native-grant-restart-file-unobserved": try await nativeGrant(mode: "file", action: "replace", expired: true, restart: true, handoff: false)
            case "codex-native-grant-restart-file-retired": try await nativeGrant(mode: "file", action: "late-routing", expired: true, restart: true, handoff: true)
            case "codex-native-grant-observe-file": try await nativeGrantControl(mode: "file", action: "observe")
            case "codex-native-grant-selected-file": try await nativeGrantControl(mode: "file", action: "selected")
            case "codex-native-grant-sync-file": try await nativeGrantControl(mode: "file", action: "sync")
            case "codex-native-grant-handoff-file": try await nativeGrantControl(mode: "file", action: "handoff")
            case "codex-native-grant-rollback-file": try await nativeGrantControl(mode: "file", action: "rollback")
            case "codex-native-grant-restart-keyring-unobserved": try await nativeGrant(mode: "keyring", action: "replace", expired: true, restart: true, handoff: false)
            case "codex-native-grant-restart-keyring-retired": try await nativeGrant(mode: "keyring", action: "late-routing", expired: true, restart: true, handoff: true)
            case "codex-native-grant-observe-keyring": try await nativeGrantControl(mode: "keyring", action: "observe")
            case "codex-native-grant-selected-keyring": try await nativeGrantControl(mode: "keyring", action: "selected")
            case "codex-native-grant-sync-keyring": try await nativeGrantControl(mode: "keyring", action: "sync")
            case "codex-native-grant-handoff-keyring": try await nativeGrantControl(mode: "keyring", action: "handoff")
            case "codex-native-grant-rollback-keyring": try await nativeGrantControl(mode: "keyring", action: "rollback")
            case "codex-native-grant-path-retarget": try await nativeGrantPath(retarget: true)
            case "codex-native-grant-path-stable": try await nativeGrantPath(retarget: false)
            case "codex-native-grant-alias-file": try await nativeGrantAlias(mode: "file")
            case "codex-native-grant-alias-keyring": try await nativeGrantAlias(mode: "keyring")
            case "codex-native-boundary-publish-spent-file-unobserved": try nativeGrantPublication(mode: "file", kind: "spent", observed: false)
            case "codex-native-boundary-publish-spent-file-observed": try nativeGrantPublication(mode: "file", kind: "spent", observed: true)
            case "codex-native-boundary-publish-spent-keyring-unobserved": try nativeGrantPublication(mode: "keyring", kind: "spent", observed: false)
            case "codex-native-boundary-publish-spent-keyring-observed": try nativeGrantPublication(mode: "keyring", kind: "spent", observed: true)
            case "codex-native-boundary-publish-spent-auto-file-unobserved": try nativeGrantPublication(mode: "auto-file", kind: "spent", observed: false)
            case "codex-native-boundary-publish-spent-auto-file-observed": try nativeGrantPublication(mode: "auto-file", kind: "spent", observed: true)
            case "codex-native-boundary-publish-spent-auto-keyring-unobserved": try nativeGrantPublication(mode: "auto-keyring", kind: "spent", observed: false)
            case "codex-native-boundary-publish-spent-auto-keyring-observed": try nativeGrantPublication(mode: "auto-keyring", kind: "spent", observed: true)
            case "codex-native-boundary-publish-independent-file": try nativeGrantPublication(mode: "file", kind: "independent")
            case "codex-native-boundary-publish-unchanged-file": try nativeGrantPublication(mode: "file", kind: "unchanged")
            case "codex-native-boundary-publish-independent-keyring": try nativeGrantPublication(mode: "keyring", kind: "independent")
            case "codex-native-boundary-publish-unchanged-keyring": try nativeGrantPublication(mode: "keyring", kind: "unchanged")
            case "codex-native-boundary-remove-spent-file": try await nativeGrantRemoval(mode: "file", kind: "spent")
            case "codex-native-boundary-remove-spent-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "spent")
            case "codex-native-boundary-remove-spent-auto-file": try await nativeGrantRemoval(mode: "auto-file", kind: "spent")
            case "codex-native-boundary-remove-spent-auto-keyring": try await nativeGrantRemoval(mode: "auto-keyring", kind: "spent")
            case "codex-native-boundary-remove-independent-file": try await nativeGrantRemoval(mode: "file", kind: "independent")
            case "codex-native-boundary-remove-unchanged-file": try await nativeGrantRemoval(mode: "file", kind: "unchanged")
            case "codex-native-boundary-remove-restart-file": try await nativeGrantRemoval(mode: "file", kind: "restart")
            case "codex-native-boundary-remove-sync-refused-file": try await nativeGrantRemoval(mode: "file", kind: "sync-refused")
            case "codex-native-boundary-remove-delete-refused-file": try await nativeGrantRemoval(mode: "file", kind: "delete-refused")
            case "codex-native-boundary-remove-independent-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "independent")
            case "codex-native-boundary-remove-unchanged-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "unchanged")
            case "codex-native-boundary-remove-restart-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "restart")
            case "codex-native-boundary-remove-sync-refused-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "sync-refused")
            case "codex-native-boundary-remove-delete-refused-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "delete-refused")
            case "codex-native-boundary-remove-read-refused-keyring": try await nativeGrantRemoval(mode: "keyring", kind: "read-refused")
            case "codex-native-boundary-remove-read-refused-auto-keyring": try await nativeGrantRemoval(mode: "auto-keyring", kind: "read-refused")
            case "codex-native-grant-child": try await nativeGrantChild()
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

    @MainActor
    private static func nativeGrant(mode: String, action: String, expired: Bool,
                                    restart: Bool = false, handoff: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("native-grant-copy")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("native-grant-other")
        let late = ProfileDirectories.codexRoot.appendingPathComponent("native-grant-late")
        let fileBackend = mode == "file" || mode == "auto-file"
        try nativeGrantAuth(base, mode: "file", account: "native-primary", grant: "synthetic-already-spent", expired: expired)
        let original = try Data(contentsOf: base.appendingPathComponent("auth.json"))
        try Fixture.codexMode(copy, mode == "auto-file" ? "auto" : mode)
        if fileBackend { try original.write(to: copy.appendingPathComponent("auth.json")) }
        else { Fixture.codexKeychain[Fixture.codexKey(copy)] = original }
        guard let owner = DirectoryIdentity.capture(copy) else { throw Failure(description: "Missing original native copy") }
        try Fixture.codexLogin(other, account: "independent-other", mode: "file")
        try AuthSwap$Codex.activate(columnID: "codex:native-grant-other", home: other)
        try AuthSwap$Codex.restoreDefault()
        try Fixture.writeAuth(base, account: "native-primary", refresh: "native-current-grant", expired: false)
        if handoff {
            _ = await Provider$Codex().fetch(DiscoveredAccount(id: "codex:native-grant-copy", provider: .codex,
                profileName: "native-grant-copy", source: .codexHome(copy)))
            try AuthSwap$Codex.activate(columnID: "codex:native-grant-other", home: other)
        }
        let native = try AuthSwap$Codex.authData(home: base)
        var target = copy
        if action == "replace" || action == "independent" {
            try Foundation.FileManager.default.removeItem(at: copy)
            try Fixture.codexMode(copy, mode == "auto-file" ? "auto" : mode)
            try expect(!owner.matches(copy), "Native copy bootstrap retained its physical owner")
            if fileBackend {
                var payload = original
                if action == "independent" {
                    var root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
                    var tokens = root["tokens"] as! [String: Any]
                    tokens["refresh_token"] = "independent-new-session"
                    root["tokens"] = tokens
                    payload = try JSONSerialization.data(withJSONObject: root)
                }
                try payload.write(to: copy.appendingPathComponent("auth.json"))
            }
        } else if action.hasPrefix("late-") {
            target = late
            try Fixture.codexMode(late, mode == "auto-file" ? "auto" : mode)
            var root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            if action == "late-routing" {
                var tokens = root["tokens"] as! [String: Any]
                tokens["account_id"] = "late-native-routing"
                root["tokens"] = tokens
            }
            let payload = try JSONSerialization.data(withJSONObject: root)
            if fileBackend { try payload.write(to: late.appendingPathComponent("auth.json")) }
            else { Fixture.codexKeychain[Fixture.codexKey(late)] = payload }
        }
        if restart { try await nativeGrantRestart(target: target, expectedPosts: 0); return }
        Fixture.rejectSpentRefresh = true
        Fixture.holdFirstUsage = true
        Fixture.releaseFirstUsage = true
        Fixture.firstUsageStatus = expired && action == "independent" ? 200 : 401
        let account = DiscoveredAccount(id: AuthSwap$Codex.profileColumnID(target.lastPathComponent), provider: .codex,
                                        profileName: target.lastPathComponent, source: .codexHome(target))
        let result = await Provider$Codex().fetch(account)
        try expect(try AuthSwap$Codex.authData(home: base) == native, "Sleeping renewal overwrote the native login")
        print("NATIVE GRANT mode=\(mode) action=\(action) expired=\(expired) posts=\(Fixture.refreshCalls) outcome=\(result)")
        if action == "independent" {
            try expect(Fixture.refreshCalls == 1, "Independent native-account session did not renew exactly once")
            guard case .success = result else { throw Failure(description: "Independent session could not fetch usage") }
        } else {
            try expect(Fixture.refreshCalls == 0, "A native-owned refresh grant was submitted again after CLI rotation")
        }
    }

    private static func nativeGrantAuth(_ home: URL, mode: String, account: String,
                                        grant: String, expired: Bool) throws {
        try Fixture.codexMode(home, mode)
        try Fixture.writeAuth(home, account: account, refresh: grant, expired: expired)
        if mode != "file" {
            Fixture.codexKeychain[Fixture.codexKey(home)] = try Data(contentsOf: home.appendingPathComponent("auth.json"))
            try Foundation.FileManager.default.removeItem(at: home.appendingPathComponent("auth.json"))
        }
    }

    @MainActor
    private static func nativeGrantControl(mode: String, action: String) async throws {
        let base = AuthSwap$Codex.baseHome
        let source = ProfileDirectories.codexRoot.appendingPathComponent("native-control-source")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("native-control-other")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("native-control-copy")
        defer { Fixture.failDefaultsSynchronization = false; Fixture.denyCodexDelete = false }
        if action == "handoff" || action == "rollback" {
            try nativeGrantAuth(base, mode: action == "rollback" ? "keyring" : "file",
                                account: "same-account", grant: "valid-primary-grant", expired: true)
            try nativeGrantAuth(source, mode: mode, account: "same-account", grant: "valid-selected-grant", expired: action == "handoff")
            try nativeGrantAuth(other, mode: mode, account: "same-account", grant: "valid-other-grant", expired: false)
            try AuthSwap$Codex.activate(columnID: "codex:native-control-source", home: source)
            if action == "handoff" {
                try AuthSwap$Codex.activate(columnID: "codex:native-control-other", home: other)
                try await nativeGrantRestart(target: source, expectedPosts: 1)
                return
            }
            Fixture.denyCodexDelete = true
            var refused = false
            do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
            Fixture.denyCodexDelete = false
            try expect(refused && AuthSwap$Codex.activeColumnID == "codex:native-control-source", "Failed backup cleanup did not restore the selected native account")
            let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                            profileName: "main", source: .codexHome(base))
            let outcome = await Provider$Codex().fetch(account)
            try expect(Fixture.refreshCalls == 1, "Rollback retired the still-valid sleeping primary grant")
            guard case .success = outcome else { throw Failure(description: "Sleeping primary could not renew after native rollback") }
            return
        }
        try nativeGrantAuth(base, mode: "file", account: "native-owner", grant: "synthetic-already-spent", expired: true)
        try nativeGrantAuth(copy, mode: mode, account: "copy-routing", grant: "synthetic-already-spent", expired: true)
        if action == "selected" {
            try Fixture.writeAuth(base, account: "unrelated-primary", refresh: "unrelated-primary-grant", expired: false)
            try nativeGrantAuth(source, mode: "file", account: "native-owner", grant: "synthetic-already-spent", expired: true)
            try AuthSwap$Codex.activate(columnID: "codex:native-control-source", home: source)
        } else {
            _ = await Provider$Codex().fetch(DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                profileName: "main", source: .codexHome(base)))
        }
        try expect(Fixture.refreshCalls == 0, "Observing a native session submitted its grant")
        try Fixture.writeAuth(base, account: "native-owner", refresh: "native-current-grant", expired: false)
        let native = try Data(contentsOf: base.appendingPathComponent("auth.json"))
        if action == "selected" { try Foundation.FileManager.default.removeItem(at: source) }
        let account = DiscoveredAccount(id: "codex:native-control-copy", provider: .codex,
                                        profileName: "native-control-copy", source: .codexHome(copy))
        Fixture.rejectSpentRefresh = true
        if action == "sync" { Fixture.failDefaultsSynchronization = true }
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 0, "Native grant protection depended on copy routing, directory or write access")
        if action == "sync" {
            let refused = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
            await Renewal$Codex.shared.cancelTermination()
            try expect(!refused, "Normal quit discarded an undurable native grant marker")
            Fixture.failDefaultsSynchronization = false
            _ = await Provider$Codex().fetch(account)
            try expect(Fixture.refreshCalls == 0, "Preference recovery replayed the consumed native grant")
        }
        try expect(try Data(contentsOf: base.appendingPathComponent("auth.json")) == native, "Grant bookkeeping changed native credentials")
        if action == "selected" {
            try expect(!Foundation.FileManager.default.fileExists(atPath: source.path), "Grant protection recreated the removed selected profile")
        }
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit, "Durable native grant bookkeeping prevented normal quit")
    }

    @MainActor
    private static func nativeGrantRestart(target: URL, expectedPosts: Int) async throws {
        let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(quit, "Native grant metadata could not terminate normally")
        let defaults = UserDefaults.standard.dictionaryRepresentation()
        try expect(!strings(in: defaults).contains(where: {
            $0.contains("synthetic-already-spent") || $0.contains("native-current-grant") || $0.contains("valid-selected-grant")
        }), "Native grant preferences contain raw refresh credentials")
        let state: [String: Any] = ["defaults": defaults, "keychain": Fixture.codexKeychain,
                                    "target": target.path, "posts": expectedPosts]
        try PropertyListSerialization.data(fromPropertyList: state, format: .binary, options: 0)
            .write(to: Fixture.root.appendingPathComponent("native-grant-checkpoint.plist"))
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = ["codex-native-grant-child", Fixture.root.path]
        let output = Pipe(); process.standardOutput = output; process.standardError = output
        try process.run(); process.waitUntilExit()
        let diagnostic = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        print(diagnostic)
        try expect(process.terminationStatus == 0, "Native grant restart violated ownership: " + diagnostic)
    }

    @MainActor
    private static func nativeGrantChild() async throws {
        let data = try Data(contentsOf: Fixture.root.appendingPathComponent("native-grant-checkpoint.plist"))
        guard let state = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let defaults = state["defaults"] as? [String: Any], let keychain = state["keychain"] as? [String: Data],
              let path = state["target"] as? String, let posts = state["posts"] as? Int else {
            throw Failure(description: "Invalid native grant checkpoint")
        }
        for (key, value) in defaults { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = keychain
        Fixture.rejectSpentRefresh = true
        let target = URL(fileURLWithPath: path)
        let account = DiscoveredAccount(id: AuthSwap$Codex.profileColumnID(target.lastPathComponent), provider: .codex,
                                        profileName: target.lastPathComponent, source: .codexHome(target))
        let outcome = await Provider$Codex().fetch(account)
        print("NATIVE RESTART expectedPosts=\(posts) posts=\(Fixture.refreshCalls) outcome=\(outcome)")
        try expect(Fixture.refreshCalls == posts, "Restart replayed a native grant or blocked an independent handoff")
        if posts > 0 {
            guard case .success = outcome else { throw Failure(description: "Independent sleeping session could not renew after restart") }
        }
    }

    @MainActor
    private static func nativeGrantPath(retarget: Bool) async throws {
        let old = ProfileDirectories.codexRoot.appendingPathComponent("old-native")
        let new = Fixture.root.appendingPathComponent("new-native")
        let link = Fixture.root.appendingPathComponent("native-home-link")
        let sleeper = ProfileDirectories.codexRoot.appendingPathComponent("independent-sleeper")
        try Fixture.codexMode(old, "file")
        try Fixture.writeAuth(old, account: "same-native-account", refresh: "valid-old-native-grant", expired: true)
        try Fixture.codexMode(new, "file")
        try Fixture.writeAuth(new, account: "same-native-account", refresh: "valid-new-home-grant", expired: false)
        let current = try Data(contentsOf: new.appendingPathComponent("auth.json"))
        try Fixture.codexLogin(sleeper, account: "independent-sleeper", mode: "file")
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
        Fixture.codexHome = link.path
        _ = try AuthSwap$Codex.beginRenewal(columnID: AuthSwap$Codex.defaultColumnID, home: link)
        Fixture.pauseAuthReadPath = old.appendingPathComponent("auth.json").path
        let task = Task.detached {
            Result { () -> Void in
                if let lease = try AuthSwap$Codex.beginRenewal(columnID: "codex:independent-sleeper", home: sleeper) {
                    AuthSwap$Codex.finishRenewal(lease)
                }
            }
        }
        var paused = false
        for _ in 0..<400 {
            Fixture.lock.lock(); paused = Fixture.authReadPaused; Fixture.lock.unlock()
            if paused { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(paused, "Native credential read did not reach the barrier")
        if retarget {
            try Foundation.FileManager.default.removeItem(at: link)
            try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: new)
        }
        Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock()
        _ = await task.value
        let account = DiscoveredAccount(id: "codex:old-native", provider: .codex, profileName: "old-native", source: .codexHome(old))
        let outcome = await Provider$Codex().fetch(account)
        print("NATIVE PATH retarget=\(retarget) posts=\(Fixture.refreshCalls) outcome=\(outcome)")
        try expect(Fixture.refreshCalls == (retarget ? 1 : 0), "A grant read from the old canonical home was attributed to the new native namespace")
        try expect(try Data(contentsOf: new.appendingPathComponent("auth.json")) == current, "Namespace bookkeeping changed the new native login")
        if retarget {
            guard case .success = outcome else { throw Failure(description: "The valid sleeping login could not renew after native home retarget") }
        }
    }

    @MainActor
    private static func nativeGrantAlias(mode: String) async throws {
        let old = ProfileDirectories.codexRoot.appendingPathComponent("native-alias-owner")
        let alias = URL(fileURLWithPath: "/System/Volumes/Data" + old.path)
        let link = Fixture.root.appendingPathComponent("native-alias-link")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("native-alias-copy")
        let sleeper = ProfileDirectories.codexRoot.appendingPathComponent("native-alias-sleeper")
        let grant = mode == "file" ? "synthetic-already-spent" : "valid-independent-keyring-grant"
        try nativeGrantAuth(old, mode: mode, account: "native-alias-account", grant: grant, expired: true)
        guard let owner = DirectoryIdentity.capture(old), let physicalAlias = DirectoryIdentity.capture(alias) else {
            throw Failure(description: "Data-volume alias is unavailable")
        }
        try expect(owner.isSameDirectory(as: physicalAlias) && Fixture.codexKey(old) != Fixture.codexKey(alias),
                   "The OS did not expose distinct native namespaces for one physical directory")
        try nativeGrantAuth(copy, mode: "file", account: "copy-routing", grant: grant, expired: true)
        try Fixture.codexLogin(sleeper, account: "alias-sleeper", mode: "file")
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
        Fixture.codexHome = link.path
        _ = try AuthSwap$Codex.beginRenewal(columnID: AuthSwap$Codex.defaultColumnID, home: link)
        if mode == "file" {
            try Fixture.writeAuth(old, account: "native-alias-account", refresh: "native-alias-current", expired: false)
        } else {
            try nativeGrantAuth(alias, mode: "keyring", account: "native-alias-account", grant: "independent-alias-current", expired: false)
        }
        let native = try AuthSwap$Codex.authData(home: alias)
        Fixture.pauseAuthReadPath = old.appendingPathComponent(mode == "file" ? "auth.json" : "config.toml").path
        let task = Task.detached {
            Result { () -> Void in
                if let lease = try AuthSwap$Codex.beginRenewal(columnID: "codex:native-alias-sleeper", home: sleeper) {
                    AuthSwap$Codex.finishRenewal(lease)
                }
            }
        }
        var paused = false
        for _ in 0..<400 {
            Fixture.lock.lock(); paused = Fixture.authReadPaused; Fixture.lock.unlock()
            if paused { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(paused, "Native alias observation did not reach its read barrier")
        try Foundation.FileManager.default.removeItem(at: link)
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: alias)
        Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock()
        _ = await task.value
        Fixture.rejectSpentRefresh = true
        let target = mode == "file" ? copy : old
        let account = DiscoveredAccount(id: AuthSwap$Codex.profileColumnID(target.lastPathComponent), provider: .codex,
                                        profileName: target.lastPathComponent, source: .codexHome(target))
        let result = await Provider$Codex().fetch(account)
        print("NATIVE ALIAS mode=\(mode) posts=\(Fixture.refreshCalls) outcome=\(result)")
        try expect(Fixture.refreshCalls == (mode == "file" ? 0 : 1),
                   "Native grant ownership confused a shared file with independent Keychain namespaces")
        try expect(try AuthSwap$Codex.authData(home: alias) == native, "Alias bookkeeping overwrote the current native login")
        if mode == "keyring" {
            guard case .success = result else { throw Failure(description: "Independent Keychain namespace could not renew") }
        }
    }


    private static func nativeBoundaryAuth(_ home: URL, mode: String, account: String,
                                           grant: String, expired: Bool) throws {
        try nativeGrantAuth(home, mode: mode.hasPrefix("auto-") ? "auto" : mode,
                            account: account, grant: grant, expired: expired)
        if mode == "auto-file" {
            guard let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home)) else {
                throw Failure(description: "Missing auto fallback fixture")
            }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }

    @MainActor
    private static func nativeGrantPublication(mode: String, kind: String, observed: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("publication-copy")
        let oldGrant = "synthetic-already-spent"
        try nativeBoundaryAuth(base, mode: mode, account: "native-owner", grant: oldGrant, expired: true)
        _ = try AuthSwap$Codex.beginRenewal(columnID: AuthSwap$Codex.defaultColumnID, home: base)
        if kind != "unchanged" {
            try nativeBoundaryAuth(base, mode: mode, account: "native-owner", grant: "native-current-grant", expired: false)
        }
        // The copy appeared after native ownership was recorded. Routing and
        // physical inventory cannot authorize replaying its shared old grant.
        let grant = kind == "independent" ? "valid-independent-publication" : oldGrant
        try nativeBoundaryAuth(copy, mode: mode, account: kind == "independent" ? "native-owner" : "copy-routing",
                               grant: grant, expired: true)
        let native = try AuthSwap$Codex.authData(home: base)
        let original = try AuthSwap$Codex.authData(home: copy)
        if observed { _ = try AuthSwap$Codex.beginRenewal(columnID: AuthSwap$Codex.defaultColumnID, home: base) }
        let account = DiscoveredAccount(id: "codex:publication-copy", provider: .codex,
                                        profileName: "publication-copy", source: .codexHome(copy))
        var result: Result<Void, Error>?
        AppSwitcher$Codex().switchTo(account) { result = $0 }
        guard let result else { throw Failure(description: "Desktop switch did not complete") }
        let refused: Bool
        if case .failure = result { refused = true } else { refused = false }
        print("NATIVE PUBLICATION mode=\(mode) kind=\(kind) observed=\(observed) refused=\(refused)")
        if kind == "spent" {
            try expect(refused && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "A late copy published a consumed native grant")
            try expect(try AuthSwap$Codex.authData(home: base) == native,
                       "Refusing the consumed copy changed the current native login")
        } else {
            try expect(!refused && AuthSwap$Codex.activeColumnID == account.id,
                       "An unspent independent session or intentional handoff could not activate")
            try expect(try AuthSwap$Codex.authData(home: base) == original,
                       "The valid session was not published through its configured native backend")
        }
        try expect(try AuthSwap$Codex.authData(home: copy) == original,
                   "Grant validation changed the copied profile's credentials")
        try expect(Fixture.refreshCalls == 0 && !AppSwitchState.inProgress.contains(.codex),
                   "Desktop switching issued a refresh POST or stranded its switch reservation")
    }

    @MainActor
    private static func nativeGrantRemoval(mode: String, kind: String) async throws {
        let base = AuthSwap$Codex.baseHome
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("removal-copy")
        let oldGrant = "synthetic-already-spent"
        try nativeBoundaryAuth(base, mode: mode, account: "native-owner", grant: oldGrant, expired: true)
        _ = try AuthSwap$Codex.beginRenewal(columnID: AuthSwap$Codex.defaultColumnID, home: base)
        if kind != "unchanged" {
            try nativeBoundaryAuth(base, mode: mode, account: "native-owner", grant: "native-current-grant", expired: false)
        }
        try nativeBoundaryAuth(copy, mode: mode, account: kind == "independent" ? "native-owner" : "copy-routing",
                               grant: kind == "independent" ? "valid-independent-removal" : oldGrant, expired: true)
        let primary = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                        profileName: "main", source: .codexHome(base))
        let native = try AuthSwap$Codex.authData(home: base)
        let original = try AuthSwap$Codex.authData(home: copy)
        defer {
            Fixture.failDefaultsSynchronization = false
            Fixture.denyCredentialFileRemovalPath = nil
            Fixture.denyCodexDelete = false
            Fixture.denyCodexRead = false
        }
        if kind == "sync-refused" || kind == "delete-refused" || kind == "read-refused" {
            Fixture.failDefaultsSynchronization = kind == "sync-refused"
            Fixture.denyCodexRead = kind == "read-refused"
            if kind == "delete-refused" {
                Fixture.denyCodexDelete = mode == "keyring"
                Fixture.denyCredentialFileRemovalPath = mode == "file" ? base.appendingPathComponent("auth.json").path : nil
            }
            var refused = false
            do { try AccountRemoval.remove(primary) } catch { refused = true }
            Fixture.denyCodexRead = false
            let retainedNative = try AuthSwap$Codex.authData(home: base)
            try expect(refused && retainedNative == native,
                       "A refused metadata or credential deletion changed the native login")
            if kind == "sync-refused" {
                let quit = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
                await Renewal$Codex.shared.cancelTermination()
                try expect(!quit, "Normal quit discarded undurable retirement metadata after refused removal")
            }
            Fixture.failDefaultsSynchronization = false
            Fixture.denyCredentialFileRemovalPath = nil
            Fixture.denyCodexDelete = false
        }
        try AccountRemoval.remove(primary)
        try expect(!AuthSwap$Codex.hasAuth(home: base)
                   && Foundation.FileManager.default.fileExists(atPath: base.path),
                   "Primary removal retained credentials or deleted native configuration")
        try expect(try AuthSwap$Codex.authData(home: copy) == original,
                   "Primary removal changed the surviving copy")
        // A replacement login cannot revive the previous native grant. A valid
        // surviving session of that account must remain independently renewable.
        try nativeBoundaryAuth(base, mode: mode, account: "native-owner", grant: "replacement-native-grant", expired: false)
        let replacement = try AuthSwap$Codex.authData(home: base)
        let valid = kind == "independent" || kind == "unchanged"
        if kind == "restart" {
            try await nativeGrantRestart(target: copy, expectedPosts: 0)
        } else {
            Fixture.rejectSpentRefresh = !valid
            let account = DiscoveredAccount(id: "codex:removal-copy", provider: .codex,
                                            profileName: "removal-copy", source: .codexHome(copy))
            let result = await Provider$Codex().fetch(account)
            print("NATIVE REMOVAL mode=\(mode) kind=\(kind) posts=\(Fixture.refreshCalls) outcome=\(result)")
            try expect(Fixture.refreshCalls == (valid ? 1 : 0),
                       "Primary removal replayed a consumed native grant or blocked an unspent surviving session")
            if valid {
                guard case .success = result else { throw Failure(description: "Valid surviving session could not fetch usage") }
            } else {
                try expect(try AuthSwap$Codex.authData(home: copy) == original,
                           "Grant retirement overwrote the surviving copy")
            }
        }
        try expect(try AuthSwap$Codex.authData(home: base) == replacement,
                   "Surviving copy renewal changed the replacement native login")
    }

}
