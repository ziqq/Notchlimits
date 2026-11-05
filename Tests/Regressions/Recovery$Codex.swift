private enum RecoverySignals {
    static var deleted: ((String) -> Void)?
    static var cleaned: ((URL) -> Void)?
    static var created: ((URL) -> Void)?
}

@main @MainActor enum Recovery$Codex {
    static let manager = Foundation.FileManager.default

    static func main() async {
        do {
            Fixture.keychainExists = false
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            try await removal(mode: parts[0], replacementMode: parts[1], phase: parts[2],
                              readd: parts[3], pending: parts[4] == "pending", preparing: parts.count > 5)
        } catch {
            print("FAIL: \(error)")
            exit(1)
        }
    }

    static func removal(mode: String, replacementMode: String, phase: String,
                        readd: String, pending: Bool, preparing: Bool) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("original")
        let id = "codex:original"
        try Cleanup$Authentication.login(AuthSwap$Codex.baseHome, name: "native", mode: "file")
        try Cleanup$Authentication.login(home, name: "original", mode: mode, expired: pending)
        let original = try Cleanup$Authentication.bytes(home, mode: mode)!
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        store.setCustomName("Original name", for: id)
        store.setHidden(id, hidden: true)
        var request: Task<Renewal$Codex.Result, Never>?
        if pending {
            Fixture.response = .heldRenewed
            request = Task { await Renewal$Codex.shared.renew(columnID: id, home: home, force: true) }
            for _ in 0..<500 {
                if Fixture.refreshCalls == 1 { break }
                try await Task.sleep(nanoseconds: 2_000_000)
            }
            try expect(Fixture.refreshCalls == 1, "refresh admission was not reached")
        }
        defer { Fixture.releaseRefresh() }
        let unreadable = phase == "opaque"
        Fixture.denyCodexRead = unreadable
        var reached = false
        var replacement: Data?
        var readded: Data?
        var recoveryHome: URL?
        let inject = { (key: String) in
            reached = true
            guard replacementMode != "stable" else { return }
            let directories = try! manager.contentsOfDirectory(at: ProfileDirectories.codexRoot,
                                                               includingPropertiesForKeys: nil)
            let recovery = directories.first {
                $0.lastPathComponent.hasPrefix("recovered-") && Fixture.codexKey($0) == key
            }!
            recoveryHome = recovery
            try! Cleanup$Authentication.login(recovery, name: "new-recovery", mode: replacementMode)
            replacement = try! Cleanup$Authentication.bytes(recovery, mode: replacementMode)
            if readd != "none" {
                try! Cleanup$Authentication.login(home, name: "readded", mode: readd)
                readded = try! Cleanup$Authentication.bytes(home, mode: readd)
            }
        }
        if phase == "cleanup" {
            RecoverySignals.cleaned = { url in
                guard url.lastPathComponent.hasPrefix(".removed-") else { return }
                RecoverySignals.cleaned = nil
                let directories = try! manager.contentsOfDirectory(at: ProfileDirectories.codexRoot,
                                                                   includingPropertiesForKeys: nil)
                let recovery = directories.first { $0.lastPathComponent.hasPrefix("recovered-") }!
                inject(Fixture.codexKey(recovery))
            }
        } else {
            RecoverySignals.deleted = { key in
                RecoverySignals.deleted = nil
                inject(key)
            }
        }
        var preparedHome: URL?
        var preparedData: Data?
        if preparing {
            RecoverySignals.created = { url in
                guard reached, url.lastPathComponent.hasPrefix("recovered-"), url != recoveryHome else { return }
                RecoverySignals.created = nil
                try! Cleanup$Authentication.login(url, name: "new-destination", mode: "file")
                preparedHome = url
                preparedData = try! Cleanup$Authentication.bytes(url, mode: "file")
            }
        }
        var success = false
        do { try store.removeAccount(id: id); success = true }
        catch { print("Refused: \(error)") }
        RecoverySignals.deleted = nil
        RecoverySignals.cleaned = nil
        RecoverySignals.created = nil
        Fixture.denyCodexRead = false
        try expect(reached, "recovery lifecycle boundary not reached")
        Fixture.releaseRefresh()
        if let request {
            let result = await request.value
            try expect(result == (readd == "none" ? .renewed : .skipped) && Fixture.refreshCalls == 1,
                       "draining the original rotation repeated its POST or reported the replacement as renewed")
        }
        let accounts = Discovery$Real().discover().filter { $0.provider == .codex }
        let visible = accounts.compactMap { account -> Data? in
            guard case .codexHome(let directory) = account.source else { return nil }
            return try? AuthSwap$Codex.authData(columnID: account.id, home: directory)
        }
        let originalRecords = visible.filter { Provider$Codex.parseAuth($0)?.accountID == "original" }
        let originalVisible = pending
            ? originalRecords.contains { refresh($0) == "synthetic-rotated" }
            : visible.contains(original)
        let replacementVisible = replacement.map { visible.contains($0) } ?? false
        let replacementUnmoved = recoveryHome.flatMap { try? AuthSwap$Codex.authData(home: $0) } == replacement
        let committed = replacementMode == "stable" || phase == "cleanup" || unreadable
        print("RECOVERY mode=\(mode) replacement=\(replacementMode) phase=\(phase) readd=\(readd) pending=\(pending) success=\(success) originalVisible=\(originalVisible) replacementVisible=\(replacementVisible) replacementUnmoved=\(replacementUnmoved)")
        if committed {
            try expect(success && !originalVisible, "explicit deletion did not reach its commit point")
        } else {
            try expect(!success && originalVisible, "a refused removal discarded its original login")
            try expect(store.customNames[id] == "Original name" && store.hidden.contains(id),
                       "a refused removal retired the original account preferences")
        }
        if replacementMode != "stable" {
            try expect(replacementVisible && replacementUnmoved,
                       "recovery cleanup erased or moved a completed independent login")
        }
        if let readded {
            try expect(visible.contains(readded) && (try AuthSwap$Codex.authData(home: home)) == readded,
                       "rollback overwrote the re-added original profile")
        }
        if preparing {
            try expect(preparedHome != nil && preparedData != nil, "clone preparation boundary not reached")
            try expect(preparedHome.flatMap { try? AuthSwap$Codex.authData(home: $0) } == preparedData,
                       "snapshot preparation changed a new destination login's storage mode")
        }
    }

    static func refresh(_ data: Data) -> String? {
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return (json?["tokens"] as? [String: Any])?["refresh_token"] as? String
    }
}
