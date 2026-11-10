private enum RemovalSignals {
    static var staged = false
    static var created: ((URL) -> Void)?
    static var gate: (() -> Void)?
    static var present: ((String) -> Void)?
    static var attempting: ((String) -> Void)?
    static var reading: ((String) -> Void)?
    static var missing: ((String) -> Void)?
    static var deleted: ((String, Data?) -> Void)?
}
@main @MainActor enum RemovalGate$Codex {
    static func main() {
        do { try run(CommandLine.arguments[1].split(separator: ":").map(String.init)) }
        catch { print("FAIL: \(error)"); exit(1) }
    }
    static func run(_ args: [String]) throws {
        let mode = args[0], opaque = args[1] == "opaque", phase = args[2]
        let stable = args[3] == "stable"
        let sameSecond = args[3] == "same-second"
        Fixture.keychainExists = false
        let home = ProfileDirectories.codexRoot.appendingPathComponent("original")
        let id = "codex:original"
        try Cleanup$Authentication.login(AuthSwap$Codex.baseHome, name: "native", mode: "file")
        let native = try Cleanup$Authentication.bytes(AuthSwap$Codex.baseHome, mode: "file")!
        try Cleanup$Authentication.login(home, name: "original", mode: mode)
        let original = try Cleanup$Authentication.bytes(home, mode: mode)!
        let originalKey = Fixture.codexKey(home)
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "setup did not discover original")
        store.setCustomName("Original name", for: id)
        store.setHidden(id, hidden: true)
        Fixture.denyCodexRead = opaque
        Fixture.denyCodexDelete = phase == "rollback-gate"
        var rollbackReads = 0, attempted = false
        var reached = false, deleteReached = false, deletedReplacement = false, missingAfterDelete = 0
        var unchangedMetadata = false, changedDatabase = false
        var replacement: Data?, config: Data?, recovery: URL?, target: URL?
        func inject(_ url: URL, _ backend: String) {
            guard !reached else { return }
            reached = true
            if !stable {
                let key = Fixture.codexKey(url)
                let modified = Fixture.codexModified[key]
                let database = sameSecond ? try! Fixture.classicKeychainDatabase() : nil
                var before = stat(), after = stat()
                if let database { precondition(lstat(database.path, &before) == 0) }
                try! Cleanup$Authentication.login(url, name: "independent-login", mode: backend)
                if let database {
                    // Model an in-place item write in the same wall-clock second.
                    // The persistent reference is fixed by account in the shim.
                    precondition(modified != nil && lstat(database.path, &after) == 0)
                    Fixture.codexModified[key] = modified
                    unchangedMetadata = Fixture.codexModified[key] == modified
                    changedDatabase = before.st_ino != after.st_ino
                }
                replacement = try! Cleanup$Authentication.bytes(url, mode: backend)!
                config = try! Data(contentsOf: url.appendingPathComponent("config.toml"))
                target = url
            }
        }
        RemovalSignals.created = { url in
            guard url.lastPathComponent.hasPrefix("recovered-") else { return }
            RemovalSignals.created = nil
            recovery = url
        }
        RemovalSignals.attempting = { key in
            if let recovery, key == Fixture.codexKey(recovery) { attempted = true }
        }
        RemovalSignals.present = { key in
            if phase == "source-gate", opaque, recovery != nil, key == originalKey, !reached {
                inject(home, mode)
            }
            if phase == "post-reservation", let recovery, key == Fixture.codexKey(recovery), !reached {
                inject(recovery, "keyring")
            }
            if phase == "rollback-gate", opaque, attempted, let recovery, key == Fixture.codexKey(recovery), !reached {
                RemovalSignals.gate = { inject(recovery, "keyring") }
            }
        }
        RemovalSignals.reading = { key in
            if phase == "rollback-gate", !opaque, attempted, let recovery, key == Fixture.codexKey(recovery), !reached {
                rollbackReads += 1
                if rollbackReads == 2 { RemovalSignals.gate = { inject(recovery, "keyring") } }
            }
            if phase == "source-gate", recovery != nil, key == originalKey, !reached {
                RemovalSignals.gate = { inject(home, "keyring") }
            }
        }
        RemovalSignals.missing = { key in
            guard let recovery else { return }
            if phase == "delete-gate", RemovalSignals.staged, key == originalKey, !deleteReached, !reached {
                RemovalSignals.gate = { inject(recovery, "keyring") }
            }
            if phase == "finish", deleteReached, key == Fixture.codexKey(recovery) {
                missingAfterDelete += 1
                if missingAfterDelete == (opaque ? 1 : 2) { inject(recovery, args[3] == "keyring" ? "keyring" : "file") }
            }
        }
        RemovalSignals.deleted = { key, bytes in
            guard let recovery, key == Fixture.codexKey(recovery) else { return }
            deleteReached = true
            deletedReplacement = replacement != nil && bytes == replacement
        }
        var success = false
        do { try store.removeAccount(id: id); success = true }
        catch { print("Refused: \(error)") }
        Fixture.denyCodexRead = false
        RemovalSignals.created = nil
        RemovalSignals.gate = nil
        RemovalSignals.present = nil
        RemovalSignals.attempting = nil
        RemovalSignals.reading = nil
        RemovalSignals.missing = nil
        RemovalSignals.deleted = nil
        let visible = Discovery$Real().discover().filter { $0.provider == .codex }.compactMap { account -> Data? in
            guard case .codexHome(let directory) = account.source else { return nil }
            return try? AuthSwap$Codex.authData(columnID: account.id, home: directory)
        }
        let current = target.flatMap { try? AuthSwap$Codex.authData(home: $0) }
        let currentConfig = target.flatMap { try? Data(contentsOf: $0.appendingPathComponent("config.toml")) }
        print("mode=\(mode) opaque=\(opaque) phase=\(phase) stable=\(stable) reached=\(reached) success=\(success) deleteReached=\(deleteReached) deletedReplacement=\(deletedReplacement) originalVisible=\(visible.contains(original)) replacementVisible=\(replacement.map { visible.contains($0) } ?? false) sameLogin=\(current == replacement) sourceOwnsReplacement=\(replacement != nil && Fixture.codexKeychain[originalKey] == replacement) recoveryOwnsReplacement=\(replacement != nil && recovery.flatMap { Fixture.codexKeychain[Fixture.codexKey($0)] } == replacement) sameConfig=\(currentConfig == config) metadataMissesAfterDelete=\(missingAfterDelete)")
        try expect(reached, "specified boundary not reached")
        if sameSecond { try expect(unchangedMetadata && changedDatabase, "fixture did not isolate the database revision") }
        try expect(try Cleanup$Authentication.bytes(AuthSwap$Codex.baseHome, mode: "file") == native, "native login changed")
        if stable && phase == "rollback-gate" {
            try expect(attempted && !success && visible.contains(original), "ordinary rollback lost original login")
            try expect(store.customNames[id] == "Original name" && store.hidden.contains(id), "ordinary rollback lost preferences")
        } else if stable {
            try expect(success && deleteReached && !visible.contains(original), "ordinary removal failed")
        } else {
            try expect(!deletedReplacement, "removal deleted the independent replacement secret")
            try expect(replacement != nil && current == replacement && visible.contains(replacement!),
                       "replacement login disappeared from its own profile")
            try expect(currentConfig == config, "cleanup removed replacement config.toml")
            if phase == "finish" {
                try expect(success && !visible.contains(original), "late cleanup undid the committed removal")
            } else {
                try expect(!success, "removal accepted a changed owner")
                try expect(store.customNames[id] == "Original name" && store.hidden.contains(id),
                           "a refused removal retired the original preferences")
                if !opaque && phase != "source-gate" {
                    try expect(visible.contains(original), "rollback lost the readable original snapshot")
                }
            }
        }
    }
}
