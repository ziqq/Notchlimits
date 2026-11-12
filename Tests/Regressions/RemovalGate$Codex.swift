private enum RemovalSignals {
    static var staged = false
    static var fileProbe: ((String) -> Void)?
    static var configRead: ((String) -> Void)?
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
        if phase == "reserve-late" || phase == "rollback-keychain-read" || phase == "switch-late" {
            try checkLateMutation(mode: mode, phase: phase, stable: stable)
            return
        }
        let sameSecond = args[3] == "same-second"
        Fixture.keychainExists = false
        let home = ProfileDirectories.codexRoot.appendingPathComponent("original")
        let id = "codex:original"
        try Cleanup$Authentication.login(AuthSwap$Codex.baseHome, name: "native", mode: "file")
        let native = try Cleanup$Authentication.bytes(AuthSwap$Codex.baseHome, mode: "file")!
        try Cleanup$Authentication.login(home, name: "original", mode: mode)
        let original = try Cleanup$Authentication.bytes(home, mode: mode)!
        if phase == "save-keyring" {
            try checkKeyringSave(home: home, mode: mode, original: original, stable: stable)
            return
        }
        let originalKey = Fixture.codexKey(home)
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "setup did not discover original")
        store.setCustomName("Original name", for: id)
        store.setHidden(id, hidden: true)
        Fixture.denyCodexRead = opaque
        let isRollback = phase == "rollback-gate" || phase == "rollback-late" || phase == "rollback-mode"
        Fixture.denyCodexDelete = isRollback
        var rollbackReads = 0, originalAbsenceReads = 0, attempted = false
        var reached = false, deleteReached = false, deletedReplacement = false, missingAfterDelete = 0
        var unchangedMetadata = false, changedDatabase = false
        var replacement: Data?, config: Data?, recovery: URL?, target: URL?, readded: Data?
        func publishFileFallback(_ url: URL, account: String) throws {
            try Fixture.writeAuth(url, account: account, refresh: "independent", expired: false)
            try Fixture.codexMode(url, "auto")
        }
        func inject(_ url: URL, _ backend: String) {
            guard !reached else { return }
            reached = true
            if !stable {
                let key = Fixture.codexKey(url)
                let modified = Fixture.codexModified[key]
                let database = sameSecond ? try! Fixture.classicKeychainDatabase() : nil
                var before = stat(), after = stat()
                if let database { precondition(lstat(database.path, &before) == 0) }
                if backend == "auto-file" {
                    // A file fallback does not commit any change to Keychain.
                    try! publishFileFallback(url, account: "independent-login")
                } else {
                    try! Cleanup$Authentication.login(url, name: "independent-login", mode: backend)
                }
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
                if args[3] == "also-readded" {
                    try! publishFileFallback(home, account: "readded-original")
                    readded = try! Cleanup$Authentication.bytes(home, mode: "auto-file")
                }
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
        if phase == "rollback-mode" {
            Fixture.beforeDirectoryMove = { from, to in
                guard from.lastPathComponent.hasPrefix(".removed-"), to.path == home.path else { return }
                reached = true
                // A CLI profile can publish its mode before the new login finishes.
                if !stable { try Fixture.codexMode(home, "file") }
            }
        }
        func checkLateRollback(_ key: String) {
            guard phase == "rollback-late", attempted, !reached,
                  let recovery, key == Fixture.codexKey(recovery) else { return }
            rollbackReads += 1
            if rollbackReads == 4 { inject(home, "auto-file") }
        }
        RemovalSignals.present = { key in
            if opaque { checkLateRollback(key) }
            if phase == "post-file", !reached, let recovery, key == Fixture.codexKey(recovery) {
                inject(recovery, "file")
            }
            if phase == "delete-late", originalAbsenceReads == 2, !reached,
               let recovery, key == Fixture.codexKey(recovery) {
                inject(recovery, "file")
            }
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
            if !opaque { checkLateRollback(key) }
            if phase == "delete-late", originalAbsenceReads == 2, !reached,
               let recovery, key == Fixture.codexKey(recovery) {
                inject(recovery, "file")
            }
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
            if phase == "delete-late", RemovalSignals.staged, key == originalKey, !deleteReached {
                originalAbsenceReads += 1
            }
            if phase == "delete-gate", RemovalSignals.staged, key == originalKey, !deleteReached, !reached {
                RemovalSignals.gate = { inject(recovery, "keyring") }
            }
            if (phase == "finish" || phase == "finish-last-read"), deleteReached, key == Fixture.codexKey(recovery) {
                missingAfterDelete += 1
                let earlyRead = opaque ? 1 : 2
                let trigger = phase == "finish-last-read" ? earlyRead + 1 : earlyRead
                if missingAfterDelete == trigger {
                    inject(recovery, phase == "finish-last-read" || args[3] == "keyring" ? "keyring" : "file")
                }
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
        Fixture.beforeDirectoryMove = nil
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
        if stable && isRollback {
            try expect(attempted && !success && visible.contains(original), "ordinary rollback lost original login")
            try expect(store.customNames[id] == "Original name" && store.hidden.contains(id), "ordinary rollback lost preferences")
        } else if phase == "rollback-mode" {
            try expect(attempted && !success, "rollback did not follow a refused deletion")
            try expect(try AuthStorage$Codex(home: home).mode == .file, "rollback overwrote the new storage mode")
            try expect(visible.contains(original), "rollback hid the original login behind the new file mode")
            try expect(Fixture.codexKeychain[originalKey] == nil, "rollback moved the secret to a file-only namespace")
            try expect(store.customNames[id] == "Original name" && store.hidden.contains(id), "a refused removal retired the original preferences")
        } else if stable {
            try expect(success && deleteReached && !visible.contains(original), "ordinary removal failed")
        } else {
            try expect(!deletedReplacement, "removal deleted the independent replacement secret")
            try expect(replacement != nil && current == replacement && visible.contains(replacement!),
                       "replacement login disappeared from its own profile")
            try expect(currentConfig == config, "cleanup removed replacement config.toml")
            if phase == "finish" || phase == "finish-last-read" {
                try expect(success && !visible.contains(original), "late cleanup undid the committed removal")
            } else {
                try expect(!success, "removal accepted a changed owner")
                if phase == "delete-late" {
                    try expect(!deleteReached, "owner conflict reached native secret deletion")
                }
                try expect(store.customNames[id] == "Original name" && store.hidden.contains(id),
                           "a refused removal retired the original preferences")
                if (!opaque && phase != "source-gate") || phase == "post-file" || phase == "delete-late" || phase == "rollback-late" {
                    try expect(visible.contains(original), "refused removal hid the original login")
                }
                if let readded {
                    try expect(try AuthSwap$Codex.authData(home: home) == readded,
                               "salvage replaced the independently re-added original profile")
                }
            }
        }
    }

    private static func checkKeyringSave(home: URL, mode: String, original: Data, stable: Bool) throws {
        let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
        try Cleanup$Authentication.login(other, name: "replacement", mode: mode)
        let replacement = try Cleanup$Authentication.bytes(other, mode: mode)!
        let tokens = OAuth$Codex.Tokens(idToken: nil, accessToken: "rotated-access", refreshToken: "rotated-refresh")
        let rotated = AuthSwap$Codex.renewedAuth(original, usedRefreshToken: "synthetic-refresh-original",
                                               tokens: tokens, now: Date())!
        let storage = try AuthStorage$Codex(home: home)
        let key = Fixture.codexKey(home)
        var reached = false
        RemovalSignals.gate = {
            reached = true
            if !stable { Fixture.codexKeychain[key] = replacement }
        }
        var refused = false
        do {
            try storage.save(rotated, backend: .keyring, validating: {
                // The injected native login waits for entry to the writer's
                // gate, rather than for an incidental gate in the reader.
                let gate = RemovalSignals.gate
                RemovalSignals.gate = nil
                defer { RemovalSignals.gate = gate }
                guard try storage.load(backend: .keyring)?.data == original else { throw AuthStorage$Codex.Failure.settings }
            })
        } catch { refused = true }
        try expect(reached, "Keychain write gate was not reached")
        if stable {
            try expect(!refused && Fixture.codexKeychain[key] == rotated, "ordinary Keychain save did not publish rotated tokens")
        } else {
            try expect(refused && Fixture.codexKeychain[key] == replacement, "Keychain save overwrote a newer login")
        }
    }

    private static func checkLateMutation(mode: String, phase: String, stable: Bool) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("original")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
        let native = AuthSwap$Codex.baseHome
        let nativeMode = phase == "switch-late" ? "keyring" : "file"
        let id = "codex:original"
        Fixture.keychainExists = false
        try Cleanup$Authentication.login(native, name: "native", mode: nativeMode)
        try Cleanup$Authentication.login(home, name: "original", mode: mode)
        try Cleanup$Authentication.login(other, name: "replacement", mode: "keyring")
        let original = try Cleanup$Authentication.bytes(home, mode: mode)!
        let replacement = try Cleanup$Authentication.bytes(other, mode: "keyring")!
        let nativeBefore = try Cleanup$Authentication.bytes(native, mode: nativeMode)!
        let key = Fixture.codexKey(home), nativeKey = Fixture.codexKey(native)
        var reached = false, succeeded = false

        if phase == "switch-late" {
            // The writer checks the incoming record, then reads native auth.
            let nativeFile = native.appendingPathComponent("auth.json").path
            var writerStarted = false
            RemovalSignals.fileProbe = { if $0 == nativeFile { writerStarted = true } }
            RemovalSignals.reading = { readKey in
                guard writerStarted, readKey == nativeKey, !reached else { return }
                reached = true
                guard !stable else { return }
                if mode == "file" {
                    try! replacement.write(to: home.appendingPathComponent("auth.json"), options: .atomic)
                } else {
                    Fixture.codexKeychain[key] = replacement
                }
            }
            do { try AuthSwap$Codex.activate(columnID: id, home: home); succeeded = true }
            catch { print("Switch refused: \(error)") }
            try expect(reached, "switch did not reach the final native Keychain read")
            let after = Fixture.codexKeychain[nativeKey]
            let selected = AuthSwap$Codex.activeColumnID == id
            if stable {
                try expect(succeeded && selected && after == original, "ordinary switch failed")
            } else {
                try expect(try AuthSwap$Codex.authData(home: home) == replacement, "switch lost the replacement source")
                try expect(!succeeded && !selected && after == nativeBefore, "switch published the retired incoming login")
            }
            return
        }

        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "original profile was not discovered")
        store.setCustomName("Original name", for: id)
        var recovery: URL?, recoveryKey: String?, attempted = false
        RemovalSignals.created = { url in
            guard url.lastPathComponent.hasPrefix("recovered-"), recovery == nil else { return }
            recovery = url
            recoveryKey = Fixture.codexKey(url)
        }
        if phase == "reserve-late" {
            RemovalSignals.fileProbe = { path in
                guard let recovery, path == recovery.appendingPathComponent("auth.json").path, !reached else { return }
                reached = true
                if !stable { Fixture.codexKeychain[key] = replacement }
            }
        } else {
            Fixture.denyCodexDelete = true
            RemovalSignals.attempting = { if $0 == recoveryKey { attempted = true } }
            Fixture.beforeDirectoryMove = { from, to in
                guard from.lastPathComponent.hasPrefix(".removed-"), to.path == home.path else { return }
                RemovalSignals.configRead = { path in
                    guard path == home.appendingPathComponent("config.toml").path,
                          let recoveryKey, attempted, !reached else { return }
                    reached = true
                    if !stable { Fixture.codexKeychain[recoveryKey] = replacement }
                }
            }
        }
        do { try store.removeAccount(id: id); succeeded = true }
        catch { print("Removal refused: \(error)") }
        RemovalSignals.fileProbe = nil
        RemovalSignals.configRead = nil
        Fixture.beforeDirectoryMove = nil
        try expect(reached, "specified Keychain or file read was not reached")
        try expect(try Cleanup$Authentication.bytes(native, mode: nativeMode) == nativeBefore, "unrelated native login changed")
        let visible = Discovery$Real().discover().filter { $0.provider == .codex }.compactMap { account -> Data? in
            guard case .codexHome(let directory) = account.source else { return nil }
            return try? AuthSwap$Codex.authData(columnID: account.id, home: directory)
        }
        let atSource = Fixture.codexKeychain[key]
        let atRecovery = recoveryKey.flatMap { Fixture.codexKeychain[$0] }
        if phase == "reserve-late" {
            if stable {
                try expect(succeeded && !visible.contains(original), "ordinary removal failed")
            } else {
                try expect(!succeeded && store.customNames[id] == "Original name", "removal did not refuse a new login")
                try expect(atSource == replacement && atRecovery != replacement,
                           "reservation moved a newer Keychain login to another profile")
            }
        } else {
            try expect(attempted && !succeeded, "expected refused Keychain deletion")
            if stable {
                try expect(atSource == original && visible.contains(original), "ordinary rollback failed")
            } else {
                try expect(atRecovery == replacement && atSource != replacement,
                           "rollback moved the recovery profile's replacement login")
                try expect(visible.contains(original), "rollback lost the original readable snapshot")
            }
        }
    }
}
