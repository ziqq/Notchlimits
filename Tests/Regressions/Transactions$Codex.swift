private enum TransactionSignals {
    static var io: ((String) -> Void)?
    static var attributes: ((String) -> Void)?
    static var removed: ((URL) -> Void)?
}

@main
enum Transactions$Codex {
    private static let manager = Foundation.FileManager.default

    static func main() async {
        do {
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            Fixture.keychainExists = false
            switch parts[0] {
            case "publish": try publication(nativeMode: parts[1], sourceMode: parts[2], phase: parts[3], change: parts[4])
            case "copyback": try copyback(mode: parts[1], phase: parts[2], change: parts[3])
            case "primary": try primary(mode: parts[1], phase: parts[2], change: parts[3])
            case "rollback": try rollback(mode: parts[1], change: parts[2])
            default: throw Failure(description: "Unknown Codex transaction scenario")
            }
        } catch { print("FAIL: \(error)"); exit(1) }
    }

    private static func login(_ home: URL, name: String, mode: String) throws {
        try Fixture.codexLogin(home, account: name, mode: mode == "auto-file" ? "auto" : mode)
        if mode == "auto-file" {
            guard let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home)) else {
                throw Failure(description: "Missing auto file fallback")
            }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }

    private static func raw(_ home: URL, mode: String) throws -> Data? {
        try AuthStorage$Codex(home: home, mode: .file)
            .load(backend: mode == "file" || mode == "auto-file" ? .file : .keyring)?.data
    }

    private static func mutate(_ home: URL, mode: String, change: String, original: Data) throws {
        switch change {
        case "login": try login(home, name: "replacement", mode: mode)
        case "owner", "identical":
            try manager.moveItem(at: home, to: home.appendingPathExtension("retired"))
            try login(home, name: "replacement", mode: mode)
            if change == "identical" {
                if mode == "file" || mode == "auto-file" { try original.write(to: home.appendingPathComponent("auth.json")) }
                else { Fixture.codexKeychain[Fixture.codexKey(home)] = original }
            }
        case "retarget":
            try manager.moveItem(at: home, to: home.appendingPathExtension("retired"))
            let replacement = Fixture.root.appendingPathComponent("replacement")
            try login(replacement, name: "replacement", mode: mode)
            try manager.createSymbolicLink(at: home, withDestinationURL: replacement)
        case "mode": try Fixture.codexMode(home, "ephemeral")
        case "metadata": try Data("preserve-settings".utf8).write(to: home.appendingPathComponent("settings-marker"))
        case "stable": break
        default: throw Failure(description: "Unknown transaction mutation")
        }
    }

    private static func stable(_ change: String) -> Bool { change == "stable" || change == "metadata" }

    private static func publication(nativeMode: String, sourceMode: String, phase: String, change: String) throws {
        let native = Fixture.root.appendingPathComponent("native")
        let source = ProfileDirectories.codexRoot.appendingPathComponent("source")
        Fixture.codexHome = native.path
        try login(native, name: "native", mode: nativeMode)
        try login(source, name: "incoming", mode: sourceMode)
        let previous = try raw(native, mode: nativeMode)
        let original = try raw(source, mode: sourceMode)!
        var reached = false
        let mutation = {
            reached = true
            TransactionSignals.io = nil
            TransactionSignals.attributes = nil
            try! mutate(source, mode: sourceMode, change: change, original: original)
        }
        if phase == "config" {
            TransactionSignals.io = { path in
                guard path == native.appendingPathComponent("config.toml").path,
                      manager.fileExists(atPath: AuthSwap$Codex.stashHome.appendingPathComponent("config.toml").path) else { return }
                mutation()
            }
        } else {
            TransactionSignals.attributes = { path in
                let file = URL(fileURLWithPath: path)
                if file.deletingLastPathComponent().path == native.path && file.lastPathComponent.hasPrefix(".auth-") { mutation() }
            }
        }
        var success = false
        do { try AuthSwap$Codex.activate(columnID: "codex:source", home: source); success = true } catch {}
        let published = try raw(native, mode: nativeMode == "auto-file" && success ? "auto" : nativeMode)
        print("PUBLICATION native=\(nativeMode) source=\(sourceMode) phase=\(phase) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "Publication did not reach its final I/O boundary")
        try expect(success == stable(change), "Publication accepted a stale source or refused a stable source")
        if stable(change) {
            try expect(AuthSwap$Codex.authIdentity(published!) == AuthSwap$Codex.authIdentity(original), "Stable publication changed the session")
        } else {
            try expect(published == previous && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "Refused publication changed native credentials or its active marker")
            let replacement = try raw(source, mode: sourceMode)
            if change == "mode" { try Fixture.codexMode(source, sourceMode == "auto-file" ? "auto" : sourceMode) }
            try AuthSwap$Codex.activate(columnID: "codex:source", home: source)
            try expect(try AuthSwap$Codex.authData(home: native) == replacement, "A refused switch stranded its reservation or published an old login on retry")
        }
        try expect(try raw(source, mode: sourceMode) != nil && Fixture.refreshCalls == 0, "Publication removed its source or issued a refresh POST")
    }

    private static func copyback(mode: String, phase: String, change: String) throws {
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let incoming = ProfileDirectories.codexRoot.appendingPathComponent("incoming")
        try login(native, name: phase == "backup-write" ? "selected" : "primary", mode: "file")
        try login(selected, name: "selected", mode: mode)
        try login(incoming, name: "incoming", mode: "file")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let original = try raw(selected, mode: mode)!
        let rotated = AuthSwap$Codex.renewedAuth(original, usedRefreshToken: "synthetic-refresh-selected",
            tokens: OAuth$Codex.Tokens(idToken: nil,
                accessToken: Fixture.accessToken(expiresAt: Date().addingTimeInterval(86400).timeIntervalSince1970),
                refreshToken: "synthetic-native-rotated"), now: Date())!
        try AuthStorage$Codex(home: native).save(rotated)
        var reached = false, reads = 0
        var replacement: Data?
        let mutation = {
            reached = true
            TransactionSignals.io = nil
            TransactionSignals.attributes = nil
            try! mutate(selected, mode: mode, change: change, original: original)
            replacement = try! raw(selected, mode: mode)
        }
        if phase == "backup" {
            TransactionSignals.io = { path in
                guard path == AuthSwap$Codex.stashHome.appendingPathComponent("auth.json").path else { return }
                reads += 1
                // The first read is inventory. The second follows the selected proof.
                if reads == 2 { mutation() }
            }
        } else {
            TransactionSignals.attributes = { path in
                let file = URL(fileURLWithPath: path)
                let destination = phase == "backup-write" ? AuthSwap$Codex.stashHome : selected
                if file.deletingLastPathComponent().path == destination.path && file.lastPathComponent.hasPrefix(".auth-") { mutation() }
            }
        }
        var success = false
        do { try AuthSwap$Codex.activate(columnID: "codex:incoming", home: incoming); success = true } catch {}
        let saved = try stable(change) ? AuthSwap$Codex.authData(home: selected) : raw(selected, mode: mode)
        print("COPYBACK mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "Copyback did not reach its post-proof I/O boundary")
        if stable(change) {
            try expect(success && saved.flatMap(AuthSwap$Codex.authIdentity) == AuthSwap$Codex.authIdentity(rotated), "Stable native rotation was not copied back")
        } else {
            try expect(!success && saved == replacement, "Copyback overwrote an independently changed profile or completed a stale switch")
            try expect(try AuthSwap$Codex.authData(home: native) == rotated, "Refused copyback lost the only native rotation")
            if change == "mode" { try Fixture.codexMode(selected, mode == "auto-file" ? "auto" : mode) }
            if change == "login" || change == "owner" {
                try AuthSwap$Codex.activate(columnID: "codex:incoming", home: incoming)
                try expect(try raw(selected, mode: mode) == replacement, "A retry overwrote the independent profile or retained a stale journal")
            }
        }
        if change == "metadata" {
            try expect(manager.fileExists(atPath: selected.appendingPathComponent("settings-marker").path), "Copyback removed unrelated profile settings")
        }
        try expect(Fixture.refreshCalls == 0, "Copyback issued a refresh POST")
    }

    private static func primary(mode: String, phase: String, change: String) throws {
        let native = AuthSwap$Codex.baseHome
        try login(native, name: "original", mode: mode)
        try login(AuthSwap$Codex.stashHome, name: "original", mode: "file")
        let backup = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
        let original = try raw(native, mode: mode)!
        let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
            profileName: "main", source: .codexHome(native))
        var reached = false, deletedBackup = false
        var replacement: Data?
        TransactionSignals.removed = { path in
            if path == AuthSwap$Codex.stashHome.appendingPathComponent("auth.json") { deletedBackup = true }
        }
        TransactionSignals.io = { path in
            let boundary = phase == "backup"
                ? path == AuthSwap$Codex.stashHome.appendingPathComponent("auth.json").path
                : deletedBackup && path == native.appendingPathComponent("auth.json").path
            guard boundary else { return }
            TransactionSignals.io = nil
            reached = true
            try! mutate(native, mode: mode, change: change, original: original)
            replacement = try! raw(native, mode: mode)
        }
        var success = false
        do { try AccountRemoval.remove(account); success = true } catch {}
        let saved = try raw(native, mode: mode)
        print("PRIMARY mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "Removal did not reach its post-discovery I/O boundary")
        if stable(change) { try expect(success && saved == nil, "Stable primary removal failed") }
        else {
            try expect(!success && saved == replacement, "Primary removal deleted a replacement owner or changed storage mode")
            try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) == backup, "Refused primary removal lost its backup")
        }
        try expect(Fixture.refreshCalls == 0, "Primary removal issued a refresh POST")
    }

    private static func rollback(mode: String, change: String) throws {
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try login(native, name: "primary", mode: mode)
        try login(selected, name: "selected", mode: "file")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let oldNative = try AuthSwap$Codex.authData(home: native)
        let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
            profileName: "main", source: .codexHome(native))
        var reached = false
        var replacement: Data?
        TransactionSignals.io = { path in
            guard path == AuthSwap$Codex.stashHome.appendingPathComponent("auth.json").path,
                  !AuthSwap$Codex.isSwapped else { return }
            TransactionSignals.io = nil
            reached = true
            let primary = try! AuthSwap$Codex.authData(home: native)!
            try! mutate(native, mode: mode, change: change, original: primary)
            replacement = try! AuthSwap$Codex.authData(home: native)
            Fixture.denyCodexDelete = true
            Fixture.denyCredentialFileRemovalPath = native.appendingPathComponent("auth.json").path
        }
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        Fixture.denyCodexDelete = false
        Fixture.denyCredentialFileRemovalPath = nil
        let retained = try AuthSwap$Codex.authData(home: native)
        print("ROLLBACK mode=\(mode) change=\(change) reached=\(reached) refused=\(refused)")
        try expect(reached && refused, "Rollback did not reach its post-restoration refusal")
        if stable(change) {
            try expect(retained.flatMap(AuthSwap$Codex.authIdentity) == oldNative.flatMap(AuthSwap$Codex.authIdentity)
                       && AuthSwap$Codex.activeColumnID == "codex:selected", "Stable rollback did not restore the selected native login")
        } else {
            try expect(retained == replacement && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "Rollback overwrote a replacement native login or restored its previous active marker")
        }
        try expect(try AuthSwap$Codex.authData(home: selected) == oldNative && Fixture.refreshCalls == 0,
                   "Refused primary removal lost the selected login or issued a POST")
    }
}
