private enum RestorationSignals {
    static var armed = false
    static var published = false
    static var refused = false
    static var io: ((String) -> Void)?
    static var remove: ((URL) throws -> Void)?
    static var attributes: ((String) -> Void)?
    static var beforeDelete: ((String) -> Void)?

    static func didWrite(_ key: String) {
        if armed && key == Fixture.codexKey(AuthSwap$Codex.baseHome) { published = true }
    }
}

func rename(_ from: UnsafePointer<CChar>, _ to: UnsafePointer<CChar>) -> Int32 {
    let result = Darwin.rename(from, to)
    if result == 0 && RestorationSignals.armed
        && String(cString: to) == AuthSwap$Codex.baseHome.appendingPathComponent("auth.json").path {
        RestorationSignals.published = true
    }
    return result
}

@main
enum Restoration$Codex {
    private static let manager = Foundation.FileManager.default

    static func main() async {
        do {
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            switch parts[0] {
            case "compensate": try compensation(mode: parts[1], phase: parts[2], change: parts[3])
            case "compensation-logins": try compensationLogins(both: parts[1] == "both")
            case "routing": try routing(returning: parts[1] == "return", foreign: parts[2] == "foreign")
            default: try restoration(kind: parts[0], mode: parts[1], phase: parts[2], change: parts[3])
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

    // Keychain callbacks already hold the production interaction lock.
    // Inspect the synthetic store directly, without re-entering that API.
    private static func bytes(_ home: URL) -> Data? {
        Fixture.codexKeychain[Fixture.codexKey(home)]
            ?? (try? Data(contentsOf: home.appendingPathComponent("auth.json")))
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
        case "rotation":
            let root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            let grant = (root["tokens"] as! [String: Any])["refresh_token"] as! String
            let rotated = AuthSwap$Codex.renewedAuth(original, usedRefreshToken: grant,
                tokens: OAuth$Codex.Tokens(idToken: nil,
                    accessToken: Fixture.accessToken(expiresAt: Date().addingTimeInterval(86400).timeIntervalSince1970),
                    refreshToken: "synthetic-native-rotation"), now: Date())!
            if mode == "file" || mode == "auto-file" {
                Fixture.codexKeychain[Fixture.codexKey(home)] = nil
                try rotated.write(to: home.appendingPathComponent("auth.json"))
            } else { Fixture.codexKeychain[Fixture.codexKey(home)] = rotated }
        case "metadata": try Data("keep-settings".utf8).write(to: home.appendingPathComponent("settings-marker"))
        case "stable": break
        default: throw Failure(description: "Unknown restoration mutation")
        }
    }

    private static func restoration(kind: String, mode: String, phase: String, change: String) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try login(native, name: "primary", mode: mode)
        try login(selected, name: "selected", mode: "file")
        let primary = try AuthSwap$Codex.authData(home: native)
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let previous = try AuthSwap$Codex.authData(home: native)
        let backup = AuthSwap$Codex.stashHome
        var reached = false
        var replacement: Data?
        RestorationSignals.armed = true
        let mutation = {
            guard !reached else { return }
            reached = true
            RestorationSignals.io = nil
            RestorationSignals.attributes = nil
            RestorationSignals.remove = nil
            Fixture.beforeCredentialDelete = nil
            let home = kind == "cleanup" ? backup : native
            let original = bytes(home)!
            try! mutate(home, mode: mode, change: change, original: original)
            replacement = bytes(home)
        }
        if kind == "cleanup" {
            RestorationSignals.io = { path in
                guard RestorationSignals.published else { return }
                let configuration = phase == "config" && path == native.appendingPathComponent("config.toml").path
                let deletion = path == backup.appendingPathComponent("auth.json").path
                // The old implementation has no post-publication native check;
                // its deletion read remains the equivalent observable boundary.
                if configuration || deletion { mutation() }
            }
        } else {
            let refuse = {
                RestorationSignals.refused = true
                if phase == "operation" { mutation() }
            }
            RestorationSignals.remove = { url in
                guard RestorationSignals.published && url.path == backup.appendingPathComponent("auth.json").path else { return }
                refuse()
                throw CocoaError(.fileWriteNoPermission)
            }
            Fixture.beforeCredentialDelete = {
                guard RestorationSignals.published else { return }
                refuse()
                Fixture.denyCodexDelete = true
            }
            if phase == "prepare" {
                RestorationSignals.attributes = { path in
                    let file = URL(fileURLWithPath: path)
                    guard RestorationSignals.refused, file.deletingLastPathComponent().path == native.path,
                          file.lastPathComponent.hasPrefix(".auth-") else { return }
                    mutation()
                }
            }
        }
        var success = false
        do { try AuthSwap$Codex.restoreDefault(); success = true } catch {}
        RestorationSignals.io = nil
        RestorationSignals.remove = nil
        RestorationSignals.attributes = nil
        Fixture.beforeCredentialDelete = nil
        Fixture.denyCodexDelete = false
        let current = bytes(native)
        let retained = bytes(backup)
        // Internal backups retain their captured backend across local config
        // edits. Native mode changes still invalidate publication ownership.
        let stable = change == "stable" || change == "metadata" || kind == "cleanup" && change == "mode"
        print("RESTORE kind=\(kind) mode=\(mode) phase=\(phase) change=\(change) published=\(RestorationSignals.published) reached=\(reached) success=\(success)")
        try expect(RestorationSignals.published && reached, "The post-publication boundary was not reached")
        if kind == "cleanup" {
            if stable {
                try expect(success && retained == nil && current == primary
                           && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                           "Stable default restoration failed or retained an obsolete backup")
            } else {
                try expect(!success && retained == replacement, "Cleanup consumed or abandoned a replacement backup login")
                try expect(current == previous && AuthSwap$Codex.activeColumnID == "codex:selected",
                           "Refused cleanup did not retain its original native selection")
                if change == "mode" { try Fixture.codexMode(backup, mode == "auto-file" ? "auto" : mode) }
                try AuthSwap$Codex.restoreDefault()
                try expect(try AuthSwap$Codex.authData(home: native) == replacement,
                           "A refused cleanup prevented a safe retry or published its previous source")
            }
        } else {
            try expect(!success && retained != nil, "Refused cleanup completed or discarded its backup")
            if stable {
                try expect(current == previous && AuthSwap$Codex.activeColumnID == "codex:selected",
                           "Stable cleanup refusal failed to restore its previous selection")
            } else {
                try expect(current == replacement, "Cleanup rollback overwrote an independent native login or rotation")
            }
        }
        try expect(Fixture.refreshCalls == 0 && manager.fileExists(atPath: selected.appendingPathComponent("auth.json").path),
                   "Default restoration issued a POST or removed its selected profile")
    }

    private static func compensation(mode: String, phase: String, change: String) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try login(native, name: "primary", mode: mode)
        try login(selected, name: "selected", mode: "keyring")
        let primary = try AuthSwap$Codex.authData(home: native)!
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let previous = try AuthSwap$Codex.authData(home: native)
        let backup = AuthSwap$Codex.stashHome
        let account = DiscoveredAccount(id: "codex:selected", provider: .codex,
            profileName: "selected", source: .codexHome(selected))
        var reached = false, refused = false
        var replacement: Data?
        let mutation = {
            guard !reached else { return }
            reached = true
            RestorationSignals.attributes = nil
            RestorationSignals.beforeDelete = nil
            try! mutate(backup, mode: mode, change: change, original: primary)
            replacement = bytes(backup)
        }
        RestorationSignals.beforeDelete = { key in
            guard key != Fixture.codexKey(backup) else { return }
            refused = true
            Fixture.denyCodexDelete = true
            if phase == "before" { mutation() }
        }
        if phase == "prepare" {
            RestorationSignals.attributes = { path in
                let file = URL(fileURLWithPath: path)
                guard refused, file.deletingLastPathComponent().path == backup.path,
                      file.lastPathComponent.hasPrefix(".auth-") else { return }
                mutation()
            }
        }
        var failed = false
        do { try AccountRemoval.remove(account) } catch { failed = true }
        RestorationSignals.beforeDelete = nil
        RestorationSignals.attributes = nil
        Fixture.denyCodexDelete = false
        let current = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
        print("COMPENSATE mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) refused=\(failed)")
        try expect(reached && refused && failed, "Removal did not reach the compensation boundary")
        if change == "login" {
            try expect(current == replacement && AuthSwap$Codex.stashHome.path == backup.path,
                       "Compensation overwrote or redirected the new primary login")
            let recovered = Discovery$Real().discover().compactMap { account -> URL? in
                guard case .codexHome(let home) = account.source,
                      home.lastPathComponent.hasPrefix("recovered-") else { return nil }
                return home
            }
            try expect(try recovered.contains { try AuthSwap$Codex.authData(home: $0) == primary },
                       "Compensation did not preserve the former primary in a discoverable recovery")
        } else {
            try expect(current == primary, "Stable compensation failed to restore the primary backup")
        }
        try expect(try AuthSwap$Codex.authData(home: native) == previous
                   && AuthSwap$Codex.activeColumnID == "codex:selected" && Fixture.refreshCalls == 0,
                   "Compensation lost the selected native login, its route, or issued a POST")
    }

    private static func routing(returning: Bool, foreign: Bool) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let other = Fixture.root.appendingPathComponent("other-login")
        try Fixture.codexLogin(native, account: "primary", mode: returning ? "keyring" : "auto")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try Fixture.codexLogin(other, account: "foreign", mode: "keyring")
        let nativeKey = Fixture.codexKey(native)
        let primary = Fixture.codexKeychain[nativeKey]!
        let selectedBytes = Fixture.codexKeychain[Fixture.codexKey(selected)]!
        let otherBytes = Fixture.codexKeychain[Fixture.codexKey(other)]!
        if returning { try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected) }
        else { try primary.write(to: native.appendingPathComponent("auth.json")) }
        let observationKey = returning ? Fixture.codexKey(AuthSwap$Codex.stashHome) : nativeKey
        let published = returning ? primary : selectedBytes
        var reached = false
        Fixture.beforeCodexSecretRead = { key in
            guard key == observationKey, Fixture.codexKeychain[nativeKey] == published else { return }
            Fixture.beforeCodexSecretRead = nil
            reached = true
            if foreign { Fixture.codexKeychain[nativeKey] = otherBytes }
        }
        var success = false
        do {
            if returning { try AuthSwap$Codex.restoreDefault() }
            else { try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected) }
            success = true
        } catch { print("Codex switch returned \(error)") }
        Fixture.beforeCodexSecretRead = nil
        let routed = try AuthSwap$Codex.authData(columnID: "codex:selected", home: selected)
        print("Codex returning=\(returning) reached=\(reached) foreign=\(foreign) success=\(success) active=\(AuthSwap$Codex.activeColumnID) foreign served as selected=\(routed == otherBytes)")
        try expect(reached, "Fixture missed the Keychain read after native publication")
        try expect(Fixture.codexKeychain[nativeKey] == (foreign ? otherBytes : published), "Native login was lost")
        try expect(success == !foreign && routed == selectedBytes, "Selected Codex column was routed to an independent native login")
        if foreign {
            try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID
                       && (try visibleLogins()).contains(primary),
                       "Refused switch hid the former primary or kept a false active route")
        }
    }

    private static func compensationLogins(both: Bool) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let nativeLogin = Fixture.root.appendingPathComponent("native-login")
        let backupLogin = Fixture.root.appendingPathComponent("backup-login")
        try Fixture.codexLogin(native, account: "primary", mode: "keyring")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try Fixture.codexLogin(nativeLogin, account: "new-native", mode: "keyring")
        try Fixture.codexLogin(backupLogin, account: "new-primary", mode: "keyring")
        let nativeKey = Fixture.codexKey(native)
        let primary = Fixture.codexKeychain[nativeKey]!
        let newNative = Fixture.codexKeychain[Fixture.codexKey(nativeLogin)]!
        let newPrimary = Fixture.codexKeychain[Fixture.codexKey(backupLogin)]!
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let selectedNative = Fixture.codexKeychain[nativeKey]!
        let backupKey = Fixture.codexKey(AuthSwap$Codex.stashHome)
        let account = Discovery$Real().discover().first { $0.id == "codex:selected" }!
        var reached = false
        RestorationSignals.beforeDelete = { key in
            guard key != backupKey && key != nativeKey && Fixture.codexKeychain[backupKey] == nil else { return }
            RestorationSignals.beforeDelete = nil
            reached = true
            Fixture.codexKeychain[backupKey] = newPrimary
            if both { Fixture.codexKeychain[nativeKey] = newNative }
            Fixture.denyCodexDelete = true
        }
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        Fixture.denyCodexDelete = false
        RestorationSignals.beforeDelete = nil
        let visible = try visibleLogins()
        print("Codex removal both=\(both) reached=\(reached) refused=\(refused) active=\(AuthSwap$Codex.activeColumnID) old primary copies=\(visible.filter { $0 == primary }.count) new backup visible=\(visible.contains(newPrimary)) backup still written=\(Fixture.codexKeychain[backupKey] == newPrimary)")
        try expect(reached && refused && Fixture.codexKeychain[nativeKey] == (both ? newNative : selectedNative),
                   "Fixture did not exercise a refused managed-profile deletion with native credentials intact")
        try expect(visible.filter { $0 == primary }.count == 1 && visible.contains(newPrimary),
                   "Compensation duplicated the former primary and hid the new login in the backup")
    }
    private static func visibleLogins() throws -> [Data] {
        try Discovery$Real().discover().compactMap { account in
            guard case .codexHome(let home) = account.source else { return nil }
            return try AuthSwap$Codex.authData(columnID: account.id, home: home)
        }
    }
}
