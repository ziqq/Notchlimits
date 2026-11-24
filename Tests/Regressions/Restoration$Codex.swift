private enum RestorationSignals {
    static var armed = false
    static var published = false
    static var refused = false
    static var io: ((String) -> Void)?
    static var remove: ((URL) throws -> Void)?
    static var attributes: ((String) -> Void)?
    static var unavailableKey: String?
    static var beforeDelete: ((String) -> Void)?
    static var afterDelete: ((String) -> Void)?
    static var beforeWrite: ((String) -> Void)?
    static var afterWrite: ((String) -> Void)?
    static var afterFileRemoval: ((URL) -> Void)?
    static var beforeMove: ((String, String) -> Void)?
    static var afterMove: ((String, String) -> Void)?
    static var keychainDenied = false
    static var afterNativeFileWrite: (() -> Void)?

    static func didWrite(_ key: String) {
        afterWrite?(key)
        if armed && key == Fixture.codexKey(AuthSwap$Codex.baseHome) { published = true }
    }
}

func rename(_ from: UnsafePointer<CChar>, _ to: UnsafePointer<CChar>) -> Int32 {
    let result = Darwin.rename(from, to)
    if result == 0 && RestorationSignals.armed
        && String(cString: to) == AuthSwap$Codex.baseHome.appendingPathComponent("auth.json").path {
        RestorationSignals.published = true
        RestorationSignals.afterNativeFileWrite?()
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
            case "compensation-logins":
                try compensationLogins(both: parts[1] == "both", fileBackup: parts.count > 2 && parts[2] == "file", denied: parts.count > 2 && parts[2] == "denied",
                                       unavailable: parts.count > 2 && parts[2] == "locked")
            case "unreadable-original": try unreadableOriginal(outcome: parts[1])
            case "restart-child": try restartChild(conditions: Set(parts.dropFirst()))
            case "restart-after-cycle": try verifyCycleAfterRestart()
            case "backup-cycle": try switchThroughMixedBackup(mode: parts[1])
            case "audit-backup": try switchThroughMixedBackup(mode: parts[1], fault: parts[2])
            case "audit-rollback": try auditRollbackAfterEmptyNative(fault: parts[1])
            case "audit-backup-restart": try inspectInterruptedBackup(conditions: Set(parts.dropFirst()))
            case "audit-combined": try await auditCombined(conditions: Set(parts.dropFirst()))
            case "audit-stale-keychain": try await staleKeychainAction(action: parts[1], condition: parts[2])
            case "migration": try backupMigration(operation: parts[1], mode: parts[2], phase: parts[3])
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

    private static func unreadableOriginal(outcome: String) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let other = Fixture.root.appendingPathComponent("foreign")
        let replacesManaged = outcome.hasPrefix("replaced-managed-")
        let reusesKeychainLogin = outcome == "replaced-managed-same"
        let refusesCleanup = outcome == "cleanup-refused" || outcome == "aliased-root" || reusesKeychainLogin
        if outcome == "aliased-root" || replacesManaged {
            let support = DesktopApp.supportDirectory.appendingPathComponent("codex-app", isDirectory: true)
            try manager.createDirectory(at: support, withIntermediateDirectories: true)
            try manager.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: support)
        }
        try Fixture.codexLogin(native, account: "primary", mode: "keyring")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try Fixture.codexLogin(other, account: "foreign", mode: "keyring")
        let nativeKey = Fixture.codexKey(native)
        let original = Fixture.codexKeychain[nativeKey]!
        let foreign = Fixture.codexKeychain[Fixture.codexKey(other)]!
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let backup = AuthSwap$Codex.stashHome
        let backupKey = Fixture.codexKey(backup)
        var reached = false
        Fixture.beforeCodexSecretRead = { key in
            guard key == backupKey, Fixture.codexKeychain[nativeKey] == original else { return }
            Fixture.beforeCodexSecretRead = nil
            reached = true
            Fixture.codexKeychain[nativeKey] = foreign
            RestorationSignals.unavailableKey = backupKey
        }
        var refused = false
        do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
        Fixture.beforeCodexSecretRead = nil
        RestorationSignals.unavailableKey = nil
        try expect(reached && refused && Fixture.codexKeychain[backupKey] == original
                   && Fixture.codexKeychain[nativeKey] == foreign,
                   "The fixture did not retain the unchanged original backup")
        let removedPrimaryAlias = outcome.hasPrefix("relocated-primary-removed-alias")
        let relocatedIntoPrimary = outcome == "relocated-primary" || removedPrimaryAlias
        let relocatedIntoManaged = outcome == "relocated-managed"
        if outcome == "relocated-owner" || relocatedIntoManaged || relocatedIntoPrimary || outcome == "non-directory" {
            guard let pending = AuthSwap$Codex.recoveredBackupHomes().first(where: { $0.home != backup }) else {
                throw Failure(description: "The private recovery copy was never registered")
            }
            let pendingKey = Fixture.codexKey(pending.home)
            try expect(Fixture.codexKeychain[pendingKey] == original, "The private copy was never saved")
            let managedRetained = outcome.contains("-managedowner-")
            let parent = (relocatedIntoManaged || managedRetained) ? ProfileDirectories.codexRoot : Fixture.root
            let relocated = parent.appendingPathComponent("relocated-original")
            try manager.moveItem(at: backup, to: relocated)
            if outcome == "non-directory" {
                try Data("restored config file".utf8).write(to: backup)
            } else {
                try manager.createSymbolicLink(at: backup, withDestinationURL: relocated)
                try expect(Fixture.codexKey(backup) != backupKey, "The alias did not change the effective Keychain namespace")
            }
            if relocatedIntoManaged {
                try Fixture.codexMode(relocated, "file")
                try original.write(to: relocated.appendingPathComponent("auth.json"))
            }
            let primaryAlias = Fixture.root.appendingPathComponent("native-route")
            let retargetDuringRead = outcome == "relocated-primary-removed-alias-during-read"
            let retargetDuringDelete = outcome.hasPrefix("relocated-primary-removed-alias-during-delete")
            let reoccupied = outcome.hasSuffix("-reoccupied")
            let reoccupiedSame = outcome.contains("-reoccupied-same")
            let deniedUntilRetry = outcome.hasSuffix("-denied-until-retry")
            let replacesAtDelete = outcome.hasSuffix("-replacement-at-delete")
            let retargetPrimary = retargetDuringRead || retargetDuringDelete
            if relocatedIntoPrimary {
                if retargetPrimary {
                    try manager.createSymbolicLink(at: primaryAlias, withDestinationURL: relocated)
                }
                Fixture.codexHome = retargetPrimary ? primaryAlias.path : relocated.path
                if outcome.contains("-fileowner-") {
                    try Fixture.codexMode(relocated, "file")
                    try original.write(to: relocated.appendingPathComponent("auth.json"))
                } else {
                    Fixture.codexKeychain[Fixture.codexKey(relocated)] = original
                }
            }
            if removedPrimaryAlias {
                Fixture.denyCodexDeleteAccount = pendingKey
                let before = try visibleLogins().filter { $0 == original }.count
                try expect(before == 1 && Fixture.codexKeychain[pendingKey] == original,
                           "The first scan did not leave exactly one column after denied cleanup")
                try manager.removeItem(at: backup)
                if retargetPrimary {
                    var retargeted = false
                    let retainedKey = Fixture.codexKey(relocated)
                    let retarget = {
                        retargeted = true
                        try! manager.removeItem(at: primaryAlias)
                        try! manager.createSymbolicLink(at: primaryAlias, withDestinationURL: native)
                    }
                    Fixture.denyCodexDeleteAccount = nil
                    if outcome.contains("-restart-") {
                        var stageKey = ""
                        let replacementHome = Fixture.root.appendingPathComponent("replacement-for-restart")
                        try Fixture.codexLogin(replacementHome, account: "replacement-after-move", mode: "keyring")
                        let replacement = Fixture.codexKeychain[Fixture.codexKey(replacementHome)]!
                        Fixture.codexKeychain[Fixture.codexKey(replacementHome)] = nil
                        let cut = {
                            let stage = AuthSwap$Codex.recoveredBackupHomes().first {
                                Fixture.codexKey($0.home) == stageKey
                            }!.home
                            let stable = outcome.hasSuffix("-stable")
                            let targetSource = outcome.hasSuffix("-source")
                            let targetStage = outcome.hasSuffix("-stage")
                            if targetSource || targetStage {
                                let target = targetSource ? pending.home : stage
                                try! manager.removeItem(at: primaryAlias)
                                try! manager.createSymbolicLink(at: primaryAlias, withDestinationURL: target)
                            } else if !stable {
                                retarget()
                            }
                            if outcome.contains("-rewrite") {
                                Fixture.codexKeychain[pendingKey] = original
                            }
                            if outcome.contains("-replace") {
                                Fixture.codexKeychain[pendingKey] = replacement
                            }
                            let values: [String: Any] = [
                                "defaults": UserDefaults.standard.dictionaryRepresentation(),
                                "keychain": Fixture.codexKeychain, "home": primaryAlias.path,
                                "original": original,
                                "primary": targetSource && outcome.contains("-replace") ? replacement
                                    : stable || targetSource || targetStage ? original : foreign,
                                "replacement": replacement,
                                "expectsReplacement": outcome.contains("-replace"),
                                "sourcePath": pending.home.path, "stagePath": stage.path, "retainedPath": relocated.path
                            ]
                            let data = try! PropertyListSerialization.data(fromPropertyList: values, format: .binary, options: 0)
                            try! data.write(to: Fixture.root.appendingPathComponent("cleanup-restart.plist"), options: .atomic)
                            _exit(86)
                        }
                        RestorationSignals.beforeMove = { source, destination in
                            if source == pendingKey {
                                stageKey = destination
                                if outcome.contains("-restart-admission") { cut() }
                            }
                        }
                        RestorationSignals.afterMove = { source, _ in
                            if source == pendingKey && outcome.contains("-restart-move") { cut() }
                        }
                        RestorationSignals.afterDelete = { key in
                            if key == stageKey && outcome.contains("-restart-delete") { cut() }
                        }
                        _ = Discovery$Real().discover()
                        throw Failure(description: "Fixture missed the requested process cut")
                    }
                    if replacesAtDelete {
                        var replaced = false
                        let replace: (String) -> Void = { key in
                            guard key == pendingKey else { return }
                            RestorationSignals.beforeDelete = nil
                            RestorationSignals.beforeMove = nil
                            replaced = true
                            Fixture.codexKeychain[pendingKey] = foreign
                            try! Data("new-keychain-revision".utf8).write(to: Fixture.classicKeychainDatabase(), options: .atomic)
                        }
                        RestorationSignals.beforeDelete = replace
                        RestorationSignals.beforeMove = { key, _ in replace(key) }
                        _ = Discovery$Real().discover()
                        try expect(replaced && Fixture.codexKeychain[retainedKey] == original,
                                   "Fixture did not replace the recovery item at the deletion boundary")
                        let after = try visibleLogins().filter { $0 == foreign }.count
                        print("Replacement visible after cleanup: \(after), Keychain still contains replacement: \(Fixture.codexKeychain[pendingKey] == foreign)")
                        try expect(after == 1 && Fixture.codexKeychain[pendingKey] == foreign,
                                   "Duplicate cleanup deleted the independent replacement login")
                        return
                    }
                    if retargetDuringDelete {
                        var deletionKey = pendingKey
                        RestorationSignals.beforeMove = { key, destination in
                            if key == pendingKey { deletionKey = destination }
                        }
                        RestorationSignals.afterDelete = { key in
                            guard key == deletionKey else { return }
                            RestorationSignals.beforeMove = nil
                            RestorationSignals.afterDelete = nil
                            if outcome.hasSuffix("-final-read") {
                                Fixture.beforeCodexSecretRead = { key in
                                    guard key == pendingKey else { return }
                                    Fixture.beforeCodexSecretRead = nil
                                    retarget()
                                }
                            } else {
                                retarget()
                            }
                            if reoccupied { Fixture.codexKeychain[pendingKey] = foreign }
                            if reoccupiedSame { Fixture.codexKeychain[pendingKey] = original }
                            if deniedUntilRetry {
                                Fixture.denyCodexWrite = true
                                Fixture.denyCodexRead = true
                            }
                        }
                    } else {
                        Fixture.beforeCodexSecretRead = { key in
                            guard key == retainedKey else { return }
                            Fixture.beforeCodexSecretRead = nil
                            retarget()
                        }
                    }
                    _ = Discovery$Real().discover()
                    try expect(retargeted && Fixture.codexKey(primaryAlias) == nativeKey
                               && Fixture.codexKeychain[nativeKey] == foreign
                               && Fixture.codexKeychain[retainedKey] == original,
                               "Fixture did not retarget the route during the duplicate cleanup")
                    if deniedUntilRetry {
                        try expect(Fixture.codexKeychain[pendingKey] == (reoccupiedSame ? original : nil),
                                   "Fixture did not deny reserve writes")
                        Fixture.denyCodexWrite = false
                        Fixture.denyCodexRead = false
                        let counts = try (0..<3).map { _ in try visibleLogins().filter { $0 == original }.count }
                        print("Former login visible after restoring Keychain access: \(counts)")
                        try expect(counts == [1, 1, 1], "Retry lost the detached recovery state after a temporary Keychain outage")
                        return
                    }
                    let after = try visibleLogins().filter { $0 == original }.count
                    print("Former login visible after retarget: \(after), recovery present: \(Fixture.codexKeychain[pendingKey] != nil)")
                    try expect(after == 1 && Fixture.codexKeychain[pendingKey] == (reoccupied ? foreign : original),
                               "Deduplication deleted recovery after the retained credentials left the primary route")
                    return
                }
                if outcome == "relocated-primary-removed-alias-unrelated-removal" {
                    try manager.createSymbolicLink(at: backup, withDestinationURL: selected)
                    let selectedKey = Fixture.codexKey(selected)
                    let accounts = Discovery$Real().discover()
                    guard let selectedLogin = Fixture.codexKeychain[selectedKey],
                          let account = accounts.first(where: { $0.id == AuthSwap$Codex.profileColumnID(selected.lastPathComponent) }),
                          let primary = accounts.first(where: { $0.id == AuthSwap$Codex.defaultColumnID }) else {
                        throw Failure(description: "Discovery missed an independent login")
                    }
                    let primaryRemoval = Result { try AccountRemoval.remove(primary) }
                    try expect(selectedLogin != original && Fixture.codexKeychain[pendingKey] == original
                               && (try AuthSwap$Codex.authData(columnID: primary.id, home: relocated)) == original,
                               "Removing the primary changed an active or pending login despite denied cleanup")
                    if case .success = primaryRemoval {
                        throw Failure(description: "Primary removal ignored its pending copy")
                    }
                    try AccountRemoval.remove(account)
                    try expect(Fixture.codexKeychain[selectedKey] == nil && Fixture.codexKeychain[pendingKey] == original
                               && (try AuthSwap$Codex.authData(columnID: primary.id, home: relocated)) == original,
                               "Removing the independent profile affected primary recovery")
                    return
                }
                if outcome == "relocated-primary-removed-alias-self" {
                    try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                               "Fixture must route the primary home directly")
                    try manager.moveItem(at: relocated, to: Fixture.root.appendingPathComponent("previous-native"))
                    try manager.createSymbolicLink(at: relocated, withDestinationURL: pending.home)
                    try expect(Fixture.codexKey(relocated) == pendingKey
                               && (try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: relocated)) == original,
                               "Fixture did not route the native login to the private copy")
                    Fixture.denyCodexDeleteAccount = nil
                    let scans = try (0..<2).map { _ in try visibleLogins().filter { $0 == original }.count }
                    try expect(scans == [1, 1] && Fixture.codexKeychain[pendingKey] == original,
                               "Discovery deleted the current primary credentials while comparing the namespace with itself")
                    Fixture.codexHome = native.path
                    try expect(try visibleLogins().filter { $0 == original }.count == 1,
                               "Moving the primary again hid the retained login")
                    return
                }
                if outcome == "relocated-primary-removed-alias-switch" {
                    try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
                    try expect(AuthSwap$Codex.activeColumnID == "codex:selected"
                               && (try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: relocated)) == original,
                               "Switching did not move the primary credentials into the backup")
                }
                Fixture.denyCodexDeleteAccount = nil
                let after = try visibleLogins().filter { $0 == original }.count
                print("Login columns before and after unlinking the alias: \(before), \(after)")
                try expect(after == 1 && Fixture.codexKeychain[pendingKey] == nil
                           && (try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: relocated)) == original,
                           "Removing an obsolete alias published a duplicate of the still-live primary login")
                return
            }
            let scans = try (0..<3).map { _ in try visibleLogins().filter { $0 == original }.count }
            print("Saved login visible columns for \(outcome): \(scans)")
            try expect(scans == [1, 1, 1] && Fixture.codexKeychain[nativeKey] == foreign,
                       "A proven path change hid the saved login or duplicated the managed login")
            let retained = Fixture.codexKeychain[pendingKey]
            try expect(relocatedIntoManaged || relocatedIntoPrimary ? retained == nil : retained == original,
                       "Recovery did not reconcile the private copy against the effective namespace")
            return
        }
        if outcome == "replaced" || outcome == "replaced-alias" || replacesManaged {
            let moved = Fixture.root.appendingPathComponent("original-backup")
            try manager.moveItem(at: backup, to: moved)
            if reusesKeychainLogin {
                try manager.createDirectory(at: backup, withIntermediateDirectories: true)
                try Fixture.codexMode(backup, "keyring")
            } else {
                let replacement = outcome == "replaced-alias" ? Fixture.root.appendingPathComponent("replacement") : backup
                try Fixture.codexLogin(replacement, account: "replacement", mode: "file")
                if replacement != backup {
                    try manager.createSymbolicLink(at: backup, withDestinationURL: replacement)
                }
                let newFile = replacement.appendingPathComponent("auth.json")
                let newLogin = try Data(contentsOf: newFile)
                Fixture.codexKeychain[backupKey] = nil
                let scans = try (0..<3).map { _ in try visibleLogins() }
                let counts = scans.map { $0.filter { $0 == original }.count }
                print("Saved login visible columns: \(counts)")
                try expect(counts == [1, 1, 1] && (try Data(contentsOf: newFile)) == newLogin
                           && Fixture.codexKeychain[nativeKey] == foreign,
                           "A replacement hid the saved login or recovery modified another owner's credentials")
                if replacesManaged {
                    try expect(scans.allSatisfy { $0.filter { $0 == newLogin }.count == 1 },
                               "Recovery hid or duplicated the independent managed login")
                }
                return
            }
        }
        if outcome == "logged-out" { Fixture.codexKeychain[backupKey] = nil }
        Fixture.denyCodexDelete = refusesCleanup
        let copies = try visibleLogins().filter { $0 == original }.count
        print("Original backup visible columns: \(copies)")
        try expect(copies == 1, "The same unchanged grant became visible in more than one column after unlock")
        let recovered = try Discovery$Real().discover().first { account in
            guard case .codexHome(let home) = account.source else { return false }
            return try AuthSwap$Codex.authData(columnID: account.id, home: home) == original
        }
        guard let recovered, case .codexHome(let recoveredHome) = recovered.source else {
            throw Failure(description: "The saved login could not be discovered")
        }
        try expect((Fixture.codexKey(recoveredHome) == backupKey) == (outcome != "logged-out"),
                   "Recovery did not prefer the surviving original CLI namespace")
        if refusesCleanup {
            var removalRefused = false
            do { try AccountRemoval.remove(recovered) } catch { removalRefused = true }
            try expect(removalRefused && Fixture.codexKeychain[backupKey] == original,
                       "Removal lost the original namespace while its private copy could not be cleared")
            Fixture.denyCodexDelete = false
        }
        try AccountRemoval.remove(recovered)
        let resurrected = try visibleLogins().contains(original)
        print("Removed backup login reappeared: \(resurrected)")
        try expect(!resurrected && Fixture.codexKeychain[nativeKey] == foreign,
                   "Removing the recovered profile resurrected its staged copy or touched the native login")
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

    private static func compensationLogins(both: Bool, fileBackup: Bool, denied: Bool, unavailable: Bool) throws {
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
        let backup = AuthSwap$Codex.stashHome
        let backupKey = Fixture.codexKey(backup)
        let account = Discovery$Real().discover().first { $0.id == "codex:selected" }!
        var reached = false
        RestorationSignals.beforeDelete = { key in
            guard key != backupKey && key != nativeKey && Fixture.codexKeychain[backupKey] == nil else { return }
            RestorationSignals.beforeDelete = nil
            reached = true
            if fileBackup {
                try! Fixture.codexMode(backup, "file")
                try! newPrimary.write(to: backup.appendingPathComponent("auth.json"), options: .atomic)
            } else {
                Fixture.codexKeychain[backupKey] = newPrimary
            }
            if both { Fixture.codexKeychain[nativeKey] = newNative }
            Fixture.denyCodexDelete = true
            if unavailable { RestorationSignals.unavailableKey = backupKey }
            if denied {
                Fixture.beforeCodexSecretRead = { key in
                    Fixture.denyCodexRead = key == backupKey
                }
            }
        }
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        Fixture.denyCodexDelete = false
        RestorationSignals.beforeDelete = nil
        Fixture.beforeCodexSecretRead = nil
        Fixture.denyCodexRead = false
        RestorationSignals.unavailableKey = nil
        let visible = try visibleLogins()
        let retained = fileBackup ? try? Data(contentsOf: backup.appendingPathComponent("auth.json")) : Fixture.codexKeychain[backupKey]
        print("Codex removal both=\(both) file=\(fileBackup) reached=\(reached) refused=\(refused) active=\(AuthSwap$Codex.activeColumnID) old primary copies=\(visible.filter { $0 == primary }.count) new backup visible=\(visible.contains(newPrimary)) backup still written=\(retained == newPrimary)")
        try expect(reached && refused && Fixture.codexKeychain[nativeKey] == (both ? newNative : selectedNative),
                   "Fixture did not exercise a refused managed-profile deletion with native credentials intact")
        try expect(visible.filter { $0 == primary }.count == 1 && visible.contains(newPrimary),
                   "Compensation duplicated the former primary and hid the new login in the backup")
        try expect(retained == newPrimary, "Compensation modified the independent backup login")
    }

    private static func backupMigration(operation: String, mode: String, phase: String) throws {
        Fixture.keychainExists = false
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let incoming = Fixture.root.appendingPathComponent("new-primary")
        let initialMode = mode == "file" ? "keyring" : "file"
        try Fixture.codexLogin(native, account: "primary", mode: initialMode)
        try Fixture.codexLogin(selected, account: "selected", mode: "file")
        try Fixture.codexLogin(incoming, account: "new-primary", mode: mode)
        let primary = try AuthSwap$Codex.authData(home: native)!
        let fresh = try AuthSwap$Codex.authData(home: incoming)!
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let selectedLogin = try AuthSwap$Codex.authData(home: native)
        let backup = AuthSwap$Codex.stashHome
        let file = backup.appendingPathComponent("auth.json")
        let key = Fixture.codexKey(backup)
        let account = Discovery$Real().discover().first { $0.id == "codex:selected" }!

        func attempt() -> Bool {
            do {
                if operation == "remove" { try AccountRemoval.remove(account) }
                else { try AuthSwap$Codex.restoreDefault() }
                return true
            } catch { return false }
        }
        func publishCLIReplacement() throws {
            try Fixture.codexMode(backup, mode)
            if phase == "empty" { try manager.removeItem(at: file) }
            if mode == "file" { try fresh.write(to: file, options: .atomic) }
            else if phase != "config-only" { Fixture.codexKeychain[key] = fresh }
        }

        var reached = false
        let lateRead = phase == "foreign" || phase == "foreign-denied"
        if phase == "unlink" {
            RestorationSignals.remove = { url in
                guard url.path == file.path else { return }
                RestorationSignals.remove = nil
                reached = true
                try publishCLIReplacement()
            }
        } else {
            try publishCLIReplacement()
            reached = !lateRead
        }
        let foreign = Fixture.root.appendingPathComponent("foreign")
        try Fixture.codexLogin(foreign, account: "foreign-native", mode: "file")
        let foreignLogin = try AuthSwap$Codex.authData(home: foreign)!
        if lateRead {
            let nativeFile = native.appendingPathComponent("auth.json")
            RestorationSignals.armed = true
            RestorationSignals.afterNativeFileWrite = {
                guard !reached, (try? Data(contentsOf: nativeFile)) == primary else { return }
                RestorationSignals.afterNativeFileWrite = nil
                reached = true
                try! foreignLogin.write(to: nativeFile, options: .atomic)
                Fixture.denyCodexRead = phase == "foreign-denied"
            }
        }
        Fixture.denyCodexRead = phase == "denied"
        let first = attempt()
        Fixture.denyCodexRead = false
        RestorationSignals.afterNativeFileWrite = nil
        RestorationSignals.remove = nil
        let current = try AuthSwap$Codex.authData(home: native)
        let visible = try visibleLogins()
        print("Codex backup migration operation=\(operation) mode=\(mode) phase=\(phase) reached=\(reached) succeeded=\(first) old=\(visible.contains(primary)) replacement=\(visible.contains(fresh))")
        try expect(reached, "Backup migration boundary was not reached")
        if phase == "config-only" {
            try expect(first && current == primary && visible.contains(primary),
                       "A mode edit without a replacement login blocked restoration")
            return
        }
        if lateRead {
            try expect(!first && current == foreignLogin && visible.filter { $0 == fresh }.count == 1
                       && visible.filter { $0 == primary }.count == 1,
                       "Concurrent native login hid the backup or kept stale routing")
            try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "The selected profile kept routing to the independent native login")
            try expect(Fixture.codexKeychain[key] == fresh && (try? Data(contentsOf: file)) != fresh,
                       "Recovery moved the original CLI login or wrote it to plaintext")
            let recovered = Discovery$Real().discover().first { account in
                guard case .codexHome(let home) = account.source else { return false }
                return (try? AuthSwap$Codex.authData(columnID: account.id, home: home)) == fresh
            }!
            let recoveredAgain = Discovery$Real().discover().contains { $0.id == recovered.id }
            try expect(recoveredAgain && manager.fileExists(atPath: selected.path),
                       "Rediscovery lost the retained profile or removed the selected one")
            try AuthSwap$Codex.activate(columnID: account.id, home: selected)
            try expect((phase == "foreign" || AuthSwap$Codex.stashHome.path != backup.path)
                       && (try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)) == foreignLogin
                       && Fixture.codexKeychain[key] == fresh,
                       "The next switch reused the recovered CLI namespace")
            try AuthSwap$Codex.restoreDefault()
            try AccountRemoval.remove(recovered)
            let afterRemoval = Discovery$Real().discover()
            try expect(!afterRemoval.contains { $0.id == recovered.id }
                       && (try AuthSwap$Codex.authData(home: native)) == foreignLogin,
                       "Removing the recovered profile affected the native primary")
            return
        }
        try expect(!first && current == selectedLogin && AuthSwap$Codex.activeColumnID == "codex:selected",
                   "Backup migration completed using the old login or left a stale native route")
        try expect(manager.fileExists(atPath: selected.path), "Refused transaction removed the selected profile")
        if mode != "file" {
            try expect(Fixture.codexKeychain[key] == fresh && (try? Data(contentsOf: file)) != fresh,
                       "Compensation changed the Keychain login or wrote it to plaintext")
        }
        if phase == "denied" {
            try expect(visible.contains(primary), "A denied replacement read abandoned the pinned backup")
            try expect(!attempt(), "Retry failed to recognize the now-readable independent login")
        }
        let recovered = try visibleLogins()
        try expect(recovered.contains(fresh), "The configured replacement login is hidden")
        if phase != "empty" {
            try expect(recovered.filter { $0 == primary }.count == 1,
                       "The original login was lost or duplicated during migration compensation")
        }
        try expect(attempt() && (try AuthSwap$Codex.authData(home: native)) == fresh,
                   "A retry did not restore the configured replacement login")
    }

    private static func restartChild(conditions: Set<String>) throws {
        let data = try Data(contentsOf: Fixture.root.appendingPathComponent("cleanup-restart.plist"))
        let state = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        for (key, value) in state["defaults"] as! [String: Any] { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = state["keychain"] as! [String: Data]
        Fixture.codexHome = state["home"] as? String
        let original = state["original"] as! Data
        let primary = state["primary"] as! Data
        let replacement = state["replacement"] as! Data
        let source = URL(fileURLWithPath: state["sourcePath"] as! String, isDirectory: true)
        let stage = URL(fileURLWithPath: state["stagePath"] as! String, isDirectory: true)
        let config = stage.appendingPathComponent("config.toml")
        let marker = stage.appendingPathComponent("settings-marker")
        let parent = source.deletingLastPathComponent()
        let replacementParent = Data("replacement parent file".utf8)
        if conditions.contains("empty-config-removed") { try manager.removeItem(at: config) }
        if conditions.contains("keep-stage") { try Data("owned by another process".utf8).write(to: marker) }
        if conditions.contains("symlink-config") {
            let target = Fixture.root.appendingPathComponent("external-settings")
            try manager.copyItem(at: config, to: target)
            try manager.removeItem(at: config)
            try manager.createSymbolicLink(at: config, withDestinationURL: target)
        }
        let mode = ["ephemeral", "file"].first(where: conditions.contains)
        if let mode {
            Fixture.managedCodex["config_toml_base64"] =
                Data("cli_auth_credentials_store = '\(mode)'\n".utf8).base64EncodedString()
        }
        if conditions.contains("parent-replaced") {
            try manager.moveItem(at: parent, to: parent.appendingPathExtension("moved"))
            try replacementParent.write(to: parent, options: .withoutOverwriting)
            var info = stat()
            try expect(Darwin.lstat(source.path, &info) != 0 && errno == ENOTDIR,
                       "Expected ENOTDIR after replacing the recovery parent")
        }
        if conditions.contains("directory-denied") {
            try expect(Darwin.chmod(parent.path, 0) == 0, "Could not protect the recovery parent")
            defer { _ = Darwin.chmod(parent.path, 0o700) }
            var info = stat()
            try expect(Darwin.lstat(source.path, &info) != 0 && errno == EACCES,
                       "Expected EACCES checking the recovery source")
            RestorationSignals.keychainDenied = conditions.contains("denied")
            _ = Discovery$Real().discover()
            RestorationSignals.keychainDenied = false
            _ = Discovery$Real().discover()
        }
        if mode != nil || conditions.contains("denied") {
            RestorationSignals.keychainDenied = conditions.contains("denied")
            _ = Discovery$Real().discover()
            RestorationSignals.keychainDenied = false
            _ = Discovery$Real().discover()
        }
        Fixture.managedCodex = [:]
        func alternateLogin() throws -> Data {
            let home = Fixture.root.appendingPathComponent("alternate-restart-login")
            try Fixture.codexLogin(home, account: "alternate-restart", mode: "keyring")
            return Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home))!
        }
        if conditions.contains("audit-renew") || conditions.contains("audit-renew-auto")
            || conditions.contains("audit-renew-same") || conditions.contains("audit-managed-remove")
            || conditions.contains("audit-private-remove") || conditions.contains("audit-switch")
            || conditions.contains("audit-managed-remove-denied") || conditions.contains("audit-managed-remove-relogin") {
            let retained = URL(fileURLWithPath: state["retainedPath"] as! String, isDirectory: true)
            let file = retained.appendingPathComponent("auth.json")
            let key = Fixture.codexKey(retained)
            let other = try alternateLogin()
            if conditions.contains("audit-renew") || conditions.contains("audit-renew-auto") || conditions.contains("audit-renew-same") {
                let same = conditions.contains("audit-renew-same")
                Fixture.codexKeychain[key] = same ? original : other
                try Fixture.codexMode(retained, conditions.contains("audit-renew-auto") ? "auto" : "keyring")
                guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(retained) }),
                      let renewal = try AuthSwap$Codex.beginRenewal(columnID: account.id, home: retained) else {
                    throw Failure(description: "Fixture did not admit a sleeping Keychain renewal")
                }
                defer { AuthSwap$Codex.finishRenewal(renewal) }
                let payload = try JSONSerialization.jsonObject(with: renewal.record.data) as! [String: Any]
                let refresh = (payload["tokens"] as! [String: Any])["refresh_token"] as! String
                let response = OAuth$Codex.Tokens(idToken: nil,
                    accessToken: Fixture.accessToken(expiresAt: Date().addingTimeInterval(86400).timeIntervalSince1970),
                    refreshToken: "synthetic-audit-keychain-rotated")
                let updated = try AuthSwap$Codex.storeRenewed(renewal, usedRefreshToken: refresh, tokens: response)
                try expect(updated?.data == Fixture.codexKeychain[key] && updated?.data != renewal.record.data,
                           "Fixture did not complete the Keychain token update")
                let onDisk = try? Data(contentsOf: file)
                print("Completed Keychain renewal; file exists: \(manager.fileExists(atPath: file.path)); file preserved: \(onDisk == original)")
                try expect(same ? onDisk == nil : onDisk == original, "Keychain renewal removed a distinct inactive file login")
                if conditions.contains("cycle") {
                    AuthSwap$Codex.finishRenewal(renewal)
                    try finishMixedStoreCycle(retained: retained, file: file, original: original, updated: updated!.data)
                }
                return
            }
            if conditions.contains("audit-switch") {
                Fixture.codexKeychain[key] = original
                try other.write(to: file)
                try Fixture.codexMode(retained, "keyring")
                _ = Discovery$Real().discover()
                let chosen = ProfileDirectories.codexRoot.appendingPathComponent("audit-switch-target")
                try Fixture.codexLogin(chosen, account: "audit-switch-target", mode: "file")
                guard let account = Discovery$Real().discover().first(where: {
                    if case .codexHome(let url) = $0.source { return url.path == chosen.path }
                    return false
                }) else {
                    throw Failure(description: "Fixture did not discover the switch target")
                }
                let switched = Result { try AppSwitcher$Codex().prepare(account) }
                let onDisk = try? Data(contentsOf: file)
                print("Switched native route: \(AuthSwap$Codex.activeColumnID == account.id); file preserved: \(onDisk == other)")
                try expect(onDisk == other, "Switching the native Keychain account deleted the distinct inactive file login")
                if case .success = switched {
                    try expect(AuthSwap$Codex.activeColumnID == account.id, "Fixture did not complete the native switch")
                }
                return
            }
            let reloginDuringRemoval = conditions.contains("audit-managed-remove-relogin")
            if !reloginDuringRemoval { Fixture.codexKeychain[key] = other }
            try Fixture.codexMode(retained, "file")
            guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(retained) }) else {
                throw Failure(description: "Fixture did not discover the active file login")
            }
            if conditions.contains("audit-managed-remove-denied") { RestorationSignals.unavailableKey = key }
            var reached = false
            if reloginDuringRemoval {
                Fixture.beforeDirectoryMove = { from, to in
                    guard from.path == retained.path, to.lastPathComponent.hasPrefix(".removed-") else { return }
                    reached = true
                    Fixture.codexKeychain[key] = other
                }
            }
            let removed = Result { try AccountRemoval.remove(account) }
            Fixture.beforeDirectoryMove = nil
            RestorationSignals.unavailableKey = nil
            try expect(!reloginDuringRemoval || reached, "Fixture missed the managed removal boundary")
            let remainingProfiles = try visibleLogins().filter { $0 == other }.count
            let directoryExists = manager.fileExists(atPath: retained.path)
            let keychainExists = Fixture.codexKeychain[key] == other
            let succeeded = (try? removed.get()) != nil
            print("File profile removal success: \(succeeded); directory preserved: \(directoryExists); Keychain preserved: \(keychainExists); remaining views: \(remainingProfiles)")
            try expect(directoryExists && keychainExists, "Removing the active file login made the separate Keychain login unreachable")
            if succeeded {
                try expect(!manager.fileExists(atPath: file.path), "Completed removal did not remove the file login")
            } else {
                try expect(try Data(contentsOf: file) == original, "Refused removal changed the file login")
            }
            try Fixture.codexMode(retained, "keyring")
            try expect(try visibleLogins().filter { $0 == other }.count == 1, "The inactive Keychain login could not be restored")
            return
        }
        if conditions.contains("file-owner-mixed") || conditions.contains("file-owner-auto")
            || conditions.contains("file-owner-distinct") || conditions.contains("file-owner-empty") {
            let retained = Fixture.root.appendingPathComponent("relocated-original", isDirectory: true)
            let retainedFile = retained.appendingPathComponent("auth.json")
            let retainedKey = Fixture.codexKey(retained)
            try expect(try Data(contentsOf: retainedFile) == original, "Fixture did not retain the old file login")
            if conditions.contains("remove-keyring-login") {
                Fixture.codexKeychain[retainedKey] = try alternateLogin()
            } else if !conditions.contains("file-owner-empty") {
                Fixture.codexKeychain[retainedKey] = conditions.contains("file-owner-distinct") ? primary : replacement
            }
            try Fixture.codexMode(retained, conditions.contains("file-owner-auto") ? "auto" : "keyring")
            if conditions.contains("deny-first") {
                RestorationSignals.keychainDenied = true
                _ = Discovery$Real().discover()
                RestorationSignals.keychainDenied = false
            }
            let scanned = try (0..<3).map { _ in try visibleLogins() }
            try expect(scanned.allSatisfy { !$0.contains(original) }, "Fixture exposed the old file login in the alternate mode")
            let activeCounts = scanned.map { $0.filter { $0 == replacement }.count }
            try expect(activeCounts == [1, 1, 1], "Expected one active replacement login, got \(activeCounts)")
            if conditions.contains("remove-keyring-login") {
                let before = Fixture.codexKeychain[retainedKey]
                guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(retained) }) else {
                    throw Failure(description: "The distinct active Keychain login was missing")
                }
                try expect((try? AccountRemoval.remove(account)) == nil,
                           "Removing the active Keychain login also consumed the inactive file login")
                try expect(Fixture.codexKeychain[retainedKey] == before, "Refused removal changed the active Keychain login")
            }
            try expect(try Data(contentsOf: retainedFile) == original, "The alternate mode modified the file login")
            try Fixture.codexMode(retained, "file")
        }
        if conditions.contains("audit-stale-switch") || conditions.contains("audit-stale-remove")
            || conditions.contains("audit-stable-switch") {
            let key = Fixture.codexKey(source)
            let other = try alternateLogin()
            Fixture.codexKeychain[key] = other
            try Fixture.codexMode(source, "file")
            let file = source.appendingPathComponent("auth.json")
            try replacement.write(to: file, options: .withoutOverwriting)
            guard let profile = Discovery$Real().discover().first(where: { $0.source == .codexHome(source) }) else {
                throw Failure(description: "Fixture did not discover the active file login before selection")
            }
            try expect(try AuthSwap$Codex.authData(columnID: profile.id, home: source) == replacement,
                       "Fixture selected an unexpected profile")
            let switcher = AppSwitcher$Codex()
            switcher.beginSwitch(profile)
            if !conditions.contains("audit-stable-switch") { try Fixture.codexMode(source, "keyring") }
            if conditions.contains("file-cycle") {
                try other.write(to: file, options: .atomic)
                try Fixture.codexMode(source, "file")
            }
            if conditions.contains("audit-stale-remove") {
                try manager.moveItem(at: file, to: Fixture.root.appendingPathComponent("retired-file-login"))
                let removed = Result { try AccountRemoval.remove(profile) }
                print("Stale removal success: \((try? removed.get()) != nil); replacement survives: \(Fixture.codexKeychain[key] == other)")
                try expect(Fixture.codexKeychain[key] == other, "Removal of the stale file selection deleted another Keychain login")
            } else {
                let switched = Result { try switcher.prepare(profile) }
                let current = try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome)
                print("Switch success: \((try? switched.get()) != nil); published other login: \(current == other)")
                if conditions.contains("audit-stable-switch") {
                    try expect((try? switched.get()) != nil && current == replacement, "Stable file selection did not switch")
                } else {
                    try expect(current != other, "Switching a stale file selection published the unrelated Keychain login")
                }
            }
            return
        }
        if conditions.contains("active-file-readd") || conditions.contains("active-file-readd-empty-keychain") {
            let key = Fixture.codexKey(source)
            try expect(Fixture.codexKeychain[key] == original, "Fixture did not leave the prior Keychain login")
            try Fixture.codexMode(source, "file")
            let file = source.appendingPathComponent("auth.json")
            try replacement.write(to: file, options: .withoutOverwriting)
            if conditions.contains("active-file-readd-empty-keychain") { Fixture.codexKeychain[key] = nil }
            let inactive = conditions.contains("remove-file-login") ? try alternateLogin() : nil
            if let inactive { Fixture.codexKeychain[key] = inactive }
            if conditions.contains("deny-first") {
                RestorationSignals.keychainDenied = true
                _ = Discovery$Real().discover()
                RestorationSignals.keychainDenied = false
            }
            if conditions.contains("inactive-denied") { RestorationSignals.unavailableKey = key }
            let counts = try (0..<3).map { _ in try visibleLogins().filter { $0 == replacement }.count }
            RestorationSignals.unavailableKey = nil
            print("Actively configured file login counts: \(counts)")
            try expect(try Data(contentsOf: file) == replacement, "Stored file login was changed")
            try expect(counts == [1, 1, 1], "The re-added profile in the configured file store stayed hidden")
            if let inactive {
                guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(source) }) else {
                    throw Failure(description: "The re-added file profile was missing")
                }
                try AccountRemoval.remove(account)
                try expect(!manager.fileExists(atPath: file.path) && Fixture.codexKeychain[key] == inactive,
                           "Removing the file login altered the separate Keychain login")
                try Fixture.codexMode(source, "keyring")
                try expect(try visibleLogins().filter { $0 == inactive }.count == 1,
                           "Removing the active file login forgot the separate Keychain login")
            }
        }
        let actualPrimary = try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome)
        try expect(actualPrimary == primary, "Restart changed the newly selected primary login")
        let scans = try (0..<3).map { _ in try visibleLogins() }
        let originalCounts = scans.map { $0.filter { $0 == original }.count }
        let replacementCounts = scans.map { $0.filter { $0 == replacement }.count }
        print("Restart old columns: \(originalCounts); replacement columns: \(replacementCounts)")
        try expect(originalCounts == [1, 1, 1], "Restart lost or duplicated the former login")
        if (state["expectsReplacement"] as? Bool) == true {
            try expect(replacementCounts == [1, 1, 1], "Restart lost or duplicated the independently re-added login")
        }
        if conditions.contains("empty-stage") || conditions.contains("empty-config-removed") {
            try expect(Fixture.codexKeychain[Fixture.codexKey(stage)] == nil,
                       "The empty stage unexpectedly acquired a Keychain login")
            try expect(!manager.fileExists(atPath: stage.path), "Restart left the empty stage on disk")
        }
        if conditions.contains("keep-stage") {
            try expect(try Data(contentsOf: marker) == Data("owned by another process".utf8),
                       "Cleanup affected files from another owner")
        }
        if conditions.contains("symlink-config") {
            try expect(try manager.destinationOfSymbolicLink(atPath: config.path)
                           == Fixture.root.appendingPathComponent("external-settings").path,
                       "Cleanup removed an independent configuration link")
        }
        if conditions.contains("parent-replaced") {
            try expect(try Data(contentsOf: parent) == replacementParent,
                       "Cleanup modified the file that replaced the recovery parent")
        }
    }

    private static func finishMixedStoreCycle(retained: URL, file: URL, original: Data, updated: Data) throws {
        func profile() throws -> DiscoveredAccount {
            guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(retained) }) else {
                throw Failure(description: "The cycle lost the retained profile")
            }
            return account
        }
        let primary = try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome)
        try Fixture.codexMode(retained, "file")
        let chosen = try profile()
        let switcher = AppSwitcher$Codex()
        switcher.beginSwitch(chosen)
        _ = try switcher.prepare(chosen)
        try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome) == original,
                   "The cycle published a different login")
        try AuthSwap$Codex.restoreDefault()
        try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome) == primary,
                   "The cycle did not restore the primary login")
        try AccountRemoval.remove(profile())
        try expect(!manager.fileExists(atPath: file.path) && Fixture.codexKeychain[Fixture.codexKey(retained)] == updated,
                   "File removal changed the rotated Keychain login")
        try Fixture.codexMode(retained, "keyring")
        try checkpointCycle(updated: updated, primary: primary!)
    }

    private static func switchThroughMixedBackup(mode: String, fault: String? = nil) throws {
        let native = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(native, account: "primary", mode: mode)
        if mode != "file" {
            let key = Fixture.codexKey(native)
            Fixture.codexKeychain[key] = try withAccountSubject(Fixture.codexKeychain[key]!, subject: "primary-person")
        }
        let chosen = try Fixture.codexAccount("cycle-selection")
        guard case .codexHome(let selection) = chosen.source,
              let primary = try AuthSwap$Codex.authData(home: native) else {
            throw Failure(description: "Fixture could not set up the switch")
        }
        try AuthSwap$Codex.activate(columnID: chosen.id, home: selection)
        let stash = AuthSwap$Codex.stashHome
        let other = Fixture.root.appendingPathComponent("cycle-alternate")
        let alternateMode = mode == "file" ? "keyring" : "file"
        try Fixture.codexLogin(other, account: "inactive", mode: alternateMode)
        let key = Fixture.codexKey(stash)
        let file = stash.appendingPathComponent("auth.json")
        let inactive: Data
        if alternateMode == "file" {
            inactive = try Data(contentsOf: other.appendingPathComponent("auth.json"))
            try inactive.write(to: file, options: .withoutOverwriting)
        } else {
            inactive = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(other))!
            Fixture.codexKeychain[key] = inactive
        }
        if fault == "signed-out-primary" {
            Fixture.codexKeychain[key] = nil
            let selected = Discovery$Real().discover().first { $0.id == chosen.id }
            guard let selected else { throw Failure(description: "The actively selected profile was missing") }
            let removed = Result { try AccountRemoval.remove(selected) }
            let retained = (try? Data(contentsOf: file)) == inactive
            print("Selected removal success: \((try? removed.get()) != nil); separate auth.json preserved: \(retained)")
            try expect(retained, "Removing the selected profile deleted the independent auth.json of the signed-out primary backup")
            return
        }
        if let fault, fault.hasPrefix("cut-") {
            let previous = try AuthSwap$Codex.authData(home: native)
            let cut: (String) -> Void = { deletedKey in
                guard deletedKey == key else { return }
                try! checkpointCycle(updated: inactive, primary: primary, backup: stash.path, selectedID: chosen.id,
                                     backupMode: mode, previous: previous)
                _exit(86)
            }
            if fault == "cut-rollback-native" || fault == "cut-rollback-removal" {
                if fault == "cut-rollback-native" { Fixture.denyCodexDeleteAccount = key }
                else {
                    Fixture.denyProfileRemoval = selection.path
                    Fixture.denyProfileMove = true
                }
                let nativeKey = Fixture.codexKey(native)
                RestorationSignals.afterWrite = { written in
                    if written == nativeKey && Fixture.codexKeychain[written] == previous { cut(key) }
                }
                if fault == "cut-rollback-removal" {
                    guard let selected = Discovery$Real().discover().first(where: { $0.id == chosen.id }) else {
                        throw Failure(description: "Missing selected profile before removal")
                    }
                    try AccountRemoval.remove(selected)
                    throw Failure(description: "Fixture missed rollback of native after removal refusal")
                }
            } else if fault.hasSuffix("publication") {
                let nativeKey = Fixture.codexKey(native)
                let publication: (String) -> Void = { written in if written == nativeKey { cut(key) } }
                if fault == "cut-before-publication" { RestorationSignals.beforeWrite = publication }
                else { RestorationSignals.afterWrite = publication }
            } else if mode == "file" {
                RestorationSignals.afterFileRemoval = { removed in if removed.path == file.path { cut(key) } }
            } else if fault == "cut-before-delete" { RestorationSignals.beforeDelete = cut }
            else { RestorationSignals.afterDelete = cut }
            if fault == "cut-during-removal" {
                guard let selected = Discovery$Real().discover().first(where: { $0.id == chosen.id }) else {
                    throw Failure(description: "The selected profile was missing before removal")
                }
                try AccountRemoval.remove(selected)
                throw Failure(description: "Fixture missed the backup deletion during removal")
            }
        }
        try AuthSwap$Codex.restoreDefault()
        if fault?.hasPrefix("cut-") == true { throw Failure(description: "Fixture missed Keychain deletion of the primary backup") }
        try expect(try AuthSwap$Codex.authData(home: native) == primary, "The primary did not restore from the mixed backup")
        let remaining = alternateMode == "file" ? (try? Data(contentsOf: file)) : Fixture.codexKeychain[key]
        try expect(remaining == inactive, "Cleaning the primary backup removed a separate login")
        try Fixture.codexMode(stash, alternateMode)
        try checkpointCycle(updated: inactive, primary: primary)
    }

    private static func checkpointCycle(updated: Data, primary: Data, backup: String? = nil, selectedID: String? = nil,
                                        backupMode: String? = nil, previous: Data? = nil) throws {
        var state: [String: Any] = ["defaults": UserDefaults.standard.dictionaryRepresentation(),
                                    "keychain": Fixture.codexKeychain, "home": AuthSwap$Codex.baseHome.path,
                                    "updated": updated, "primary": primary]
        if let backup { state["backup"] = backup }
        if let selectedID { state["selectedID"] = selectedID }
        if let backupMode { state["backupMode"] = backupMode }
        if let previous { state["previous"] = previous }
        let data = try PropertyListSerialization.data(fromPropertyList: state, format: .binary, options: 0)
        try data.write(to: Fixture.root.appendingPathComponent("cycle-restart.plist"), options: .atomic)
    }

    private static func verifyCycleAfterRestart() throws {
        let data = try Data(contentsOf: Fixture.root.appendingPathComponent("cycle-restart.plist"))
        let state = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        for (key, value) in state["defaults"] as! [String: Any] { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = state["keychain"] as! [String: Data]
        Fixture.codexHome = state["home"] as? String
        let updated = state["updated"] as! Data
        let primary = state["primary"] as! Data
        let counts = try (0..<3).map { _ in try visibleLogins().filter { $0 == updated }.count }
        try expect(counts == [1, 1, 1], "Restart after the full cycle lost or duplicated the rotated Keychain login")
        try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome) == primary,
                   "Restart after the cycle changed the primary login")
    }

    private static func auditRollbackAfterEmptyNative(fault: String) throws {
        let native = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(native, account: "primary-rollback", mode: "keyring")
        let chosen = try Fixture.codexAccount("rollback-selection")
        guard case .codexHome(let selection) = chosen.source else { throw Failure(description: "Missing rollback fixture") }
        try AuthSwap$Codex.activate(columnID: chosen.id, home: selection)
        let stash = AuthSwap$Codex.stashHome
        let key = Fixture.codexKey(native)
        if fault == "absent" { Fixture.codexKeychain[key] = nil }
        let previous = Fixture.codexKeychain[key]
        let other = Fixture.root.appendingPathComponent("rollback-other", isDirectory: true)
        try Fixture.codexLogin(other, account: "independent-rollback", mode: "file")
        let inactive = try Data(contentsOf: other.appendingPathComponent("auth.json"))
        let file = native.appendingPathComponent("auth.json")
        try inactive.write(to: file)
        Fixture.denyCodexDeleteAccount = Fixture.codexKey(stash)
        let outcome = Result { try AuthSwap$Codex.restoreDefault() }
        let retained = (try? Data(contentsOf: file)) == inactive
        let priorRestored = Fixture.codexKeychain[key] == previous
        print("Rollback returned failure: \((try? outcome.get()) == nil); native active restored: \(priorRestored); independent file preserved: \(retained)")
        try expect((try? outcome.get()) == nil && priorRestored, "Fixture did not enter rollback of the native publication")
        try expect(retained, "Rollback deleted a separate native file login")
    }

    private static func inspectInterruptedBackup(conditions: Set<String>) throws {
        let snapshot = try Data(contentsOf: Fixture.root.appendingPathComponent("cycle-restart.plist"))
        let state = try PropertyListSerialization.propertyList(from: snapshot, format: nil) as! [String: Any]
        for (key, value) in state["defaults"] as! [String: Any] { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = state["keychain"] as! [String: Data]
        Fixture.codexHome = state["home"] as? String
        let stash = URL(fileURLWithPath: state["backup"] as! String, isDirectory: true)
        let inactive = state["updated"] as! Data
        let primary = state["primary"] as! Data
        let file = stash.appendingPathComponent("auth.json")
        let beforePublication = conditions.contains("before-publication")
        let beforeDelete = conditions.contains("before-delete") || beforePublication
        let fileMode = state["backupMode"] as? String == "file"
        let key = Fixture.codexKey(stash)
        let currentInactive = { fileMode ? Fixture.codexKeychain[key] : try? Data(contentsOf: file) }
        let stored = fileMode ? (try? Data(contentsOf: file)) : Fixture.codexKeychain[key]
        try expect(stored == (beforeDelete ? primary : nil) && currentInactive() == inactive,
                   "Cut did not leave the expected backup records")
        let initialNative = beforePublication ? state["previous"] as? Data : primary
        try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome) == initialNative,
                   "Cut did not leave the expected active native login")
        if beforePublication {
            _ = Discovery$Real().discover()
            try expect(AuthSwap$Codex.activeColumnID == state["selectedID"] as? String,
                       "Recovery changed routing before publication")
        }
        if conditions.contains("denied") {
            RestorationSignals.unavailableKey = beforeDelete || fileMode ? key : Fixture.codexKey(AuthSwap$Codex.baseHome)
            _ = Discovery$Real().discover()
            RestorationSignals.unavailableKey = nil
            try expect(currentInactive() == inactive, "Recovery during Keychain denial changed a different login")
        }
        var expectedPrimary = primary
        if conditions.contains("native-relogin") {
            let native = AuthSwap$Codex.baseHome
            try Fixture.codexLogin(native, account: "after-cut", mode: "keyring")
            expectedPrimary = Fixture.codexKeychain[Fixture.codexKey(native)]!
        }
        if conditions.contains("parent-replaced") {
            let parent = stash.deletingLastPathComponent()
            let moved = parent.appendingPathExtension("moved")
            try manager.moveItem(at: parent, to: moved)
            let replacement = Data("new parent file".utf8)
            try replacement.write(to: parent, options: .withoutOverwriting)
            var info = stat()
            try expect(Darwin.lstat(stash.path, &info) != 0 && errno == ENOTDIR, "Fixture did not replace the backup parent")
            let columns = Discovery$Real().discover()
            let activeID = AuthSwap$Codex.activeColumnID
            try expect(activeID == AuthSwap$Codex.defaultColumnID && columns.contains { $0.id == activeID },
                       "The retired backup path blocked discovery of the restored primary")
            let relocated = moved.appendingPathComponent(stash.lastPathComponent).appendingPathComponent("auth.json")
            try expect(try Data(contentsOf: relocated) == inactive && Data(contentsOf: parent) == replacement,
                       "Recovery changed the moved credentials or their replacement path")
            return
        }
        if conditions.contains("retry") || beforePublication {
            let restored = Result { try AuthSwap$Codex.restoreDefault() }
            let retained = currentInactive() == inactive
            let native = try AuthSwap$Codex.authData(home: AuthSwap$Codex.baseHome)
            print("Recovery retry success: \((try? restored.get()) != nil); file preserved: \(retained); expected active login: \(native == expectedPrimary)")
            try expect((try? restored.get()) != nil && retained && native == expectedPrimary,
                       "Retry of the interrupted switch lost or rolled back a different login")
            return
        }
        if beforeDelete { _ = Discovery$Real().discover() }
        try Fixture.codexMode(stash, fileMode ? "keyring" : "file")
        let columns = Discovery$Real().discover().filter { $0.provider == .codex }
        let active = AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID
        let defaultLogin = try columns.first { $0.id == AuthSwap$Codex.defaultColumnID }.flatMap { account -> Data? in
            guard case .codexHome(let home) = account.source else { return nil }
            return try AuthSwap$Codex.authData(columnID: account.id, home: home)
        }
        let counts = try (0..<3).map { _ in try visibleLogins().filter { $0 == inactive }.count }
        print("Restart default route finalized: \(active); default represents primary: \(defaultLogin == expectedPrimary); independent login counts: \(counts)")
        try expect(active && defaultLogin == expectedPrimary && counts == [1, 1, 1],
                   "Restart retained the old route or hid the second login")
        if conditions.contains("removal") {
            try expect(columns.contains { $0.id == state["selectedID"] as? String },
                       "Recovery replayed the interrupted user's profile removal")
        }
    }

    private static func withAccountSubject(_ data: Data, subject: String) throws -> Data {
        var document = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        var tokens = document["tokens"] as! [String: Any]
        let claims = try JSONSerialization.data(withJSONObject: ["iss": "https://auth.example.invalid", "sub": subject])
        tokens["id_token"] = "synthetic.\(claims.base64EncodedString()).signature"
        document["tokens"] = tokens
        return try JSONSerialization.data(withJSONObject: document)
    }

    private final class DiscoveryDuringRestart: AccountDiscovery {
        var first: [DiscoveredAccount]?

        init(first: [DiscoveredAccount]) { self.first = first }

        func discover() -> [DiscoveredAccount] {
            if let first {
                self.first = nil
                return first
            }
            return Discovery$Real().discover()
        }
    }

    @MainActor
    private static func auditCombined(conditions: Set<String>) throws {
        let snapshot = try Data(contentsOf: Fixture.root.appendingPathComponent("cycle-restart.plist"))
        let state = try PropertyListSerialization.propertyList(from: snapshot, format: nil) as! [String: Any]
        for (key, value) in state["defaults"] as! [String: Any] { UserDefaults.standard.set(value, forKey: key) }
        Fixture.codexKeychain = state["keychain"] as! [String: Data]
        Fixture.codexHome = state["home"] as? String
        let native = AuthSwap$Codex.baseHome
        let stash = URL(fileURLWithPath: state["backup"] as! String, isDirectory: true)
        let selectedID = state["selectedID"] as! String
        let primary = state["primary"] as! Data
        let previous = state["previous"] as! Data
        let inactive = state["updated"] as! Data
        let nativeKey = Fixture.codexKey(native)
        let stashKey = Fixture.codexKey(stash)
        let discovery = Discovery$Real()
        if conditions.contains("denied") {
            RestorationSignals.unavailableKey = nativeKey
            _ = discovery.discover()
            RestorationSignals.unavailableKey = nil
        }
        if conditions.contains("usage") {
            // Simulate the profile list already present before the temporary denial.
            let name = "unchanged-file-profile"
            _ = try Fixture.codexAccount(name)
            guard let home = ProfileDirectories.codexProfiles().first(where: { $0.lastPathComponent == name }),
                  let login = try AuthStorage$Codex(home: home).loginSelection() else {
                throw Failure(description: "Missing the independent file login")
            }
            let independent = DiscoveredAccount(id: AuthSwap$Codex.profileColumnID(name), provider: .codex,
                                                 profileName: name, source: .codexHome(home), codexLogin: login)
            var column = AccountColumn(id: independent.id, provider: .codex, profileName: independent.profileName)
            column.updatedAt = Date()
            UsageCache().save(column)
            _ = UsageHistory().record(columnID: independent.id,
                                      window: LimitWindow(key: "fixture", title: "Fixture", utilization: 42, resetsAt: nil),
                                      now: Date())
            let history = UserDefaults.standard.data(forKey: "usageHistory")
            let store = UsageStore(providers: [:], discovery: DiscoveryDuringRestart(first: [independent]))
            store.rediscover(force: true)
            try expect(store.columns.contains { $0.id == independent.id } && UsageCache().load(id: independent.id) != nil,
                       "Fixture did not load the independent profile with usage")
            RestorationSignals.unavailableKey = nativeKey
            store.rediscover(force: true)
            let visibleDenied = store.columns.contains { $0.id == independent.id }
            RestorationSignals.unavailableKey = nil
            try Fixture.codexLogin(native, account: "new-native-login", mode: "keyring")
            store.rediscover(force: true)
            let cached = UsageCache().load(id: independent.id) != nil
            print("Independent profile visible during denial: \(visibleDenied); cached usage preserved after recovery: \(cached)")
            try expect(visibleDenied && cached && history != nil && UserDefaults.standard.data(forKey: "usageHistory") == history,
                       "Native Keychain denial retired usage of an unrelated file-backed profile")
            return
        }
        if conditions.contains("ephemeral") || conditions.contains("file-mode") {
            try expect(Fixture.codexKeychain[nativeKey] == previous && Fixture.codexKeychain[stashKey] == primary,
                       "Fixture did not stop before publication")
            try Fixture.codexMode(native, conditions.contains("file-mode") ? "file" : "ephemeral")
            _ = discovery.discover()
            try Fixture.codexMode(native, "keyring")
        }
        if conditions.contains("same-workspace") {
            try mutate(native, mode: "keyring", change: "rotation", original: primary)
            let replacement = try withAccountSubject(Fixture.codexKeychain[nativeKey]!, subject: "another-person")
            Fixture.codexKeychain[nativeKey] = replacement
            let oldCounts = try (0..<3).map { _ in try visibleLogins().filter { $0 == primary }.count }
            try expect(oldCounts == [1, 1, 1] && Fixture.codexKeychain[nativeKey] == replacement,
                       "Recovery confused two users in the same workspace")
            return
        }
        if conditions.contains("relogin") {
            try Fixture.codexLogin(native, account: "replacement-native-login", mode: "keyring")
        }
        if conditions.contains("stash-relogin") {
            try expect(Fixture.codexKeychain[nativeKey] == primary && Fixture.codexKeychain[stashKey] == primary,
                       "Fixture did not stop after publication and before cleanup")
            try Fixture.codexLogin(stash, account: "replacement-backup-login", mode: "file")
            let replacement = try Data(contentsOf: stash.appendingPathComponent("auth.json"))
            RestorationSignals.unavailableKey = stashKey
            _ = discovery.discover()
            RestorationSignals.unavailableKey = nil
            let columns = (0..<3).map { _ in discovery.discover().filter { $0.provider == .codex }.count }
            try expect(Fixture.codexKeychain[nativeKey] == primary && (try Data(contentsOf: stash.appendingPathComponent("auth.json"))) == replacement,
                       "Recovery overwrote the new login")
            print("Discovered Codex profiles after the mode switch and Keychain recovery: \(columns)")
            try expect(columns == [3, 3, 3], "Backup relogin in a new backend permanently blocked Codex discovery")
            try expect(Fixture.codexKeychain[stashKey] == nil && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "Recovery did not retire only the duplicate Keychain login")
            return
        }
        if conditions.contains("duplicate-file") {
            let file = stash.appendingPathComponent("auth.json")
            try primary.write(to: file)
            _ = discovery.discover()
            try expect(Fixture.codexKeychain[stashKey] == nil && !manager.fileExists(atPath: file.path)
                       && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "Recovery left a second backend with the duplicate primary credentials")
            return
        }
        if conditions.contains("rotation") || conditions.contains("access-only") {
            try expect(Fixture.codexKeychain[nativeKey] == primary && Fixture.codexKeychain[stashKey] == primary,
                       "Fixture did not stop after publication and before cleanup")
            let sharedHome: URL?
            if conditions.contains("shared-copy") {
                let copy = try Fixture.codexAccount("copied-primary")
                guard case .codexHome(let home) = copy.source else { throw Failure(description: "Missing managed copy") }
                try primary.write(to: home.appendingPathComponent("auth.json"))
                sharedHome = home
            } else { sharedHome = nil }
            if conditions.contains("access-only") {
                let grant = try JSONSerialization.jsonObject(with: primary) as! [String: Any]
                let tokens = grant["tokens"] as! [String: Any]
                Fixture.codexKeychain[nativeKey] = AuthSwap$Codex.renewedAuth(
                    primary, usedRefreshToken: tokens["refresh_token"] as! String,
                    tokens: OAuth$Codex.Tokens(idToken: nil, accessToken: Fixture.accessToken(expiresAt: 10), refreshToken: nil),
                    now: Date())
            } else { try mutate(native, mode: "keyring", change: "rotation", original: primary) }
            let refreshed = bytes(native)!
            try expect(AuthSwap$Codex.authIdentity(primary) != AuthSwap$Codex.authIdentity(refreshed),
                       "Fixture did not rotate the native credentials")
            if let sharedHome {
                _ = discovery.discover()
                let renewal = try AuthSwap$Codex.beginRenewal(columnID: "codex:copied-primary", home: sharedHome)
                let current = try Data(contentsOf: sharedHome.appendingPathComponent("auth.json"))
                try expect(renewal == nil && AuthStorage$Codex.sameCredentials(current, refreshed),
                           "The managed copy kept a spent grant after restart")
            }
            let staleCounts = try (0..<3).map { _ in try visibleLogins().filter { $0 == primary }.count }
            let expired = try AuthSwap$Codex.authData(home: native) != refreshed
            let retired = UserDefaults.standard.stringArray(forKey: "codexRetiredNativeGrants") ?? []
            try expect((try? Data(contentsOf: stash.appendingPathComponent("auth.json"))) == inactive,
                       "Recovery changed an independent dormant credential")
            print("Old primary login copies discovered: \(staleCounts); native refresh lost: \(expired)")
            let expectedRetiredCount = conditions.contains("access-only") ? 0 : 1
            try expect(staleCounts == [0, 0, 0] && !expired && retired.count == expectedRetiredCount,
                       "Native refresh became a second profile with the retired primary token")
            return
        }
        let expectedSelected = !conditions.contains("relogin")
        let expectedNative = Fixture.codexKeychain[nativeKey]
        if expectedSelected {
            try expect(expectedNative == previous && Fixture.codexKeychain[stashKey] == primary,
                       "Fixture did not leave the prior login and its backup")
        }
        let accounts = discovery.discover().filter { $0.provider == .codex }
        let expectedID = expectedSelected ? selectedID : AuthSwap$Codex.defaultColumnID
        let defaultRecord = try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: native)
        let correctPrimary = defaultRecord == (expectedSelected ? primary : expectedNative)
        let activeID = accounts.first(where: { $0.isActive })?.id
        print("Expected route: \(expectedID); actual route: \(activeID ?? "none"); primary assignment correct: \(correctPrimary)")
        try expect(activeID == expectedID && correctPrimary && Fixture.codexKeychain[nativeKey] == expectedNative,
                   "Restart reassigned the prior selected login to the primary route")
    }

    @MainActor
    private static func staleKeychainAction(action: String, condition: String) throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "native", mode: "file")
        let oldNative = try AuthSwap$Codex.authData(home: base)
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("action-target", isDirectory: true)
        try Fixture.codexLogin(profile, account: "confirmed-login", mode: "keyring")
        guard let account = Discovery$Real().discover().first(where: { $0.source == .codexHome(profile) }) else {
            throw Failure(description: "Fixture did not discover the initial Keychain login")
        }
        let switcher = AppSwitcher$Codex()
        let key = Fixture.codexKey(profile)
        let opaque = condition.hasPrefix("opaque")
        if opaque { Fixture.codexModified[key] = Date(timeIntervalSince1970: 100) }
        Fixture.denyCodexRead = condition != "available"
        if action == "switch" { switcher.captureSelection(account) }
        let expected = action == "remove" ? AuthSwap$Codex.actionLogin(for: account) : nil
        Fixture.denyCodexRead = false
        let unchanged = condition == "opaque-unchanged"
        if !unchanged {
            try Fixture.codexLogin(profile, account: "replacement-after-confirmation", mode: "keyring")
            if opaque {
                // The same item and timestamp may survive the credential update.
                try Data("changed database".utf8).write(to: Fixture.classicKeychainDatabase(), options: .atomic)
            }
        }
        let replacement = Fixture.codexKeychain[key]!
        if action == "remove" {
            var result: Result<Void, Error>?
            AccountRemoval.remove(account, expectedLogin: expected) { result = $0 }
            guard let result else { throw Failure(description: "Fixture did not reach actual coordinated removal") }
            print("Stale removal success: \((try? result.get()) != nil); replacement preserved: \(Fixture.codexKeychain[key] == replacement)")
            if unchanged {
                try expect((try? result.get()) != nil && Fixture.codexKeychain[key] == nil,
                           "A verified unchanged Keychain login could not be removed")
            } else {
                try expect(Fixture.codexKeychain[key] == replacement, "A temporary denial at confirmation allowed removal to erase a different login")
            }
        } else {
            switcher.beginSwitch(account)
            let result = Result { try switcher.prepare(account) }
            let current = try AuthSwap$Codex.authData(home: base)
            print("Stale switch success: \((try? result.get()) != nil); replacement published: \(current == replacement)")
            try expect(current == (unchanged ? replacement : oldNative),
                       "A temporary denial at confirmation allowed the switch to select a different login")
        }
    }

    private static func visibleLogins() throws -> [Data] {
        try Discovery$Real().discover().compactMap { account in
            guard case .codexHome(let home) = account.source else { return nil }
            return try AuthSwap$Codex.authData(columnID: account.id, home: home)
        }
    }
}
