private enum RecoverySignals {
    static var deleted: ((String) -> Void)?
    static var created: ((URL) -> Void)?
    static var gated: (() -> Void)?
    static var renaming: (() -> Void)?
    static var absenceRead: ((String) -> Void)?
    static var staged: (() -> Void)?
}
@main @MainActor enum Reservation$Codex {
    static let manager = Foundation.FileManager.default
    static func main() async {
        do {
            Fixture.keychainExists = false
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            try reservation(mode: parts[0], replacementMode: parts[1], phase: parts[2])
        } catch { print("FAIL: \(error)"); exit(1) }
    }
    static func reservation(mode: String, replacementMode: String, phase: String) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("original")
        let id = "codex:original"
        try Cleanup$Authentication.login(AuthSwap$Codex.baseHome, name: "native", mode: "file")
        let native = try Cleanup$Authentication.bytes(AuthSwap$Codex.baseHome, mode: "file")!
        try Cleanup$Authentication.login(home, name: "original", mode: mode)
        let original = try Cleanup$Authentication.bytes(home, mode: mode)!
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        store.setCustomName("Original name", for: id)
        store.setHidden(id, hidden: true)
        var reached = false
        var replacement: Data?
        var recoveryHome: URL?
        var replacementConfig: Data?
        var replacementOwner: DirectoryIdentity?
        var deleted = false, attemptedRename = false
        RecoverySignals.deleted = { _ in deleted = true }
        RecoverySignals.created = { url in
            guard url.lastPathComponent.hasPrefix("recovered-") else { return }
            RecoverySignals.created = nil
            recoveryHome = url
            let inject = {
                RecoverySignals.gated = nil
                if phase != "absence" { RecoverySignals.renaming = nil }
                RecoverySignals.absenceRead = nil
                RecoverySignals.staged = nil
                reached = true
                guard replacementMode != "stable" else { return }
                try! Cleanup$Authentication.login(url, name: "reservation-replacement", mode: replacementMode)
                replacement = try! Cleanup$Authentication.bytes(url, mode: replacementMode)
                replacementConfig = try! Data(contentsOf: url.appendingPathComponent("config.toml"))
                replacementOwner = DirectoryIdentity.capture(url)
            }
            switch phase {
            case "created": inject()
            case "gate": RecoverySignals.gated = inject
            case "staged": RecoverySignals.staged = inject
            case "absence":
                // Publish after the last lookup has observed an empty destination.
                // An absent source must never reach the native rename operation.
                let key = Fixture.codexKey(url)
                RecoverySignals.absenceRead = { if $0 == key { inject() } }
                RecoverySignals.renaming = { attemptedRename = true }
            default: RecoverySignals.renaming = inject
            }
        }
        var success = false
        do { try store.removeAccount(id: id); success = true } catch { print("Refused: \(error)") }
        RecoverySignals.created = nil
        RecoverySignals.deleted = nil
        RecoverySignals.gated = nil
        RecoverySignals.renaming = nil
        RecoverySignals.absenceRead = nil
        RecoverySignals.staged = nil
        let accounts = Discovery$Real().discover().filter { $0.provider == .codex }
        let visible = accounts.compactMap { account -> Data? in
            guard case .codexHome(let directory) = account.source else { return nil }
            return try? AuthSwap$Codex.authData(columnID: account.id, home: directory)
        }
        let current = recoveryHome.flatMap { try? AuthSwap$Codex.authData(home: $0) }
        let directoryExists = recoveryHome.map { manager.fileExists(atPath: $0.path) } ?? false
        let config = recoveryHome.flatMap { try? String(contentsOf: $0.appendingPathComponent("config.toml")) } ?? "absent"
        print("RESERVATION mode=\(mode) phase=\(phase) replacement=\(replacementMode) reached=\(reached) deleted=\(deleted) success=\(success) originalVisible=\(visible.contains(original)) replacementVisible=\(replacement.map{visible.contains($0)} ?? false) sameLogin=\(current==replacement) directoryExists=\(directoryExists) config=\(config.trimmingCharacters(in: .whitespacesAndNewlines))")
        try expect(try Cleanup$Authentication.bytes(AuthSwap$Codex.baseHome, mode: "file") == native,
                   "reservation changed the native CLI login")
        try expect(reached, "initial recovery preparation boundary not reached")
        if phase == "absence" { try expect(!attemptedRename, "an absent source reached the native rename operation") }
        if replacementMode == "stable" {
            try expect(success && (deleted || mode == "auto-file") && !visible.contains(original), "stable initial reservation failed")
        } else {
            try expect(success || visible.contains(original), "failed reservation lost the original login")
            try expect(replacement != nil && current == replacement && visible.contains(replacement!) && directoryExists,
                       "initial reservation overwrote or deleted a completed independent recovery login")
            try expect(recoveryHome.flatMap { try? Data(contentsOf: $0.appendingPathComponent("config.toml")) } == replacementConfig
                       && recoveryHome.map { replacementOwner?.matches($0) == true } == true,
                       "reservation changed the replacement configuration or physical directory")
            if !success {
                try expect(store.customNames[id] == "Original name" && store.hidden.contains(id),
                           "refused reservation retired original preferences")
            }
        }
    }
}
