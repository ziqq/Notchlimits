private enum PublicationSignals {
    static var attributes: ((String, Bool) -> Void)?
    static var created: ((URL) -> Void)?
}

@main
enum Publication$Authentication {
    private static let manager = Foundation.FileManager.default

    static func main() async {
        do {
            Fixture.keychainExists = false
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            switch parts[0] {
            case "renew": try await renewal(target: parts[1], mode: parts[2], phase: parts[3], change: parts[4])
            case "remove": try removal(mode: parts[1], phase: parts[2], change: parts[3])
            case "claude": try claude(operation: parts[1], phase: parts[2], change: parts[3])
            default: throw Failure(description: "Unknown publication scenario")
            }
        } catch { print("FAIL: \(error)"); exit(1) }
    }

    private static func login(_ home: URL, name: String, mode: String, expired: Bool = false) throws {
        try Fixture.codexLogin(home, account: name, mode: mode == "auto-file" ? "auto" : mode, expired: expired)
        if mode == "auto-file" {
            guard let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home)) else {
                throw Failure(description: "Missing auto file fallback")
            }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }

    private static func bytes(_ home: URL, mode: String) throws -> Data? {
        try AuthStorage$Codex(home: home, mode: .file)
            .load(backend: mode == "file" || mode == "auto-file" ? .file : .keyring)?.data
    }

    private static func setBytes(_ data: Data, home: URL, mode: String) throws {
        if mode == "file" || mode == "auto-file" { try data.write(to: home.appendingPathComponent("auth.json")) }
        else { Fixture.codexKeychain[Fixture.codexKey(home)] = data }
    }

    private static func mutate(_ home: URL, mode: String, change: String, original: Data) throws {
        switch change {
        case "login": try login(home, name: "replacement", mode: mode)
        case "owner", "identical", "retarget":
            try manager.moveItem(at: home, to: home.appendingPathExtension("retired"))
            if change == "retarget" {
                let replacement = Fixture.root.appendingPathComponent("replacement")
                try login(replacement, name: "replacement", mode: mode)
                try manager.createSymbolicLink(at: home, withDestinationURL: replacement)
            } else {
                try login(home, name: "replacement", mode: mode)
                if change == "identical" { try setBytes(original, home: home, mode: mode) }
            }
        case "rotation":
            let root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            let grant = (root["tokens"] as! [String: Any])["refresh_token"] as! String
            let fresh = AuthSwap$Codex.renewedAuth(original, usedRefreshToken: grant,
                tokens: OAuth$Codex.Tokens(idToken: nil,
                    accessToken: Fixture.accessToken(expiresAt: Date().addingTimeInterval(864000).timeIntervalSince1970),
                    refreshToken: "synthetic-independent-rotation"), now: Date())!
            try setBytes(fresh, home: home, mode: mode)
        case "mode": try Fixture.codexMode(home, "ephemeral")
        case "metadata": try Data("preserve-settings".utf8).write(to: home.appendingPathComponent("settings-marker"))
        case "stable", "unreadable": break
        default: throw Failure(description: "Unknown credential mutation")
        }
    }

    private static func renewal(target: String, mode: String, phase: String, change: String) async throws {
        let native = AuthSwap$Codex.baseHome
        let source = ProfileDirectories.codexRoot.appendingPathComponent("source")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("copy")
        try login(native, name: "native", mode: "file")
        let nativeData = try bytes(native, mode: "file")
        try login(source, name: "sleeping", mode: target == "source" ? mode : "file", expired: true)
        let original = try bytes(source, mode: "file")!
        if target == "copy" {
            try Fixture.codexMode(copy, mode == "auto-file" ? "auto" : mode)
            try setBytes(original, home: copy, mode: mode)
        }
        let home = target == "source" ? source : copy
        var reached = false
        var replacement: Data?
        PublicationSignals.attributes = { path, after in
            let file = URL(fileURLWithPath: path)
            guard Fixture.refreshCalls == 1, after == (phase == "after"),
                  file.deletingLastPathComponent().path == home.path,
                  file.lastPathComponent.hasPrefix(".auth-") else { return }
            PublicationSignals.attributes = nil
            reached = true
            try! mutate(home, mode: mode, change: change, original: original)
            replacement = try! bytes(home, mode: mode)
        }
        _ = await Renewal$Codex.shared.renew(columnID: "codex:source", home: source, force: true)
        PublicationSignals.attributes = nil
        let current = try bytes(home, mode: mode)
        let stable = ["stable", "metadata", "mode"].contains(change)
        print("RENEW target=\(target) mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) posts=\(Fixture.refreshCalls)")
        try expect(reached && Fixture.refreshCalls == 1, "Accepted rotation did not reach file preparation")
        if stable {
            try expect(current.flatMap { Renewal$Codex.refreshToken(inFixture: $0) } == "synthetic-rotated",
                       "Stable or pinned-backend renewal lost its accepted rotation")
        } else {
            try expect(current == replacement, "Renewal persistence overwrote a replacement login or file owner")
        }
        if change == "mode" { try Fixture.codexMode(home, mode == "auto-file" ? "auto" : mode) }
        _ = await Renewal$Codex.shared.renew(columnID: "codex:source", home: source, force: false)
        try expect(Fixture.refreshCalls == 1, "Persistence retry replayed the accepted one-use grant")
        if target == "copy" {
            let sourceData = try bytes(source, mode: "file")!
            try expect(Renewal$Codex.refreshToken(inFixture: sourceData) == "synthetic-rotated",
                       "Refused copy persistence lost the source's accepted rotation")
        }
        if !stable { try expect(try bytes(home, mode: mode) == replacement, "A persistence retry overwrote the replacement") }
        if change == "metadata" {
            try expect(manager.fileExists(atPath: home.appendingPathComponent("settings-marker").path),
                       "Renewal removed unrelated settings")
        }
        try expect(try bytes(native, mode: "file") == nativeData, "Sleeping renewal changed native credentials")
        let ready = await Renewal$Codex.shared.prepareForTermination(timeout: 0.02)
        try expect(ready,
                   "A replaced owner or completed rotation stranded normal termination")
    }

    private static func removal(mode: String, phase: String, change: String) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("source")
        try login(home, name: "original", mode: mode)
        let original = try bytes(home, mode: mode)!
        let account = DiscoveredAccount(id: "codex:source", provider: .codex,
            profileName: "source", source: .codexHome(home))
        var reached = false
        var replacement: Data?
        let mutation = { (url: URL) in
            guard url.lastPathComponent.hasPrefix("recovered-") else { return }
            Fixture.beforeDirectoryCreate = nil
            PublicationSignals.created = nil
            reached = true
            try! mutate(home, mode: mode, change: change, original: original)
            replacement = Fixture.codexKeychain[Fixture.codexKey(home)]
        }
        if phase == "before" { Fixture.beforeDirectoryCreate = { mutation($0) } }
        else { PublicationSignals.created = mutation }
        Fixture.denyCodexRead = change == "unreadable"
        var success = false
        do { try AccountRemoval.remove(account); success = true } catch {}
        Fixture.denyCodexRead = false
        let stable = ["stable", "metadata", "unreadable"].contains(change)
        print("REMOVE mode=\(mode) phase=\(phase) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "Removal did not reach recovery preparation")
        if stable {
            try expect(success && Fixture.codexKeychain[Fixture.codexKey(home)] == nil,
                       "Stable or explicitly unreadable namespace removal was refused")
        } else {
            try expect(!success && (try bytes(home, mode: mode)) == replacement,
                       "Removal deleted the credentials or owner created during recovery preparation")
            if change == "mode" { try Fixture.codexMode(home, mode) }
            let retry = DiscoveredAccount(id: account.id, provider: .codex,
                profileName: account.profileName, source: .codexHome(home))
            let retryKey = Fixture.codexKey(home)
            try AccountRemoval.remove(retry)
            try expect(Fixture.codexKeychain[retryKey] == nil,
                       "A refused reservation stranded subsequent explicit removal")
        }
        try expect(Fixture.refreshCalls == 0, "Removal issued a refresh POST")
    }

    private static func replaceLease(_ path: URL) throws {
        try manager.moveItem(at: path, to: path.appendingPathExtension("retired"))
        try manager.createDirectory(at: path, withIntermediateDirectories: false)
    }

    private static func claude(operation: String, phase: String, change: String) throws {
        let directory = Fixture.storageDirectory
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent(".credentials.json")
        let original = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("original", expired: true))
        try original.write(to: file)
        guard let credentials = AuthStorage$Claude.credentials(service: Fixture.service),
              let lease = AuthStorage$Claude.refreshLock(service: Fixture.service, directory: credentials.directory) else {
            throw Failure(description: "Missing file credentials or native renewal lease")
        }
        defer { lease.release() }
        var reached = false
        var replacement = original
        PublicationSignals.attributes = { path, after in
            guard after == (phase == "after"),
                  URL(fileURLWithPath: path).resolvingSymlinksInPath().path == file.resolvingSymlinksInPath().path else { return }
            PublicationSignals.attributes = nil
            reached = true
            switch change {
            case "storage": try! replaceLease(Fixture.storageLock)
            case "oauth":
                try! replaceLease(Fixture.oauthLock)
                try! replaceLease(Fixture.legacyLock)
            case "login":
                for path in [Fixture.storageLock, Fixture.oauthLock, Fixture.legacyLock] { try! replaceLease(path) }
                try! JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false)).write(to: file)
            case "owner", "identical", "retarget":
                try! manager.moveItem(at: directory, to: directory.appendingPathExtension("retired"))
                if change == "retarget" {
                    let fresh = Fixture.root.appendingPathComponent("replacement")
                    try! manager.createDirectory(at: fresh, withIntermediateDirectories: true)
                    try! manager.createSymbolicLink(at: directory, withDestinationURL: fresh)
                } else { try! manager.createDirectory(at: directory, withIntermediateDirectories: true) }
                let data = change == "identical" ? original
                    : try! JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
                try! data.write(to: file)
            case "metadata": try! Data("preserve-settings".utf8).write(to: directory.appendingPathComponent("settings-marker"))
            case "stable": break
            default: preconditionFailure("Unknown lease mutation")
            }
            replacement = try! Data(contentsOf: file)
        }
        let fresh = OAuth$Claude.Tokens(accessToken: "synthetic-new-access", expiresAt: Date().addingTimeInterval(7200),
            refreshToken: "synthetic-rotated", refreshTokenExpiresAt: nil, scopes: nil)
        let success = operation == "preflight"
            ? AuthStorage$Claude.canWrite(service: Fixture.service, renewalLock: lease, expected: credentials)
            : AuthStorage$Claude.save(service: Fixture.service, tokens: fresh, expected: credentials, renewalLock: lease) == .saved
        PublicationSignals.attributes = nil
        let current = try Data(contentsOf: file)
        let stable = change == "stable" || change == "metadata"
        print("CLAUDE operation=\(operation) phase=\(phase) change=\(change) reached=\(reached) success=\(success)")
        try expect(reached, "Claude file publication did not reach its preparation boundary")
        if stable {
            let parsed = AuthStorage$Claude.parse(try JSONSerialization.jsonObject(with: current) as! [String: Any])
            try expect(success && parsed?.accessToken == (operation == "save" ? fresh.accessToken : credentials.accessToken),
                       "Stable file preflight or accepted rotation failed")
            let attributes = try manager.attributesOfItem(atPath: file.path)
            try expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
                       "Published credentials lost private file permissions")
        } else {
            try expect(!success && current == replacement,
                       "Claude file publication wrote after losing its native lease or physical owner")
        }
        try expect(Fixture.refreshCalls == 0, "File persistence or preflight issued a refresh POST")
    }
}

private extension Renewal$Codex {
    static func refreshToken(inFixture data: Data) -> String? {
        let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (root?["tokens"] as? [String: Any])?["refresh_token"] as? String
    }
}
