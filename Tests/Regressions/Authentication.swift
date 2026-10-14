import Foundation
import Security

// Only OS/network boundaries are replaced. Providers, discovery, auth swaps and
// removal are compiled from their unmodified production source files.
private enum Fixture {
    static let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    static let service = "Notchlimits-regression-synthetic"
    static let lock = NSLock()
    static var keychain: [String: Any] = [:]
    static var keychainWrites = 0
    static var failKeychainSave = false
    static var refreshCalls = 0
    static var lastAuthorization = ""

    enum Response { case renewed, lost, temporary, unreadable, delayedLost, changedClaude }
    static var response: Response = .renewed

    static func didRefresh() {
        lock.lock()
        defer { lock.unlock() }
        refreshCalls += 1
    }

    static func accessToken(expiresAt: TimeInterval) -> String {
        let payload = Data("{\"exp\":\(expiresAt)}".utf8).base64EncodedString()
        return "synthetic.\(payload).signature"
    }

    static func writeAuth(_ home: URL, account: String, refresh: String,
                          expired: Bool = true) throws {
        try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let access = accessToken(expiresAt: expired ? 1 : Date().addingTimeInterval(864_000).timeIntervalSince1970)
        let data = try JSONSerialization.data(withJSONObject: [
            "auth_mode": "chatgpt",
            "tokens": ["access_token": access, "account_id": account, "refresh_token": refresh]
        ])
        try data.write(to: home.appendingPathComponent("auth.json"))
    }

    static func claudeLogin(_ name: String, expired: Bool) -> [String: Any] {
        ["claudeAiOauth": [
            "accessToken": "synthetic-\(name)", "refreshToken": "synthetic-refresh-\(name)",
            "expiresAt": expired ? 1 : Date().addingTimeInterval(7_200).timeIntervalSince1970 * 1000,
            "subscriptionType": name
        ], "unknown": "preserved"]
    }

    static func codexAccount(_ name: String) throws -> DiscoveredAccount {
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        try writeAuth(home, account: "synthetic-\(name)", refresh: "synthetic-refresh-\(name)")
        return DiscoveredAccount(id: "codex:\(name)", provider: .codex,
                                 profileName: name, source: .codexHome(home))
    }

    static var claudeAccount: DiscoveredAccount {
        DiscoveredAccount(id: "claude:synthetic", provider: .claude, profileName: "synthetic",
                          source: .claudeKeychain(service: service, configDir: nil),
                          email: "synthetic@example.invalid")
    }
}

private final class FixtureFileManager: Foundation.FileManager, @unchecked Sendable {
    override var homeDirectoryForCurrentUser: URL { Fixture.root }
}

enum FileManager { static let `default`: Foundation.FileManager = FixtureFileManager() }
enum ProcessInfo {
    static let processInfo = FixtureProcessInfo()
    struct FixtureProcessInfo {
        var environment: [String: String] {
            Foundation.ProcessInfo.processInfo.environment.filter { $0.key != "CODEX_HOME" }
        }
    }
}

enum UserDefaults {
    static let standard = MemoryDefaults()
    final class MemoryDefaults {
        private var values: [String: Any] = [:]
        func string(forKey key: String) -> String? { values[key] as? String }
        func dictionary(forKey key: String) -> [String: Any]? { values[key] as? [String: Any] }
        func set(_ value: Any?, forKey key: String) { values[key] = value }
        func removeObject(forKey key: String) { values[key] = nil }
    }
}

enum DesktopApp { static var supportDirectory: URL { Fixture.root.appendingPathComponent("support") } }
struct ClaudeAppSwitcher { func isOpenInApp(columnID: String) -> Bool? { nil } }
protocol AccountDiscovery { func discover() -> [DiscoveredAccount] }
enum BinaryLocator { static func claudeVersion(fallback: String) -> String { fallback }
    static func codex() -> URL? { nil }
    static func version(of binary: URL, fallback: String) -> String { fallback }
}
enum L { static func t(_ key: String, _ arguments: CVarArg...) -> String { key } }
enum Format {
    static func compact(_ value: Double) -> String { String(value) }
    static func money(minor: Double, places: Int, currency: String) -> String { String(minor) }
}

// Swift resolves these local declarations before the imported Security functions.
// No test reads or writes the user's Keychain.
func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    if (query as NSDictionary)[kSecReturnAttributes as String] as? Bool == true {
        result?.pointee = NSArray()
    } else {
        result?.pointee = try! JSONSerialization.data(withJSONObject: Fixture.keychain) as CFData
    }
    return errSecSuccess
}

func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    Fixture.keychainWrites += 1
    if Fixture.failKeychainSave && Fixture.keychainWrites > 1 { return errSecAuthFailed }
    let data = (attributes as NSDictionary)[kSecValueData as String] as! Data
    Fixture.keychain = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    return errSecSuccess
}

func SecItemDelete(_ query: CFDictionary) -> OSStatus { errSecSuccess }
func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus { errSecSuccess }

struct HTTPClient {
    static let shared = HTTPClient()
    struct Response { let status: Int; let data: Data; let retryAfter: TimeInterval? }
    enum Failure: Error { case transport(String) }

    func post(_ url: URL, headers: [String: String], json: [String: Any],
              retry: Bool = true) async -> Result<Response, Failure> {
        Fixture.didRefresh()
        switch Fixture.response {
        case .lost:
            return .failure(.transport("synthetic lost response"))
        case .delayedLost:
            try? await Task.sleep(nanoseconds: 50_000_000)
            return .failure(.transport("synthetic lost response"))
        case .temporary:
            return .success(Response(status: 429, data: Data(), retryAfter: 120))
        case .unreadable:
            return .success(Response(status: 200, data: Data("{}".utf8), retryAfter: nil))
        case .changedClaude:
            Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        case .renewed:
            break
        }
        let access = Fixture.accessToken(expiresAt: Date().addingTimeInterval(864_000).timeIntervalSince1970)
        let data = try! JSONSerialization.data(withJSONObject: [
            "access_token": access, "refresh_token": "synthetic-rotated", "expires_in": 3_600
        ])
        return .success(Response(status: 200, data: data, retryAfter: nil))
    }

    func get(_ url: URL, headers: [String: String]) async -> Result<Response, Failure> {
        Fixture.lastAuthorization = headers["Authorization"] ?? ""
        let data = Data(#"{"five_hour":{"utilization":12},"rate_limit":{"primary_window":{"used_percent":12,"limit_window_seconds":18000}}}"#.utf8)
        return .success(Response(status: 200, data: data, retryAfter: nil))
    }
}

private struct Failure: Error, CustomStringConvertible { let description: String }
private func expect(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(description: message) }
}

@main
enum Authentication {
    static func main() async {
        do {
            switch CommandLine.arguments[1] {
            case "profile-identity": try profileIdentity()
            case "lost-response": try await lostResponse()
            case "failed-save": try await failedSave()
            case "temporary-response": try await temporaryResponse()
            case "unreadable-response": try await unreadableResponse()
            case "concurrent-refresh": try await concurrentRefresh()
            case "claude-login-changed": try await claudeLoginChanged()
            case "claude-pending-changed": try await claudePendingChanged()
            default: throw Failure(description: "Unknown scenario")
            }
            print("PASS: \(CommandLine.arguments[1])")
        } catch {
            FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func profileIdentity() throws {
        let main = CodexAuthSwap.baseHome
        let extra = ProfileDirectories.codexRoot.appendingPathComponent("default")
        try Fixture.writeAuth(main, account: "synthetic-main", refresh: "main-refresh")
        try Fixture.writeAuth(extra, account: "synthetic-extra", refresh: "extra-refresh")
        let accounts = RealDiscovery().discover()
        try expect(accounts.count == 2, "Expected both Codex accounts")
        try expect(Set(accounts.map(\.id)).count == 2, "Main and default profile share one ID")
        try expect(accounts.filter(\.isActive).count == 1, "Two accounts marked active")
        let profile = accounts.first { $0.profileName == "default" }!
        try CodexAuthSwap.activate(columnID: profile.id, home: extra)
        try expect(CodexProvider.readAuth(codexHome: main)?.accountID == "synthetic-extra", "Wrong account activated")
        try CodexAuthSwap.restoreDefault()
        try expect(CodexProvider.readAuth(codexHome: main)?.accountID == "synthetic-main", "Main sign-in not restored")
        try AccountRemoval.remove(profile)
        try expect(Foundation.FileManager.default.fileExists(atPath: main.appendingPathComponent("auth.json").path),
                   "Removing default profile removed main sign-in")
        try expect(!Foundation.FileManager.default.fileExists(atPath: extra.path),
                   "Profile not removed: source=\(profile.source), root=\(ProfileDirectories.codexRoot.path), folder=\(extra.path)")
    }

    private static func lostResponse() async throws {
        let account = try Fixture.codexAccount("lost")
        Fixture.response = .lost
        _ = await CodexProvider().fetch(account)
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Lost response reused refresh token: \(Fixture.refreshCalls) POSTs")
    }

    private static func failedSave() async throws {
        let account = try Fixture.codexAccount("save")
        guard case .codexHome(let home) = account.source else { return }
        try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: home.path)
        defer { try? Foundation.FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path) }
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Write failure reused refresh token: \(Fixture.refreshCalls) POSTs")
        try expect(CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-refresh-save",
                   "Fixture did not produce a real write failure")
        try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
        let outcome = await CodexProvider().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Pending tokens not recovered after restoring write access") }
        try expect(Fixture.refreshCalls == 1, "Saving pending tokens made another refresh request")
        try expect(CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated",
                   "Rotated tokens were lost")
    }

    private static func temporaryResponse() async throws {
        let account = try Fixture.codexAccount("temporary")
        Fixture.response = .temporary
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Temporary response retried in the same fetch")
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 2, "Explicit temporary response blocked later renewal")
    }

    private static func unreadableResponse() async throws {
        let account = try Fixture.codexAccount("unreadable")
        Fixture.response = .unreadable
        _ = await CodexProvider().fetch(account)
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Unreadable success response reused refresh token")
    }

    private static func concurrentRefresh() async throws {
        let account = try Fixture.codexAccount("concurrent")
        Fixture.response = .delayedLost
        async let first = CodexProvider().fetch(account)
        async let second = CodexProvider().fetch(account)
        _ = await (first, second)
        try expect(Fixture.refreshCalls == 1, "Concurrent fetches reused refresh token: \(Fixture.refreshCalls) POSTs")
    }

    private static func claudeLoginChanged() async throws {
        let old = Fixture.claudeLogin("old-login", expired: true)
        let expected = ClaudeKeychain.parse(old)!
        let fresh = ClaudeOAuth.Tokens(accessToken: "synthetic-stale", expiresAt: Date().addingTimeInterval(3_600),
                                       refreshToken: "synthetic-stale-refresh", refreshTokenExpiresAt: nil, scopes: nil)
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        #if LEGACY_CLAUDE_SAVE
        _ = ClaudeKeychain.save(service: Fixture.service, tokens: fresh)
        #else
        _ = ClaudeKeychain.save(service: Fixture.service, tokens: fresh, expected: expected)
        #endif
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Stale refresh response overwrote newer Keychain login")

        Fixture.keychain = old
        Fixture.response = .changedClaude
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if case .success = outcome {} else { throw Failure(description: "New CLI login not used for usage") }
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Stale response cached after CLI login")
        try expect(Fixture.keychain["unknown"] as? String == "preserved", "Unrelated Keychain fields lost")
    }

    private static func claudePendingChanged() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.failKeychainSave = true
        let provider = ClaudeProvider()
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.keychainWrites > 1, "Fixture did not attempt to save rotated tokens")
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        Fixture.failKeychainSave = false
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 1, "Pending save made another refresh request")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Pending save replaced newer CLI login")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Old cached tokens survived CLI login")
    }
}
