import Foundation
import Combine
import AppKit
import Security
import Darwin
import CryptoKit

// Only OS/network boundaries are replaced. Providers, discovery, auth swaps and
// removal are compiled from their unmodified production source files.
private enum Fixture {
    static let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    static let service = "Claude Code-credentials"
    static let lock = NSLock()
    static var keychain: [String: Any] = [:]
    static var keychainWrites = 0
    static var codexKeychain: [String: Data] = [:]
    static var denyCodexRead = false
    static var denyCodexWrite = false
    static var denyCodexDelete = false
    static var denyCredentialFileRemoval = false
    static var codexSecretReads = 0
    static var distinctRefreshGrants = false
    static var failClaudeFileWrite = false
    static var claudeFileWriteFailures = 0
    static var managedCodex: [String: String] = [:]
    static var failKeychainSave = false
    static var refreshCalls = 0
    static var lastAuthorization = ""
    static var cliVersion = "2.1.278"
    static var shell = "/bin/zsh"
    static var keychainReads = 0
    static var changeLoginAfterRead = 0
    static var pendingCLILogin = false
    static var replaceLockAfterRead = 0
    static var slowKeychainRead = false
    static var expectedLock: URL?
    static var observedProfileLock = false
    static var oauthDirectory: URL { expectedOAuthDirectory ?? storageDirectory }
    static var expectedOAuthDirectory: URL?
    static var oauthHeldDuringPOST = false
    static var oauthHeldDuringWrite = true
    static var nativeLoginPending = false
    static var noninteractiveWrites = true
    static var interactionAllowed = true
    static var denyNoninteractiveWrite = false
    static var allowHTTPRetry = false
    static var usageStatus = 200
    static var replaceOAuthDuringPOST = false
    static var loginBeforeOAuth = false
    static var refreshInput = ""
    static var loginAtWriteBoundary = false
    static var cliClearedRevokedGrant = false
    static var desktopFails = false
    static var holdDesktopCompletion = false
    static var desktopCalls = 0
    static var desktopArguments: [String] = []
    static var keychainExists = true
    static var denyKeychainDelete = false
    static var discoveredClaudeService: String?
    static var releaseRefreshReply = false
    static var holdFirstUsage = false
    static var usageCalls = 0
    static var usageCompletions = 0
    static var releaseFirstUsage = false
    static var pauseProfileSnapshot = false
    static var profileSnapshotPaused = false
    static var resumeProfileSnapshot = false
    static var lockCrashPhase = ""
    static var nativeAcquisitionAtPublish = false
    static var nativeAcquisitionObserved = false
    static var replaceMarkedOwnerAfterRead = false
    static var markedOwnerReplacementObserved = false
    @MainActor static var desktopCompletion: ((Result<Void, Error>) -> Void)?

    static func writes() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return keychainWrites
    }

    static func releaseRefresh() {
        lock.lock()
        releaseRefreshReply = true
        lock.unlock()
    }

    static func refreshIsPaused() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return !releaseRefreshReply
    }

    static func tryNativeRefresh() {
        guard mkdir(oauthLock.path, 0o700) == 0 else { return }
        defer { _ = rmdir(oauthLock.path) }
        guard mkdir(legacyLock.path, 0o700) == 0 else { return }
        defer { _ = rmdir(legacyLock.path) }
        guard mkdir(storageLock.path, 0o700) == 0 else { return }
        defer { _ = rmdir(storageLock.path) }
        if ClaudeKeychain.parse(keychain)?.refreshToken == "synthetic-refresh-old-login" {
            // Model native eRn after invalid_grant for the already rotated grant.
            keychain["claudeAiOauth"] = ["accessToken": "", "refreshToken": "", "expiresAt": 0]
            cliClearedRevokedGrant = true
        }
    }

    static var oauthLock: URL { oauthDirectory.appendingPathComponent(".oauth_refresh.lock") }
    static var legacyLock: URL { URL(fileURLWithPath: oauthDirectory.resolvingSymlinksInPath().path + ".lock") }
    static var holdsOAuthLocks: Bool {
        Foundation.FileManager.default.fileExists(atPath: oauthLock.path)
            && Foundation.FileManager.default.fileExists(atPath: legacyLock.path)
    }

    // Model native CLI login/refresh: acquire both OAuth locks before storage.
    static func tryNativeLogin(stealStaleStorage: Bool = false) {
        guard mkdir(oauthLock.path, 0o700) == 0 else { nativeLoginPending = true; return }
        defer { _ = rmdir(oauthLock.path) }
        guard mkdir(legacyLock.path, 0o700) == 0 else { nativeLoginPending = true; return }
        defer { _ = rmdir(legacyLock.path) }
        if stealStaleStorage,
           let attributes = try? Foundation.FileManager.default.attributesOfItem(atPath: storageLock.path),
           let modified = attributes[.modificationDate] as? Date, modified.timeIntervalSinceNow < -15 {
            _ = rmdir(storageLock.path)
        }
        guard mkdir(storageLock.path, 0o700) == 0 else { nativeLoginPending = true; return }
        defer { _ = rmdir(storageLock.path) }
        keychain = claudeLogin("new-login", expired: false)
        nativeLoginPending = false
    }

    static var storageDirectory: URL { root.appendingPathComponent(".claude") }
    static var storageLock: URL { storageDirectory.appendingPathComponent(".storage-write.lock") }

    // The CLI's independent writer uses its native mkdir lock protocol.
    static func tryCLILogin() {
        if mkdir(storageLock.path, 0o700) == 0 {
            keychain = claudeLogin("new-login", expired: false)
            pendingCLILogin = false
            _ = rmdir(storageLock.path)
        } else {
            pendingCLILogin = true
        }
    }

    enum Response { case renewed, lost, temporary, unreadable, delayedLost, changedClaude, nativeLogin, forbidden, delayedRenewed, slowRenewed, heldRenewed }
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

    static func codexKey(_ home: URL) -> String {
        let hash = SHA256.hash(data: Data(home.resolvingSymlinksInPath().path.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return "cli|" + hash.prefix(16)
    }

    static func codexMode(_ home: URL, _ mode: String) throws {
        try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(("cli_auth_credentials_store = \"" + mode + "\"\n").utf8)
            .write(to: home.appendingPathComponent("config.toml"))
    }

    static func codexLogin(_ home: URL, account: String, mode: String, expired: Bool = false) throws {
        try writeAuth(home, account: account, refresh: "synthetic-refresh-" + account, expired: expired)
        try codexMode(home, mode)
        if mode != "file" {
            let file = home.appendingPathComponent("auth.json")
            codexKeychain[codexKey(home)] = try Data(contentsOf: file)
            try Foundation.FileManager.default.removeItem(at: file)
        }
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

// Faults are injected at OS boundaries in separate fixture processes.
private func crashAtLockBoundary(_ phase: String) -> Never {
    FileHandle.standardOutput.write(Data("FAULT:\(phase)\n".utf8))
    _exit(86)
}

func mkdir(_ path: UnsafePointer<CChar>, _ mode: mode_t) -> Int32 {
    let value = String(cString: path)
    if Fixture.nativeAcquisitionAtPublish && value == Fixture.oauthLock.path {
        Fixture.nativeAcquisitionAtPublish = false
        Fixture.nativeAcquisitionObserved = Darwin.mkdir(path, mode) == 0
    }
    let result = Darwin.mkdir(path, mode)
    if result == 0 && Fixture.lockCrashPhase == "mkdir" { crashAtLockBoundary("mkdir") }
    return result
}

func pwrite(_ fd: Int32, _ bytes: UnsafeRawPointer?, _ count: Int, _ offset: off_t) -> Int {
    if Fixture.lockCrashPhase == "record" {
        _ = Darwin.pwrite(fd, bytes, count / 2, offset)
        crashAtLockBoundary("record")
    }
    return Darwin.pwrite(fd, bytes, count, offset)
}

private func replaceMarkedOwnerAfterRead(_ path: String) {
    guard Fixture.replaceMarkedOwnerAfterRead, path == Fixture.oauthLock.path else { return }
    Fixture.replaceMarkedOwnerAfterRead = false
    // A native contender reaps the abandoned directories and owns fresh unmarked ones.
    let current = path.withCString { Darwin.rmdir($0) == 0 && Darwin.mkdir($0, 0o700) == 0 }
    let legacy = Fixture.legacyLock.path.withCString { Darwin.rmdir($0) == 0 && Darwin.mkdir($0, 0o700) == 0 }
    Fixture.markedOwnerReplacementObserved = current && legacy
}

func getxattr(_ path: UnsafePointer<CChar>, _ name: UnsafePointer<CChar>, _ value: UnsafeMutableRawPointer?,
              _ count: Int, _ position: UInt32, _ options: Int32) -> Int {
    let result = Darwin.getxattr(path, name, value, count, position, options)
    if result > 0 { replaceMarkedOwnerAfterRead(String(cString: path)) }
    return result
}

func fgetxattr(_ fd: Int32, _ name: UnsafePointer<CChar>, _ value: UnsafeMutableRawPointer?,
               _ count: Int, _ position: UInt32, _ options: Int32) -> Int {
    let result = Darwin.fgetxattr(fd, name, value, count, position, options)
    var opened = stat(), named = stat()
    if result > 0, fstat(fd, &opened) == 0,
       Fixture.oauthLock.path.withCString({ Darwin.lstat($0, &named) }) == 0,
       opened.st_dev == named.st_dev, opened.st_ino == named.st_ino {
        replaceMarkedOwnerAfterRead(Fixture.oauthLock.path)
    }
    return result
}

func fsetxattr(_ fd: Int32, _ name: UnsafePointer<CChar>, _ value: UnsafeRawPointer?,
               _ count: Int, _ position: UInt32, _ options: Int32) -> Int32 {
    let result = Darwin.fsetxattr(fd, name, value, count, position, options)
    if result == 0 && Fixture.lockCrashPhase == "record" { crashAtLockBoundary("record") }
    return result
}

func renameatx_np(_ fromFD: Int32, _ from: UnsafePointer<CChar>, _ toFD: Int32,
                  _ to: UnsafePointer<CChar>, _ flags: UInt32) -> Int32 {
    if Fixture.nativeAcquisitionAtPublish && String(cString: to) == Fixture.oauthLock.path {
        Fixture.nativeAcquisitionAtPublish = false
        Fixture.nativeAcquisitionObserved = Darwin.mkdir(to, 0o700) == 0
    }
    return Darwin.renameatx_np(fromFD, from, toFD, to, flags)
}

private final class FixtureFileManager: Foundation.FileManager, @unchecked Sendable {
    override var homeDirectoryForCurrentUser: URL { Fixture.root }

    override func removeItem(at url: URL) throws {
        if Fixture.denyCredentialFileRemoval && ["auth.json", ".credentials.json"].contains(url.lastPathComponent) {
            throw CocoaError(.fileWriteNoPermission)
        }
        try super.removeItem(at: url)
    }


    override func setAttributes(_ attributes: [FileAttributeKey: Any], ofItemAtPath path: String) throws {
        if path.hasSuffix("/.credentials.json"), Fixture.failClaudeFileWrite, Fixture.refreshCalls > 0 {
            Fixture.lock.lock()
            Fixture.claudeFileWriteFailures += 1
            Fixture.lock.unlock()
            throw CocoaError(.fileWriteNoPermission)
        }
        try super.setAttributes(attributes, ofItemAtPath: path)
    }


    private func configPath(_ path: String) -> String {
        path.hasPrefix("/etc/codex/") ? Fixture.root.path + "/system/" + URL(fileURLWithPath: path).lastPathComponent : path
    }
    override func fileExists(atPath path: String) -> Bool { super.fileExists(atPath: configPath(path)) }
    override func contents(atPath path: String) -> Data? { super.contents(atPath: configPath(path)) }


    override func contentsOfDirectory(at url: URL, includingPropertiesForKeys keys: [URLResourceKey]?,
                                      options mask: DirectoryEnumerationOptions = []) throws -> [URL] {
        var entries = try super.contentsOfDirectory(at: url, includingPropertiesForKeys: keys, options: mask)
        Fixture.lock.lock()
        let pause = Fixture.pauseProfileSnapshot && url.path == ProfileDirectories.claudeRoot.resolvingSymlinksInPath().path
        if pause { Fixture.pauseProfileSnapshot = false }
        Fixture.lock.unlock()
        guard pause else { return entries }
        // Preserve the directory metadata already observed by this enumeration.
        // Removal happens after resolution starts but before storage lock I/O.
        for index in entries.indices {
            let isDirectory = try entries[index].resourceValues(forKeys: [.isDirectoryKey]).isDirectory
            entries[index].setTemporaryResourceValue(isDirectory, forKey: .isDirectoryKey)
        }
        Fixture.lock.lock()
        Fixture.profileSnapshotPaused = true
        Fixture.lock.unlock()
        while true {
            Fixture.lock.lock()
            let resume = Fixture.resumeProfileSnapshot
            Fixture.lock.unlock()
            if resume { break }
            Thread.sleep(forTimeInterval: 0.005)
        }
        return entries
    }
}

enum FileManager { static let `default`: Foundation.FileManager = FixtureFileManager() }
enum ProcessInfo {
    static let processInfo = FixtureProcessInfo()
    struct FixtureProcessInfo {
        var environment: [String: String] {
            Foundation.ProcessInfo.processInfo.environment.filter {
                !["CODEX_HOME", "ZDOTDIR"].contains($0.key)
            }.merging(["SHELL": Fixture.shell]) { _, fixture in fixture }
        }
    }
}

final class UserDefaults {
    static let standard = UserDefaults()
    private var values: [String: Any] = [:]
    func object(forKey key: String) -> Any? { values[key] }
    func string(forKey key: String) -> String? { values[key] as? String }
    func stringArray(forKey key: String) -> [String]? { values[key] as? [String] }
    func dictionary(forKey key: String) -> [String: Any]? { values[key] as? [String: Any] }
    func data(forKey key: String) -> Data? { values[key] as? Data }
    func bool(forKey key: String) -> Bool { values[key] as? Bool ?? false }
    func persistentDomain(forName name: String) -> [String: Any]? { nil }
    func set(_ value: Any?, forKey key: String) { values[key] = value }
    func removeObject(forKey key: String) { values[key] = nil }
}

// History and notification delivery do not participate in settings migration.
struct UsageHistory {
    func purge(columnID: String) {}
    func record(columnID: String, window: LimitWindow, now: Date) -> [Double] { [] }
    static func projection(samples: [Double], current: Double, resetsAt: Date?, now: Date) -> Date? { nil }
}
struct ThresholdNotifier {
    func purge(columnID: String) {}
    func evaluate(column: AccountColumn) {}
}

enum DesktopApp {
    static var supportDirectory: URL { Fixture.root.appendingPathComponent("support") }
    static func url(bundleID: String) -> URL? { nil }
    @MainActor static func restart(bundleID: String, appName: String,
                                 prepare: () throws -> NSWorkspace.OpenConfiguration,
                                 completion: @escaping (Result<Void, Error>) -> Void) {
        Fixture.desktopCalls += 1
        do {
            Fixture.desktopArguments = try prepare().arguments
            if Fixture.holdDesktopCompletion {
                Fixture.desktopCompletion = completion
            } else {
                completion(Fixture.desktopFails ? .failure(Failure(description: "Synthetic Desktop launch failure")) : .success(()))
            }
        } catch { completion(.failure(error)) }
    }
}
protocol AccountDiscovery { func discover() -> [DiscoveredAccount] }
enum BinaryLocator { static func claudeVersion(fallback: String) -> String { Fixture.cliVersion }
    static func codex() -> URL? { nil }
    static func version(of binary: URL, fallback: String) -> String { fallback }
}
enum L { static func t(_ key: String, _ arguments: CVarArg...) -> String { key } }
enum Format {
    static func compact(_ value: Double) -> String { String(value) }
    static func money(minor: Double, places: Int, currency: String) -> String { String(minor) }
}

func CFPreferencesAppValueIsForced(_ key: CFString, _ applicationID: CFString) -> Bool {
    Fixture.managedCodex[key as String] != nil
}
func CFPreferencesCopyAppValue(_ key: CFString, _ applicationID: CFString) -> CFPropertyList? {
    Fixture.managedCodex[key as String].map { $0 as CFString }
}

// Swift resolves these local declarations before the imported Security functions.
// No test reads or writes the user's Keychain.
func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String
        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }
        if (query as NSDictionary)[kSecReturnData as String] as? Bool == true {
            Fixture.codexSecretReads += 1
            guard !Fixture.denyCodexRead else { return errSecInteractionNotAllowed }
            result?.pointee = data as CFData
        } else {
            result?.pointee = [kSecAttrService as String: "Codex Auth", kSecAttrAccount as String: key] as NSDictionary
        }
        return errSecSuccess
    }
    if (query as NSDictionary)[kSecReturnAttributes as String] as? Bool == true {
        if let service = (query as NSDictionary)[kSecAttrService as String] as? String {
            guard Fixture.keychainExists else { return errSecItemNotFound }
            result?.pointee = [kSecAttrService as String: service] as NSDictionary
            return errSecSuccess
        }
        if Fixture.keychainExists, let service = Fixture.discoveredClaudeService {
            result?.pointee = [[kSecAttrService as String: service]] as NSArray
        } else { result?.pointee = NSArray() }
    } else {
        guard Fixture.keychainExists else { return errSecItemNotFound }
        let data = try! JSONSerialization.data(withJSONObject: Fixture.keychain)
        Fixture.keychainReads += 1
        if Fixture.slowKeychainRead { Thread.sleep(forTimeInterval: 6.5) }
        if Fixture.keychainReads == Fixture.changeLoginAfterRead { Fixture.tryCLILogin() }
        if Fixture.keychainReads == Fixture.replaceLockAfterRead {
            let path = Fixture.storageLock.path
            _ = rename(path, path + ".previous-owner")
            _ = mkdir(path, 0o700)
        }
        if Fixture.loginBeforeOAuth && Fixture.keychainReads == 1 { Fixture.tryNativeLogin() }
        result?.pointee = data as CFData
    }
    return errSecSuccess
}

func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String
        guard Fixture.codexKeychain[key] != nil else { return errSecItemNotFound }
        guard !Fixture.denyCodexWrite else { return errSecAuthFailed }
        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data
        return errSecSuccess
    }
    Fixture.keychainWrites += 1
    guard Fixture.keychainExists else { return errSecItemNotFound }
    Fixture.oauthHeldDuringWrite = Fixture.oauthHeldDuringWrite && Fixture.holdsOAuthLocks
    Fixture.noninteractiveWrites = Fixture.noninteractiveWrites && !Fixture.interactionAllowed
    if Fixture.denyNoninteractiveWrite && !Fixture.interactionAllowed { return errSecInteractionNotAllowed }
    if let expected = Fixture.expectedLock {
        Fixture.observedProfileLock = Foundation.FileManager.default.fileExists(atPath: expected.path)
    }
    if Fixture.failKeychainSave && Fixture.keychainWrites > 1 { return errSecAuthFailed }
    if Fixture.loginAtWriteBoundary && Fixture.keychainWrites == 2 {
        // Model a storage lease that expired after the final ownership check.
        try! Foundation.FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-16)],
                                                          ofItemAtPath: Fixture.storageLock.path)
        Fixture.tryNativeLogin(stealStaleStorage: true)
    }
    let data = (attributes as NSDictionary)[kSecValueData as String] as! Data
    Fixture.keychain = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    return errSecSuccess
}

func SecKeychainGetUserInteractionAllowed(_ state: UnsafeMutablePointer<DarwinBoolean>) -> OSStatus {
    state.pointee = DarwinBoolean(Fixture.interactionAllowed)
    return errSecSuccess
}

func SecKeychainSetUserInteractionAllowed(_ state: Bool) -> OSStatus {
    Fixture.interactionAllowed = state
    return errSecSuccess
}

func SecItemDelete(_ query: CFDictionary) -> OSStatus {
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        guard !Fixture.denyCodexDelete else { return errSecAuthFailed }
        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String
        Fixture.codexKeychain[key] = nil
        return errSecSuccess
    }
    guard !Fixture.denyKeychainDelete else { return errSecAuthFailed }
    Fixture.keychainExists = false
    return errSecSuccess
}
func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    if (attributes as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        guard !Fixture.denyCodexWrite else { return errSecAuthFailed }
        let key = (attributes as NSDictionary)[kSecAttrAccount as String] as! String
        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data
    }
    return errSecSuccess
}

struct HTTPClient {
    static let shared = HTTPClient()
    struct Response { let status: Int; let data: Data; let retryAfter: TimeInterval? }
    enum Failure: Error { case transport(String) }

    func post(_ url: URL, headers: [String: String], json: [String: Any],
              retry: Bool = true) async -> Result<Response, Failure> {
        Fixture.didRefresh()
        Fixture.allowHTTPRetry = retry
        Fixture.refreshInput = json["refresh_token"] as? String ?? ""
        Fixture.oauthHeldDuringPOST = Fixture.holdsOAuthLocks
        if Fixture.replaceOAuthDuringPOST {
            let path = Fixture.oauthLock.path
            _ = rename(path, path + ".previous-owner")
            _ = mkdir(path, 0o700)
        }
        if Fixture.pendingCLILogin { Fixture.tryCLILogin() }
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
        case .forbidden:
            return .success(Response(status: 403, data: Data("{\"error\":\"region_blocked\"}".utf8), retryAfter: nil))
        case .nativeLogin:
            Fixture.tryNativeLogin()
        case .slowRenewed:
            try? await Task.sleep(nanoseconds: 6_500_000_000)
        case .delayedRenewed:
            try? await Task.sleep(nanoseconds: 100_000_000)
        case .heldRenewed:
            while Fixture.refreshIsPaused() { try? await Task.sleep(nanoseconds: 10_000_000) }
        case .renewed:
            break
        }
        let access = Fixture.accessToken(expiresAt: Date().addingTimeInterval(864_000).timeIntervalSince1970)
        let data = try! JSONSerialization.data(withJSONObject: [
            "access_token": access, "refresh_token": Fixture.distinctRefreshGrants ? "synthetic-rotated-" + (json["refresh_token"] as! String) : "synthetic-rotated", "expires_in": 3_600
        ])
        return .success(Response(status: 200, data: data, retryAfter: nil))
    }

    func get(_ url: URL, headers: [String: String]) async -> Result<Response, Failure> {
        Fixture.lock.lock()
        Fixture.usageCalls += 1
        let first = Fixture.usageCalls == 1
        let hold = Fixture.holdFirstUsage && first
        Fixture.lock.unlock()
        if hold {
            while true {
                Fixture.lock.lock()
                let release = Fixture.releaseFirstUsage
                Fixture.lock.unlock()
                if release { break }
                try? await Task.sleep(nanoseconds: 5_000_000)
            }
        }
        if Fixture.holdFirstUsage {
            let data = try! JSONSerialization.data(withJSONObject: ["five_hour": ["utilization": first ? 12 : 84]])
            Fixture.lock.lock()
            Fixture.usageCompletions += 1
            Fixture.lock.unlock()
            return .success(Response(status: 200, data: data, retryAfter: nil))
        }
        Fixture.lastAuthorization = headers["Authorization"] ?? ""
        let data = Data(#"{"five_hour":{"utilization":12},"rate_limit":{"primary_window":{"used_percent":12,"limit_window_seconds":18000}}}"#.utf8)
        return .success(Response(status: Fixture.usageStatus, data: data, retryAfter: nil))
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
            case "codex-store-keyring": try codexStoreRead("keyring")
            case "codex-store-auto": try codexStoreRead("auto")
            case "codex-store-file": try codexStoreRead("file")
            case "codex-store-auto-missing": try codexStoreRead("auto", missing: true)
            case "codex-store-auto-denied": try codexStoreRead("auto", denied: true)
            case "codex-store-keyring-denied": try codexStoreRead("keyring", denied: true)
            case "codex-store-ephemeral": try codexStoreRead("ephemeral")
            case "codex-store-invalid": try codexStoreRead("unknown")
            case "codex-store-discovery": try codexStoreDiscovery()
            case "codex-store-symlink": try codexStoreDiscovery(symlink: true)
            case "codex-store-auto-switch": try codexStoreSwitch(baseMode: "auto", profileMode: "auto")
            case "codex-store-auto-fallback-switch": try codexStoreSwitch(baseMode: "auto", profileMode: "file", fallback: true)
            case "codex-store-ephemeral-current": try codexStoreEphemeralSwitch(alreadyActive: true)
            case "codex-store-encrypted": try codexStoreEncryptedBackend()
            case "codex-store-switch": try codexStoreSwitch()
            case "codex-store-switch-incoming-keyring": try codexStoreSwitch(baseMode: "file")
            case "codex-store-switch-incoming-file": try codexStoreSwitch(profileMode: "file")
            case "codex-store-auto-renewal": try await codexStoreRenewal(mode: "auto")
            case "codex-store-auto-renewal-denied": try await codexStoreRenewal(mode: "auto", denied: true)
            case "codex-store-renewal": try await codexStoreRenewal()
            case "codex-store-renewal-denied": try await codexStoreRenewal(denied: true)
            case "codex-store-remove": try codexStoreRemove()
            case "codex-store-remove-denied": try codexStoreRemove(denied: true)
            case "codex-store-root-settings": try codexStoreSettings()
            case "codex-store-system-requirements": try codexStoreSettings(requirements: true)
            case "codex-store-managed-requirements": try codexStoreSettings(managed: true)
            case "codex-store-ephemeral-switch": try codexStoreEphemeralSwitch()
            case "codex-auto-source-loss": try await codexAutoSourceLoss()
            case "codex-readd-pending-loss": try await codexReaddPendingLoss()
            case "codex-switch-inflight": try await codexSwitchInFlight()
            case "claude-file-discovery": try await claudeFileDiscovery()
            case "claude-file-removal": try claudeFileRemoval()
            case "codex-toml-mode": try codexTOMLMode()
            case "codex-toml-backend": try codexTOMLBackend()
            case "codex-auto-source-no-fallback": try await codexAutoSourceLoss(fallback: false)
            case "codex-auto-file-source": try await codexAutoFileSource()
            case "codex-switch-inflight-file": try await codexSwitchInFlight(mode: "file")
            case "codex-switch-pending": try await codexSwitchPending()
            case "codex-remove-denied-pending": try await codexSwitchPending(deniedRemoval: true)
            case "claude-file-lifecycle-main": try await claudeFileLifecycle(primary: true)
            case "claude-file-lifecycle-profile": try await claudeFileLifecycle(primary: false)
            case "claude-file-lifecycle-off": try await claudeFileLifecycle(primary: false, switchCLI: false)
            case "claude-file-save-recovery": try await claudeFileLifecycle(primary: false, failSave: true)
            case "claude-file-lock-busy": try await claudeFileLockBusy()
            case "claude-file-relogin": try await claudeFileRelogin()
            case "codex-toml-forms": try codexTOMLForms()
            case "codex-switch-inflight-alias": try await codexSwitchInFlight(alias: true)
            case "codex-renewal-base-alias": try await codexBaseAlias()
            case "claude-remove-fallback-denied-keychain": try fallbackRemovalDenied(codex: false, keychainDenied: true)
            case "claude-remove-fallback-denied-file": try fallbackRemovalDenied(codex: false, keychainDenied: false)
            case "codex-remove-fallback-denied-keychain": try fallbackRemovalDenied(codex: true, keychainDenied: true)
            case "codex-remove-fallback-denied-file": try fallbackRemovalDenied(codex: true, keychainDenied: false)
            case "profile-identity": try profileIdentity()
            case "profile-collision": try profileCollision()
            case "profile-active-migration": try profileActiveMigration()
            case "profile-settings-migration": try profileSettingsMigration()
            case "profile-settings-existing": try profileSettingsExisting()
            case "profile-settings-collision": try profileSettingsCollision()
            case "profile-settings-nested": try profileSettingsNested()
            case "lost-response": try await lostResponse()
            case "failed-save": try await failedSave()
            case "temporary-response": try await temporaryResponse()
            case "unreadable-response": try await unreadableResponse()
            case "concurrent-refresh": try await concurrentRefresh()
            case "claude-login-changed": try await claudeLoginChanged()
            case "claude-pending-changed": try await claudePendingChanged()
            case "claude-preflight-race": try await claudeWriteRace(afterRead: 2)
            case "claude-save-race": try await claudeWriteRace(afterRead: 3)
            case "claude-lock-busy": try claudeLockBusy(stale: false)
            case "claude-lock-stale": try claudeLockBusy(stale: true)
            case "claude-lock-lost": try claudeLockLost()
            case "claude-lock-heartbeat": try await claudeLockHeartbeat()
            case "claude-profile-lock": try claudeProfileLock()
            case "claude-unsupported-cli": try await claudeUnsupportedCLI()
            case "claude-native-login": try await claudeNativeLogin()
            case "claude-write-boundary": try await claudeNativeLogin(writeBoundary: true)
            case "claude-oauth-heartbeat": try await claudeOAuthHeartbeat()
            case "claude-no-write-permission": try await claudeNoWritePermission()
            case "claude-oauth-busy": try await claudeOAuthBusy(legacy: false)
            case "claude-legacy-busy": try await claudeOAuthBusy(legacy: true)
            case "claude-oauth-reread": try await claudeOAuthReread()
            case "claude-concurrent-refresh": try await claudeConcurrentRefresh()
            case "claude-oauth-lost": try await claudeOAuthLost()
            case "claude-cache-login": try await claudeCacheLogin()
            case "claude-network-recovery": try await claudeNetworkRecovery()
            case "claude-refresh-no-retry": try await claudeRefreshNoRetry()
            case "claude-refresh-forbidden": try await claudeRefreshForbidden()
            case "claude-usage-forbidden": try await claudeUsageForbidden()
            case "claude-oauth-profile": try await claudeOAuthProfile()
            case "claude-switch-default": try claudeSwitchCLI(enabled: nil)
            case "claude-switch-off": try claudeSwitchCLI(enabled: false)
            case "claude-switch-main": try claudeSwitchCLI(enabled: true, primary: true)
            case "claude-switch-bash": try claudeSwitchBash()
            case "claude-persist-before-unlock": try await claudePersistBeforeUnlock()
            case "claude-quit-pending": try await claudeQuitPending()
            case "claude-quit-inflight": try await claudeQuitInFlight()
            case "claude-switch-trailing-path": try claudeExactPath(symlink: false)
            case "claude-switch-resolved-path": try claudeExactPath(symlink: true)
            case "claude-switch-aliased-path": try claudeExactPath(symlink: true, resolved: false)
            case "claude-switch-short-hash": try claudeRejectShortHash()
            case "claude-launch-failed": try claudeLaunchFailed(first: false, enabled: true)
            case "claude-first-launch-failed": try claudeLaunchFailed(first: true, enabled: true)
            case "claude-desktop-only-failed": try claudeLaunchFailed(first: false, enabled: false)
            case "claude-switch-concurrent": try claudeConcurrentSwitch()
            case "claude-switch-toggle-off": try claudeToggleOffDuringSwitch()
            case "claude-switch-toggle-on": try claudeToggleOnDuringSwitch(fails: false)
            case "claude-switch-toggle-on-failed": try claudeToggleOnDuringSwitch(fails: true)
            case "claude-remove-inflight": try await claudeRemoveDuringRenewal(pending: false)
            case "claude-remove-pending": try await claudeRemoveDuringRenewal(pending: true)
            case "claude-remove-denied": try await claudeRemoveDuringRenewal(pending: true, denied: true)
            case "claude-remove-readd": try await claudeRemoveDuringRenewal(pending: false, readded: true)
            case "claude-readd-inflight": try await claudeReaddInFlight(expired: false)
            case "claude-readd-expired-inflight": try await claudeReaddInFlight(expired: true)
            case "claude-remove-during-save": try await claudeRemoveDuringSave()
            case "claude-remove-during-oauth-lock": try await claudeRemoveDuringOAuthLock()
            case "claude-remove-staged-cli": try claudeRemoveStagedCLI()
            case "claude-remove-staged-cli-main": try claudeRemoveStagedCLI(primary: true)
            case "claude-remove-staged-cli-off": try claudeRemoveStagedCLI(enabled: false)
            case "claude-remove-staged-cli-denied": try claudeRemoveStagedCLI(denied: true)
            case "claude-stale-usage-result": try await claudeStaleUsageResult()
            case "claude-remove-native-writer": try claudeRemoveNativeWriter()
            case "claude-remove-native-profile-writer": try claudeRemoveNativeWriter(primary: false)
            case "claude-remove-native-legacy-writer": try claudeRemoveNativeWriter(lockKind: "legacy")
            case "claude-remove-native-storage-writer": try claudeRemoveNativeWriter(lockKind: "storage")
            case "claude-remove-unmapped": try claudeRemoveUnmapped()
            case "claude-recovery-replacement": try await claudeRecoveryReplacement()
            case "claude-readded-desktop": try claudeReaddedDesktop()
            case "claude-readded-desktop-off": try claudeReaddedDesktop(enabled: false)
            case "claude-readded-desktop-main": try claudeReaddedDesktop(primary: true)
            case "claude-remove-desktop-denied": try claudeReaddedDesktop(denied: true)
            case "claude-readd-staged-cli": try claudeRemoveStagedCLI(readded: true)
            case "claude-readd-staged-cli-off": try claudeRemoveStagedCLI(enabled: false, readded: true)
            case "claude-native-publish": try await claudeNativePublish()
            case "claude-crash-mkdir":
                Fixture.lockCrashPhase = "mkdir"
                try claudeCrashOwner(live: false)
            case "claude-crash-record":
                Fixture.lockCrashPhase = "record"
                try claudeCrashOwner(live: false)
            case "claude-crash-legacy": try claudeCrashLegacyOwner()
            case "claude-crash-owner": try claudeCrashOwner(live: false)
            case "claude-live-owner": try claudeCrashOwner(live: true)
            case "claude-recover-owner": try await claudeRecoverOwner(expectBusy: false)
            case "claude-preserve-owner": try await claudeRecoverOwner(expectBusy: true)
            default: throw Failure(description: "Unknown scenario")
            }
            print("PASS: \(CommandLine.arguments[1])")
        } catch {
            FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
            exit(1)
        }
    }


    @MainActor
    private static func waitForRefresh(_ count: Int) async throws {
        for _ in 0..<300 {
            Fixture.lock.lock()
            let ready = Fixture.refreshCalls >= count
            Fixture.lock.unlock()
            if ready { return }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        throw Failure(description: "Refresh did not reach the held response boundary")
    }

    @MainActor
    private static func codexAutoSourceLoss(fallback: Bool = true) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("auto-source")
        try Fixture.codexLogin(home, account: "source-a", mode: "auto", expired: true)
        if fallback { try Fixture.writeAuth(home, account: "fallback-b", refresh: "fallback-grant", expired: false) }
        let account = DiscoveredAccount(id: "codex:auto-source", provider: .codex, profileName: "auto-source", source: .codexHome(home))
        Fixture.response = .heldRenewed
        let task = Task { await CodexProvider().fetch(account) }
        try await waitForRefresh(1)
        // The server has accepted the grant; Keychain becomes unreadable before persistence.
        Fixture.denyCodexRead = true
        Fixture.releaseRefresh()
        _ = await task.value
        Fixture.denyCodexRead = false
        let outcome = await CodexProvider().fetch(account)
        let saved = CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated"
        print("auto rotation saved after unlocking: \(saved), refresh POST count: \(Fixture.refreshCalls)")
        if case .success = outcome {} else {
            throw Failure(description: "Auto fallback discarded the rotated Keychain grant as if a different file login replaced it")
        }
        try expect(saved && Fixture.refreshCalls == 1, "Auto fallback lost the source Keychain rotation")
    }

    @MainActor
    private static func codexReaddPendingLoss() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("readded")
        try Fixture.codexLogin(home, account: "generation-a", mode: "keyring", expired: true)
        let account = DiscoveredAccount(id: "codex:readded", provider: .codex, profileName: "readded", source: .codexHome(home))
        let provider = CodexProvider()
        let store = UsageStore(providers: [.codex: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        Fixture.distinctRefreshGrants = true
        Fixture.response = .heldRenewed
        let old = Task { await provider.fetch(account) }
        try await waitForRefresh(1)
        try store.removeAccount(id: account.id)
        try Fixture.codexLogin(home, account: "generation-b", mode: "keyring", expired: true)
        Fixture.response = .renewed
        Fixture.denyCodexWrite = true
        store.rediscover(force: true)
        _ = await provider.fetch(account)
        try expect(Fixture.refreshCalls == 2, "Replacement generation did not receive its own refresh response")
        // B now owns an unsaved rotation. A's late response must not erase it.
        Fixture.releaseRefresh()
        _ = await old.value
        Fixture.denyCodexWrite = false
        let outcome = await provider.fetch(account)
        let saved = CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated-synthetic-refresh-generation-b"
        print("replacement rotation retained: \(saved), refresh POST count: \(Fixture.refreshCalls)")
        if case .success = outcome {} else {
            throw Failure(description: "Removed generation's late response erased the re-added generation's pending rotation")
        }
        try expect(saved && Fixture.refreshCalls == 2, "Replacement generation lost its rotated grant")
    }

    @MainActor
    private static func codexSwitchInFlight(mode: String = "keyring", alias: Bool = false) async throws {
        let main = CodexAuthSwap.baseHome
        let home = ProfileDirectories.codexRoot.appendingPathComponent("switching")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(home, account: "switching", mode: mode, expired: true)
        let account = DiscoveredAccount(id: "codex:switching", provider: .codex, profileName: "switching", source: .codexHome(home))
        let target = alias ? ProfileDirectories.codexRoot.appendingPathComponent("switch-alias") : home
        if alias { try Foundation.FileManager.default.createSymbolicLink(at: target, withDestinationURL: home) }
        Fixture.response = .heldRenewed
        let renewal = Task { await CodexProvider().fetch(account) }
        try await waitForRefresh(1)
        var switched = false
        do { try CodexAuthSwap.activate(columnID: alias ? "codex:switch-alias" : account.id, home: target); switched = true } catch {}
        let oldGrantPublished = switched && CodexRenewal.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-refresh-switching"
        Fixture.releaseRefresh()
        _ = await renewal.value
        print("switch exposed a grant while its refresh response was in flight: \(oldGrantPublished)")
        try expect(!oldGrantPublished, "Switch exposed an already-submitted refresh grant to the native Desktop/CLI before rotation was persisted")
        try CodexAuthSwap.activate(columnID: account.id, home: home)
        try expect(CodexRenewal.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-rotated",
                   "Switch did not recover after renewal persisted its grant")
    }

    @MainActor
    private static func claudeFileDiscovery() async throws {
        Fixture.keychainExists = false
        let home = Fixture.storageDirectory
        try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("file-login", expired: false))
            .write(to: home.appendingPathComponent(".credentials.json"))
        let accounts = RealDiscovery().discover().filter { $0.provider == .claude }
        print("valid native Claude fallback file: true, discovered Claude accounts: \(accounts.count)")
        try expect(accounts.count == 1, "Native macOS Claude file fallback is invisible to discovery")
    }

    @MainActor
    private static func claudeFileRemoval() throws {
        Fixture.discoveredClaudeService = Fixture.service
        Fixture.keychain = Fixture.claudeLogin("old-keychain-login", expired: false)
        let home = Fixture.storageDirectory
        try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let file = home.appendingPathComponent(".credentials.json")
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("file-login", expired: false)).write(to: file)
        let account = DiscoveredAccount(id: "claude:" + Fixture.service, provider: .claude, profileName: "main",
                                        source: .claudeKeychain(service: Fixture.service, configDir: nil))
        try AccountRemoval.remove(account)
        let retained = Foundation.FileManager.default.fileExists(atPath: file.path)
        print("successful Claude removal retained native fallback credentials: \(retained)")
        try expect(!retained, "Successful removal retained the native Claude file login")
    }

    private static func codexTOMLMode() throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        try Data("cli_auth_credentials_store = \"\"\"keyring\"\"\"\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(CodexProvider.readAuth(codexHome: home)?.accountID == "secure", "Valid TOML multiline basic string was rejected as an unknown storage setting")
    }

    private static func codexTOMLBackend() throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.codexLogin(home, account: "old-direct-login", mode: "keyring")
        try Data("features = { secret_auth_storage = true }\ncli_auth_credentials_store = 'keyring'\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(CodexProvider.readAuth(codexHome: home) == nil, "Valid inline TOML features bypassed the encrypted-backend guard and loaded an obsolete direct Keychain login")
    }


    @MainActor
    private static func codexSwitchPending(deniedRemoval: Bool = false) async throws {
        let main = CodexAuthSwap.baseHome
        let home = ProfileDirectories.codexRoot.appendingPathComponent("pending-switch")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(home, account: "pending-switch", mode: "keyring", expired: true)
        let account = DiscoveredAccount(id: "codex:pending-switch", provider: .codex, profileName: "pending-switch", source: .codexHome(home))
        Fixture.denyCodexWrite = true
        _ = await CodexProvider().fetch(account)
        if deniedRemoval {
            Fixture.denyCodexDelete = true
            var failed = false
            do { try AccountRemoval.remove(account) } catch { failed = true }
            try expect(failed, "Denied removal reported success")
            Fixture.denyCodexDelete = false
        } else {
            var failed = false
            do { try CodexAuthSwap.activate(columnID: account.id, home: home) } catch { failed = true }
            try expect(failed && CodexProvider.readAuth(codexHome: main)?.accountID == "main",
                       "Switch published an unsaved refresh grant")
        }
        Fixture.denyCodexWrite = false
        let result = await CodexProvider().fetch(account)
        if case .success = result {} else { throw Failure(description: "Pending persistence did not recover") }
        try expect(Fixture.refreshCalls == 1, "Pending persistence repeated the refresh POST")
        try CodexAuthSwap.activate(columnID: account.id, home: home)
        try expect(CodexRenewal.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-rotated", "Switch lost the durable grant")
    }

    @MainActor
    private static func codexAutoFileSource() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("auto-file")
        try Fixture.codexLogin(home, account: "file-owner", mode: "file", expired: true)
        try Fixture.codexMode(home, "auto")
        let account = DiscoveredAccount(id: "codex:auto-file", provider: .codex, profileName: "auto-file", source: .codexHome(home))
        Fixture.response = .heldRenewed
        let task = Task { await CodexProvider().fetch(account) }
        try await waitForRefresh(1)
        let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
        try Fixture.codexLogin(other, account: "new-keychain-login", mode: "keyring")
        let replacement = Fixture.codexKeychain[Fixture.codexKey(other)]!
        Fixture.codexKeychain[Fixture.codexKey(home)] = replacement
        Fixture.releaseRefresh()
        _ = await task.value
        let file = try JSONSerialization.jsonObject(with: Data(contentsOf: home.appendingPathComponent("auth.json"))) as! [String: Any]
        try expect((file["tokens"] as? [String: Any])?["refresh_token"] as? String == "synthetic-rotated",
                   "Auto renewal lost the file grant when a Keychain login appeared")
        try expect(Fixture.codexKeychain[Fixture.codexKey(home)] == replacement, "File renewal overwrote the new Keychain login")
    }

    private static func claudeFileAccount(primary: Bool = true, expired: Bool = true) throws -> (DiscoveredAccount, URL) {
        Fixture.keychainExists = false
        let directory = primary ? Fixture.storageDirectory : ProfileDirectories.claudeRoot.appendingPathComponent("file-profile")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent(".credentials.json")
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("file-owner", expired: expired)).write(to: file)
        try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let hash = SHA256.hash(data: Data(directory.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = primary ? Fixture.service : Fixture.service + "-" + hash
        Fixture.expectedOAuthDirectory = directory
        return (DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: primary ? "main" : "file-profile",
                                  source: .claudeKeychain(service: service, configDir: primary ? nil : directory)), file)
    }

    @MainActor
    private static func claudeFileLifecycle(primary: Bool, failSave: Bool = false, switchCLI: Bool = true) async throws {
        let (account, file) = try claudeFileAccount(primary: primary)
        let directory = file.deletingLastPathComponent()
        let settings = directory.appendingPathComponent("settings.json")
        try Data("preserved".utf8).write(to: settings)
        let provider = ClaudeProvider()
        let store = UsageStore(providers: [.claude: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "File-backed Claude profile was not discovered")
        Fixture.failClaudeFileWrite = failSave
        let renewal = Task { await provider.fetch(account) }
        if failSave {
            for _ in 0..<300 {
                Fixture.lock.lock()
                let failed = Fixture.claudeFileWriteFailures > 0
                Fixture.lock.unlock()
                if failed { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            try expect(Fixture.claudeFileWriteFailures > 0 && Fixture.holdsOAuthLocks,
                       "Failed file save did not retain OAuth locks")
            Fixture.denyKeychainDelete = true
            var removalFailed = false
            do { try store.removeAccount(id: account.id) } catch { removalFailed = true }
            try expect(removalFailed && store.account(for: account.id) != nil
                       && Foundation.FileManager.default.fileExists(atPath: file.path),
                       "Denied removal discarded a pending file grant")
            Fixture.denyKeychainDelete = false
            Fixture.failClaudeFileWrite = false
        }
        let result = await renewal.value
        if case .success = result {} else { throw Failure(description: "File-backed Claude renewal failed") }
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        try expect(ClaudeKeychain.parse(json)?.refreshToken == "synthetic-rotated" && json["unknown"] as? String == "preserved",
                   "File renewal lost its grant or unknown native fields")
        let permissions = try Foundation.FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        try expect(permissions?.intValue == 0o600 && Fixture.refreshCalls == 1 && Fixture.keychainWrites == 0,
                   "File renewal used the wrong backend, permissions or refresh count")
        try expect(Fixture.oauthHeldDuringPOST && !Fixture.holdsOAuthLocks,
                   "File renewal did not hold/release native OAuth locks")
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous/cli/profile\n".utf8).write(to: pointer)
        UserDefaults.standard.set(switchCLI, forKey: "switchClaudeCLI")
        _ = try switchSuccessfully(account)
        let selected = try String(contentsOf: pointer)
        try expect(selected == (switchCLI ? (primary ? "\n" : directory.path + "\n") : "/previous/cli/profile\n"),
                   "File-backed Desktop switch ignored the CLI setting")
        try store.removeAccount(id: account.id)
        try expect(!Foundation.FileManager.default.fileExists(atPath: file.path) && store.account(for: account.id) == nil,
                   "Removed file-backed profile remained signed in or reappeared")
        try expect(Foundation.FileManager.default.fileExists(atPath: settings.path) == primary,
                   "Removal lost primary settings or retained an extra profile")
    }

    @MainActor
    private static func claudeFileLockBusy() async throws {
        let (account, file) = try claudeFileAccount()
        try Foundation.FileManager.default.createDirectory(at: Fixture.oauthLock, withIntermediateDirectories: true)
        let provider = ClaudeProvider()
        _ = await provider.fetch(account)
        try expect(Fixture.refreshCalls == 0, "File-backed refresh ignored a native OAuth lock")
        try Foundation.FileManager.default.removeItem(at: Fixture.oauthLock)
        let result = await provider.fetch(account)
        if case .success = result {} else { throw Failure(description: "File-backed refresh did not recover after lock release") }
        try expect(Foundation.FileManager.default.fileExists(atPath: file.path) && Fixture.refreshCalls == 1, "File refresh did not retain its backend")
    }

    @MainActor
    private static func claudeFileRelogin() async throws {
        let (account, file) = try claudeFileAccount(primary: false)
        Fixture.response = .heldRenewed
        let task = Task { await ClaudeProvider().fetch(account) }
        try await waitForRefresh(1)
        let replacement = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("new-file-login", expired: false))
        try replacement.write(to: file, options: .atomic)
        Fixture.releaseRefresh()
        let result = await task.value
        if case .success = result {} else { throw Failure(description: "Replacement file login was not used") }
        try expect(try Data(contentsOf: file) == replacement, "Late refresh overwrote a replacement file login")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-file-login", "Replaced file login used stale cached credentials")
    }

    private static func codexTOMLForms() throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        let forms = [
            "cli_auth_credentials_store = '''keyring'''\n",
            "cli_auth_credentials_store = \"\"\"\nkey\\\n ring\"\"\"\n",
            "cli_auth_credentials_store = 'keyring'\nfeatures = { secret_auth_storage = false }\n",
        ]
        for text in forms {
            try Data(text.utf8).write(to: home.appendingPathComponent("config.toml"))
            try expect(CodexProvider.readAuth(codexHome: home)?.accountID == "secure", "Valid native TOML form did not select Keychain")
        }
        for features in ["features = { 'secret_auth_storage' = true }", "[ 'features' ]\nsecret_auth_storage = true", "features . secret_auth_storage = true"] {
            try Data(("cli_auth_credentials_store = 'keyring'\n" + features + "\n").utf8).write(to: home.appendingPathComponent("config.toml"))
            try expect(CodexProvider.readAuth(codexHome: home) == nil, "Valid TOML syntax bypassed the encrypted backend guard")
        }
    }


    private static func codexBaseAlias() async throws {
        let main = CodexAuthSwap.baseHome
        try Fixture.codexLogin(main, account: "main", mode: "keyring", expired: true)
        let home = ProfileDirectories.codexRoot.appendingPathComponent("base-alias")
        try Foundation.FileManager.default.createDirectory(at: ProfileDirectories.codexRoot, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: home, withDestinationURL: main)
        let account = DiscoveredAccount(id: "codex:base-alias", provider: .codex, profileName: "base-alias", source: .codexHome(home))
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 0, "Symlink alias renewed a grant owned by the native Desktop/CLI")
    }


    @MainActor
    private static func fallbackRemovalDenied(codex: Bool, keychainDenied: Bool) throws {
        let account: DiscoveredAccount
        let file: URL
        let keychainData: Data?
        if codex {
            let home = ProfileDirectories.codexRoot.appendingPathComponent("denied-fallback")
            try Fixture.codexLogin(home, account: "keychain-owner", mode: "auto")
            try Fixture.writeAuth(home, account: "file-owner", refresh: "file-grant", expired: false)
            account = DiscoveredAccount(id: "codex:denied-fallback", provider: .codex, profileName: "denied-fallback", source: .codexHome(home))
            file = home.appendingPathComponent("auth.json")
            keychainData = Fixture.codexKeychain[Fixture.codexKey(home)]
            Fixture.denyCodexDelete = keychainDenied
        } else {
            (account, file) = try claudeFileAccount()
            Fixture.keychainExists = true
            Fixture.keychain = Fixture.claudeLogin("keychain-owner", expired: false)
            Fixture.denyKeychainDelete = keychainDenied
            keychainData = nil
        }
        let original = try Data(contentsOf: file)
        Fixture.denyCredentialFileRemoval = !keychainDenied
        var failed = false
        do { try AccountRemoval.remove(account) } catch { failed = true }
        try expect(failed, "Partial credential-store deletion reported success")
        try expect(try Data(contentsOf: file) == original, "Failed removal did not retain/restore the fallback credentials")
        if codex {
            try expect(Fixture.codexKeychain[Fixture.codexKey(file.deletingLastPathComponent())] == keychainData,
                       "Failed file unlink discarded the Keychain credentials")
        } else {
            try expect(Fixture.keychainExists, "Failed file unlink discarded Claude's Keychain credentials")
        }
    }

    private static func codexStoreRead(_ mode: String, missing: Bool = false, denied: Bool = false) throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        if missing { Fixture.codexKeychain = [:] }
        Fixture.denyCodexRead = denied
        try Fixture.writeAuth(home, account: "stale-file", refresh: "stale-file-refresh", expired: false)
        try Fixture.codexMode(home, mode)
        let auth = CodexProvider.readAuth(codexHome: home)
        if mode == "ephemeral" || mode == "unknown" || mode == "keyring" && denied {
            try expect(auth == nil, "Persistent file credentials bypassed the selected Codex storage mode")
        } else {
            let expected = mode == "file" || missing || denied ? "stale-file" : "secure"
            try expect(auth?.accountID == expected, "Codex loaded a stale or wrong credential backend")
        }
        if mode == "ephemeral" || mode == "file" { try expect(Fixture.codexSecretReads == 0, "Storage mode probed an unrelated Keychain secret") }
    }

    private static func codexStoreDiscovery(symlink: Bool = false) throws {
        let main = CodexAuthSwap.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(main, account: "main", mode: "keyring")
        try Fixture.codexLogin(profile, account: "profile", mode: "keyring")
        if symlink {
            let alias = Fixture.root.appendingPathComponent("codex-alias")
            try Foundation.FileManager.default.createSymbolicLink(at: alias, withDestinationURL: profile)
            try expect(CodexProvider.readAuth(codexHome: alias)?.accountID == "profile", "Keychain service key ignored the canonical CODEX_HOME")
        }
        let reads = Fixture.codexSecretReads
        let accounts = RealDiscovery().discover().filter { $0.provider == .codex }
        try expect(Set(accounts.map(\.id)) == [CodexAuthSwap.defaultColumnID, "codex:secure"], "Keychain-only Codex accounts were not discovered")
        try expect(Fixture.codexSecretReads == reads, "Discovery read credential secrets instead of metadata")
        try expect(CodexProvider.readAuth(codexHome: main)?.accountID == "main", "Keychain primary account could not be read")
    }

    @MainActor
    private static func codexStoreSwitch(baseMode: String = "keyring", profileMode: String = "keyring", fallback: Bool = false) throws {
        let main = CodexAuthSwap.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(main, account: "main", mode: fallback ? "file" : baseMode)
        try Fixture.codexMode(main, baseMode)
        try Fixture.codexLogin(profile, account: "profile", mode: profileMode)
        Fixture.denyCodexWrite = fallback
        let projects = main.appendingPathComponent("synthetic-projects")
        try Data("preserved".utf8).write(to: projects)
        ClaudeCLISelection.isEnabled = false // Claude's setting cannot change Codex switching.
        do { try CodexAuthSwap.activate(columnID: "codex:secure", home: profile) }
        catch { throw Failure(description: "Codex switch rejected an existing persistent Keychain profile") }
        try expect(CodexProvider.readAuth(codexHome: main)?.accountID == "profile", "Desktop/CLI did not select the profile in the base backend")
        try expect(CodexProvider.readAuth(codexHome: CodexAuthSwap.stashHome)?.accountID == "main", "Main credentials were not retained in their backend")
        try Fixture.codexLogin(main, account: "profile", mode: fallback ? "file" : baseMode, expired: false)
        try Fixture.codexMode(main, baseMode)
        // Model native refresh while this profile owns the Desktop/CLI base home.
        if baseMode != "file" && !fallback {
            let data = Fixture.codexKeychain[Fixture.codexKey(main)]!
            var root = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            var tokens = root["tokens"] as! [String: Any]
            tokens["refresh_token"] = "native-rotated"
            root["tokens"] = tokens
            Fixture.codexKeychain[Fixture.codexKey(main)] = try JSONSerialization.data(withJSONObject: root)
        } else {
            try Fixture.writeAuth(main, account: "profile", refresh: "native-rotated", expired: false)
        }
        try CodexAuthSwap.restoreDefault()
        try expect(CodexProvider.readAuth(codexHome: main)?.accountID == "main", "Main account did not restore")
        try expect(CodexRenewal.refreshToken(profile.appendingPathComponent("auth.json")) == "native-rotated", "Native refreshed profile credentials were not returned to their selected backend")
        try expect(try String(contentsOf: projects) == "preserved", "Switch changed Desktop projects")
        if baseMode != "file" && !fallback { try expect(!Foundation.FileManager.default.fileExists(atPath: main.appendingPathComponent("auth.json").path), "Switch exported base Keychain credentials to auth.json") }
        if profileMode != "file" { try expect(!Foundation.FileManager.default.fileExists(atPath: profile.appendingPathComponent("auth.json").path), "Switch exported profile Keychain credentials to auth.json") }
    }

    private static func codexStoreRenewal(mode: String = "keyring", denied: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(home, account: "secure", mode: mode, expired: true)
        let account = DiscoveredAccount(id: "codex:secure", provider: .codex, profileName: "secure", source: .codexHome(home))
        Fixture.denyCodexWrite = denied
        _ = await CodexProvider().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Sleeping Keychain profile was not renewed")
        if denied {
            try expect(CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-refresh-secure", "Denied persistence did not preserve the stored grant")
            Fixture.denyCodexWrite = false
        }
        let outcome = await CodexProvider().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Keychain renewal did not recover persistence") }
        try expect(Fixture.refreshCalls == 1 && CodexRenewal.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated", "Keychain persistence lost tokens or repeated the refresh POST")
        try expect(!Foundation.FileManager.default.fileExists(atPath: home.appendingPathComponent("auth.json").path), "Keychain renewal wrote plaintext credentials")
    }

    @MainActor
    private static func codexStoreRemove(denied: Bool = false) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        Fixture.denyCodexDelete = denied
        let account = DiscoveredAccount(id: "codex:secure", provider: .codex, profileName: "secure", source: .codexHome(home))
        var failed = false
        do { try AccountRemoval.remove(account) } catch { failed = true }
        try expect(failed == denied, "Codex removal ignored its Keychain deletion result")
        try expect((Fixture.codexKeychain[Fixture.codexKey(home)] != nil) == denied,
                   "Codex removal left credentials behind or deleted a refused account")
        try expect(Foundation.FileManager.default.fileExists(atPath: home.path) == denied, "Codex removal did not preserve the profile on failure")
    }

    private static func codexStoreSettings(requirements: Bool = false, managed: Bool = false) throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        try Fixture.writeAuth(home, account: "stale", refresh: "stale", expired: false)
        if requirements || managed {
            try Fixture.codexMode(home, "file")
            if requirements {
                let directory = Fixture.root.appendingPathComponent("system")
                try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try Data("cli_auth_credentials_store = 'keyring'\n".utf8).write(to: directory.appendingPathComponent("requirements.toml"))
            } else {
                Fixture.managedCodex["requirements_toml_base64"] = Data("cli_auth_credentials_store = 'keyring'\n".utf8).base64EncodedString()
            }
        } else {
            let text = "description = \"\"\"\ncli_auth_credentials_store = 'file'\n\"\"\"\n\"cli_auth_credentials_store\" = 'keyring' # root\n[other]\ncli_auth_credentials_store = 'file'\n"
            try Data(text.utf8).write(to: home.appendingPathComponent("config.toml"))
        }
        try expect(CodexProvider.readAuth(codexHome: home)?.accountID == "secure", "Codex ignored root/managed storage settings or parsed a nested/string value as root")
    }

    private static func codexStoreEncryptedBackend() throws {
        let home = CodexAuthSwap.baseHome
        try Fixture.writeAuth(home, account: "stale", refresh: "stale", expired: false)
        try Data("cli_auth_credentials_store = 'keyring'\n[features]\nsecret_auth_storage = true\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(CodexProvider.readAuth(codexHome: home) == nil,
                   "Encrypted secrets mode was mistaken for a direct Keychain or file login")
    }

    private static func codexStoreEphemeralSwitch(alreadyActive: Bool = false) throws {
        let main = CodexAuthSwap.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("file")
        try Fixture.writeAuth(main, account: "stale-main", refresh: "stale", expired: false)
        try Fixture.codexMode(main, "ephemeral")
        try Fixture.codexLogin(profile, account: "profile", mode: "file")
        let before = try Data(contentsOf: main.appendingPathComponent("auth.json"))
        if alreadyActive {
            UserDefaults.standard.set("codex:file", forKey: "codexAppAccountID")
            UserDefaults.standard.set(profile.path, forKey: "codexAppAccountHome")
        }
        let previousID = CodexAuthSwap.activeColumnID
        var failed = false
        do { try CodexAuthSwap.activate(columnID: "codex:file", home: profile) } catch { failed = true }
        try expect(failed && CodexAuthSwap.activeColumnID == previousID,
                   "Ephemeral mode allowed a persistent Desktop/CLI switch")
        try expect(try Data(contentsOf: main.appendingPathComponent("auth.json")) == before, "Ephemeral mode mutated a persistent cache")
    }

    @MainActor
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

    private static func profileCollision() throws {
        let names = ["default", "profile:default", "profile:profile:default", "work"]
        try Fixture.writeAuth(CodexAuthSwap.baseHome, account: "synthetic-main", refresh: "main-refresh")
        for name in names {
            try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent(name),
                                  account: "synthetic-" + name, refresh: "refresh-" + name)
        }
        let accounts = RealDiscovery().discover()
        try expect(accounts.count == names.count + 1, "Imported profiles missing")
        try expect(Set(accounts.map(\.id)).count == accounts.count, "Imported profiles share an ID")
        try expect(CodexAuthSwap.profileColumnID("work") == "codex:work", "Existing ordinary profile ID changed")
        for name in names {
            let account = accounts.first { $0.profileName == name }!
            guard case .codexHome(let home) = account.source else { continue }
            try CodexAuthSwap.activate(columnID: account.id, home: home)
            try expect(CodexProvider.readAuth(codexHome: CodexAuthSwap.baseHome)?.accountID == "synthetic-" + name,
                       "Switching imported profile chose another account")
            try expect(RealDiscovery().discover().filter(\.isActive).count == 1, "Multiple imported profiles active")
        }
        try CodexAuthSwap.restoreDefault()
        let imported = accounts.first { $0.profileName == "profile:default" }!
        try AccountRemoval.remove(imported)
        try expect(RealDiscovery().discover().count == names.count, "Wrong number of profiles after removal")
        try expect(CodexProvider.readAuth(codexHome: CodexAuthSwap.baseHome)?.accountID == "synthetic-main",
                   "Imported profile removal changed main account")
    }

    private static func profileActiveMigration() throws {
        let name = "profile:default"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        try Fixture.writeAuth(CodexAuthSwap.baseHome, account: "synthetic-main", refresh: "main-refresh")
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent("default"),
                              account: "synthetic-default-profile", refresh: "default-refresh")
        try CodexAuthSwap.activate(columnID: CodexAuthSwap.profileColumnID(name), home: home)
        UserDefaults.standard.set("codex:" + name, forKey: "codexAppAccountID")
        let accounts = RealDiscovery().discover()
        try expect(accounts.filter(\.isActive).count == 1, "Legacy active ID marks two profiles active")
        let active = accounts.first(where: \.isActive)!
        try expect(active.profileName == name, "Legacy active ID migrated to the wrong profile")
        try CodexAuthSwap.restoreDefault()
        try expect(CodexProvider.readAuth(codexHome: home)?.accountID == "synthetic-imported",
                   "Legacy migration saved live credentials to the wrong profile")
        try expect(CodexProvider.readAuth(codexHome: CodexAuthSwap.baseHome)?.accountID == "synthetic-main",
                   "Legacy migration did not restore main account")
    }

    @MainActor
    private static func profileSettingsMigration() throws {
        let name = "profile:work"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        UserDefaults.standard.set(["codex:" + name], forKey: "hiddenColumns")
        UserDefaults.standard.set(["codex:" + name: "Private account"], forKey: "columnNames")
        let store = UsageStore(providers: [:], discovery: RealDiscovery())
        store.rediscover(force: true)
        try expect(store.columns.count == 1, "Imported profile missing")
        try expect(store.visibleColumns.isEmpty, "Previously hidden imported profile became visible")
        try expect(store.columns[0].customName == "Private account", "Imported profile's custom name was lost")
    }

    @MainActor
    private static func profileSettingsExisting() throws {
        let name = "profile:work"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        let currentID = CodexAuthSwap.profileColumnID(name)
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        UserDefaults.standard.set(["codex:" + name], forKey: "hiddenColumns")
        UserDefaults.standard.set(["codex:" + name: "Legacy name", currentID: "Current name",
                                   "claude:unrelated": "Unrelated name"], forKey: "columnNames")
        let first = UsageStore(providers: [:], discovery: RealDiscovery())
        first.rediscover(force: true)
        try expect(first.columns[0].customName == "Current name", "Current custom name was overwritten")
        first.setCustomName("Edited name", for: currentID)
        first.setHidden(currentID, hidden: false)
        let restarted = UsageStore(providers: [:], discovery: RealDiscovery())
        restarted.rediscover(force: true)
        try expect(restarted.visibleColumns.count == 1, "Repeated migration hid a profile the user unhid")
        try expect(restarted.columns[0].customName == "Edited name", "Repeated migration replaced the user's edit")
        try expect(restarted.customNames["claude:unrelated"] == "Unrelated name", "Unrelated provider settings changed")
    }

    @MainActor
    private static func profileSettingsCollision() throws {
        for name in ["default", "profile:default"] {
            try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent(name),
                                  account: "synthetic-" + name, refresh: "refresh-" + name)
        }
        let legacyID = "codex:profile:default"
        UserDefaults.standard.set([legacyID], forKey: "hiddenColumns")
        UserDefaults.standard.set([legacyID: "Shared legacy name"], forKey: "columnNames")
        let store = UsageStore(providers: [:], discovery: RealDiscovery())
        store.rediscover(force: true)
        try expect(store.columns.count == 2, "Colliding legacy profiles missing")
        try expect(store.visibleColumns.isEmpty, "Legacy collision revealed a hidden account")
        try expect(store.columns.allSatisfy { $0.customName == "Shared legacy name" },
                   "Migration removed settings still owned by the default profile")
    }

    @MainActor
    private static func profileSettingsNested() throws {
        for name in ["profile:work", "profile:profile:work"] {
            try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent(name),
                                  account: "synthetic-" + name, refresh: "refresh-" + name)
        }
        UserDefaults.standard.set(["codex:profile:work"], forKey: "hiddenColumns")
        UserDefaults.standard.set(["codex:profile:work": "First profile"], forKey: "columnNames")
        let store = UsageStore(providers: [:], discovery: RealDiscovery())
        store.rediscover(force: true)
        try expect(store.visibleColumns.map(\.profileName) == ["profile:profile:work"],
                   "Nested ID migration copied hidden state to another profile")
        try expect(store.columns.first { $0.profileName == "profile:work" }?.customName == "First profile",
                   "Original profile's custom name was not migrated")
        try expect(store.columns.first { $0.profileName == "profile:profile:work" }?.customName == nil,
                   "Nested ID migration copied another profile's name")
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
        let renewal = Task { await provider.fetch(Fixture.claudeAccount) }
        try await waitForFailedSave()
        Fixture.lock.lock()
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        Fixture.failKeychainSave = false
        Fixture.lock.unlock()
        _ = await renewal.value
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 1, "Pending save made another refresh request")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Pending save replaced newer CLI login")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Old cached tokens survived CLI login")
    }

    private static func claudeWriteRace(afterRead: Int) async throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.changeLoginAfterRead = afterRead
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if Fixture.pendingCLILogin { Fixture.tryCLILogin() }
        try expect(Fixture.keychainReads >= afterRead, "Target Keychain read did not happen")
        if case .success = outcome {} else { throw Failure(description: "Usage did not complete") }
        try expect(!Fixture.pendingCLILogin, "CLI could not acquire the released storage lock")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Keychain write replaced a concurrent CLI login after read \(afterRead)")
    }

    private static func claudeLockBusy(stale: Bool) throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageLock, withIntermediateDirectories: true)
        if stale {
            try Foundation.FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-60)],
                                                             ofItemAtPath: Fixture.storageLock.path)
        }
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        try expect(!ClaudeKeychain.canWrite(service: Fixture.service), "CLI-owned lock allowed a Keychain write")
        try expect(Fixture.keychainWrites == 0, "Busy storage lock still wrote credentials")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Another process's storage lock was removed")
    }

    private static func claudeLockLost() throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.replaceLockAfterRead = 1
        try expect(!ClaudeKeychain.canWrite(service: Fixture.service), "Lost storage lock allowed a Keychain write")
        try expect(Fixture.keychainWrites == 0, "Credentials written after storage lock changed owner")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Releasing a lost lock removed the CLI's replacement lock")
    }

    private static func claudeLockHeartbeat() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.slowKeychainRead = true
        let started = Date()
        let writer = Task.detached { ClaudeKeychain.canWrite(service: Fixture.service) }
        try await Task.sleep(nanoseconds: 5_800_000_000)
        let attributes = try? Foundation.FileManager.default.attributesOfItem(atPath: Fixture.storageLock.path)
        let touched = attributes?[.modificationDate] as? Date
        let writable = await writer.value
        try expect(touched.map { $0.timeIntervalSince(started) >= 4 } == true,
                   "Storage heartbeat stopped while Keychain waited")
        try expect(writable, "Owned storage lock did not allow the write")
        try expect(!Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Owned storage lock was not released")
    }

    private static func claudeProfileLock() throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageLock, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = ClaudeKeychain.baseService + "-" + suffix
        Fixture.expectedLock = profile.appendingPathComponent(".storage-write.lock")
        Fixture.keychain = Fixture.claudeLogin("work", expired: true)
        try expect(ClaudeKeychain.canWrite(service: service), "Main profile's lock blocked a separate profile")
        try expect(Fixture.observedProfileLock, "Extra profile write did not acquire that profile's CLI lock")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Extra profile write removed main profile's lock")
    }

    private static func claudeNativeLogin(writeBoundary: Bool = false) async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = writeBoundary ? .renewed : .nativeLogin
        Fixture.loginAtWriteBoundary = writeBoundary
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if case .success = outcome {} else { throw Failure(description: "Renewal did not complete") }
        try expect(Fixture.nativeLoginPending, "Native CLI login entered during the refresh HTTP request")
        try expect(Fixture.oauthHeldDuringPOST && Fixture.oauthHeldDuringWrite,
                   "OAuth locks did not cover the entire read/refresh/save cycle")
        try expect(Fixture.noninteractiveWrites, "Keychain write could display a dialog while holding OAuth locks")
        try expect(Fixture.interactionAllowed, "Legacy Keychain interaction policy was not restored")
        Fixture.tryNativeLogin()
        try expect(!Fixture.nativeLoginPending, "OAuth locks were not released after saving")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "CLI login after renewal did not survive")
    }

    private static func claudeNoWritePermission() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.denyNoninteractiveWrite = true
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if case .failure = outcome {} else { throw Failure(description: "Missing write permission did not defer renewal") }
        try expect(Fixture.refreshCalls == 0, "Renewal spent a refresh token without noninteractive write permission")
        try expect(Fixture.interactionAllowed, "Failed Keychain preflight did not restore interaction policy")
        try expect(!Fixture.holdsOAuthLocks, "Failed Keychain preflight leaked OAuth locks")
    }

    private static func claudeOAuthHeartbeat() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .slowRenewed
        let started = Date()
        let renewal = Task { await ClaudeProvider().fetch(Fixture.claudeAccount) }
        try await Task.sleep(nanoseconds: 5_800_000_000)
        var touched = true
        for path in [Fixture.oauthLock, Fixture.legacyLock] {
            let attributes = try? Foundation.FileManager.default.attributesOfItem(atPath: path.path)
            let modified = attributes?[.modificationDate] as? Date
            touched = touched && modified.map { $0.timeIntervalSince(started) >= 4 } == true
        }
        let outcome = await renewal.value
        try expect(touched, "OAuth heartbeat stopped during HTTP refresh")
        if case .success = outcome {} else { throw Failure(description: "Renewal failed after OAuth heartbeat") }
        try expect(!Fixture.holdsOAuthLocks, "OAuth heartbeat locks were not released")
    }

    private static func claudeOAuthBusy(legacy: Bool) async throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        let path = legacy ? Fixture.legacyLock : Fixture.oauthLock
        try Foundation.FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0,
                   "Renewal entered a CLI-owned OAuth critical section")
        try expect(Foundation.FileManager.default.fileExists(atPath: path.path), "CLI's OAuth lock was removed")
        if legacy {
            try expect(!Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path),
                       "Failure to acquire the legacy lock leaked the new OAuth lock")
        }
    }

    private static func claudeOAuthReread() async throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.loginBeforeOAuth = true
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 0, "Used credentials read before acquiring the OAuth locks")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Did not adopt the login committed before lock acquisition")
    }

    private static func claudeConcurrentRefresh() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .delayedRenewed
        let provider = ClaudeProvider()
        async let first = provider.fetch(Fixture.claudeAccount)
        async let second = provider.fetch(Fixture.claudeAccount)
        let outcomes = await [first, second]
        try expect(Fixture.refreshCalls == 1, "Concurrent Claude fetches posted the same refresh token twice")
        for outcome in outcomes {
            if case .success = outcome {} else { throw Failure(description: "Concurrent caller did not share renewal result") }
        }
    }

    private static func claudeOAuthLost() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.replaceOAuthDuringPOST = true
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(Fixture.keychainWrites == 1, "Saved credentials after losing the OAuth lease")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.accessToken == "synthetic-old-login", "Lost lease changed credentials")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path), "Released another OAuth lock owner")
    }

    private static func claudeCacheLogin() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        let provider = ClaudeProvider()
        _ = await provider.fetch(Fixture.claudeAccount)
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Usage retained a cached token from the previous CLI login")
        try expect(Fixture.refreshCalls == 0, "Changing to a live login unnecessarily refreshed it")
    }

    private static func claudeNetworkRecovery() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .lost
        let provider = ClaudeProvider()
        let failed = await provider.fetch(Fixture.claudeAccount)
        if case .failure = failed {} else { throw Failure(description: "Network error incorrectly requested login") }
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.refreshToken == "synthetic-refresh-old-login", "Network failure erased credentials")
        try expect(!Fixture.holdsOAuthLocks, "Network error leaked OAuth locks")
        Fixture.response = .renewed
        let recovered = await provider.fetch(Fixture.claudeAccount)
        if case .success = recovered {} else { throw Failure(description: "Renewal did not recover after network returned") }
        try expect(Fixture.refreshCalls == 2, "Network recovery failed to retry on the next polling cycle")
    }

    private static func claudeRefreshNoRetry() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(!Fixture.allowHTTPRetry, "Rotating Claude refresh POST enabled automatic HTTP retries")
    }

    private static func claudeRefreshForbidden() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .forbidden
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if case .failure = outcome {} else { throw Failure(description: "Regional/proxy 403 incorrectly requested login") }
        try expect(!Fixture.holdsOAuthLocks, "Forbidden response leaked OAuth locks")
    }

    private static func claudeUsageForbidden() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.usageStatus = 403
        let provider = ClaudeProvider()
        _ = await provider.fetch(Fixture.claudeAccount)
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 0, "Usage 403 caused unnecessary refresh-token rotation")
    }

    private static func claudeOAuthProfile() async throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        Fixture.expectedOAuthDirectory = profile
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = ClaudeKeychain.baseService + "-" + suffix
        let account = DiscoveredAccount(id: "claude:work", provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory.appendingPathComponent(".oauth_refresh.lock"), withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("work", expired: true)
        let outcome = await ClaudeProvider().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Main OAuth lock blocked a separate profile") }
        try expect(Fixture.oauthHeldDuringPOST && Fixture.oauthHeldDuringWrite, "Profile did not use its own OAuth locks")
        try expect(!Fixture.holdsOAuthLocks, "Profile OAuth locks were not released")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageDirectory.appendingPathComponent(".oauth_refresh.lock").path), "Profile renewal removed main lock")
    }

    @MainActor
    private static func switchSuccessfully(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        var result: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(account) { result = $0 }
        guard let result else { throw Failure(description: "Fixture did not complete Desktop launch") }
        try result.get()
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = Fixture.desktopArguments
        return config
    }

    @MainActor
    private static func claudeSwitchCLI(enabled: Bool?, primary: Bool = false) throws {
        if let enabled { UserDefaults.standard.set(enabled, forKey: "switchClaudeCLI") }
        let startup = Fixture.root.appendingPathComponent(".zshrc")
        try Data("# Existing user configuration\nexport USER_SETTING=preserved\n".utf8).write(to: startup)
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work 'quoted'")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = primary ? Fixture.service : Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: primary ? nil : profile))
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        if enabled == false {
            try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("/previous/selection\n".utf8).write(to: pointer)
        }
        let config = try switchSuccessfully(account)
        try expect(config.arguments.first?.hasPrefix("--user-data-dir=") == true, "Claude Desktop session switching changed")
        let selected = try? String(contentsOf: pointer, encoding: .utf8)
        if enabled == false {
            try expect(selected == "/previous/selection\n", "Desktop-only switching changed CLI selection")
            try expect((try String(contentsOf: startup)) == "# Existing user configuration\nexport USER_SETTING=preserved\n", "Desktop-only switch installed shell integration")
        } else {
            try expect(selected == (primary ? "\n" : profile.path + "\n"), "CLI selection did not follow Desktop by default")
            _ = try switchSuccessfully(account)
            let content = try String(contentsOf: startup)
            try expect(content.hasPrefix("# Existing user configuration\nexport USER_SETTING=preserved\n"), "Shell integration replaced user configuration")
            try expect(content.components(separatedBy: "# Notchlimits Claude profile selection").count == 2, "Shell integration duplicated startup entries")
        }
        try expect(Fixture.keychainWrites == 0 && Fixture.refreshCalls == 0, "Switching profiles copied or renewed credentials")
    }

    @MainActor
    private static func claudeSwitchBash() throws {
        Fixture.shell = "/bin/bash"
        let profile = Fixture.root.appendingPathComponent(".profile")
        let bashrc = Fixture.root.appendingPathComponent(".bashrc")
        try Data("# Existing login profile\n".utf8).write(to: profile)
        try Data("# Existing interactive config\n".utf8).write(to: bashrc)
        _ = try switchSuccessfully(Fixture.claudeAccount)
        try expect(!Foundation.FileManager.default.fileExists(atPath: Fixture.root.appendingPathComponent(".bash_profile").path),
                   "Creating .bash_profile shadowed the user's existing .profile")
        try expect((try String(contentsOf: profile)).hasPrefix("# Existing login profile\n"), "Login shell configuration was replaced")
        let interactive = try String(contentsOf: bashrc)
        try expect(interactive.hasPrefix("# Existing interactive config\n"), "Interactive shell configuration was replaced")
        try expect(interactive.contains("# Notchlimits Claude profile selection"), "Non-login bash did not load CLI routing")
    }

    private static func waitForFailedSave() async throws {
        for _ in 0..<200 {
            if Fixture.writes() >= 2 { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        throw Failure(description: "Fixture did not reach the post-refresh save failure")
    }

    private static func claudePersistBeforeUnlock() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.failKeychainSave = true
        let provider = ClaudeProvider()
        let renewal = Task { await provider.fetch(Fixture.claudeAccount) }
        try await waitForFailedSave()
        // Let the old implementation finish and release its leases.
        try await Task.sleep(nanoseconds: 120_000_000)
        Fixture.lock.lock()
        Fixture.tryNativeRefresh()
        let cleared = Fixture.cliClearedRevokedGrant
        Fixture.failKeychainSave = false
        Fixture.lock.unlock()
        let outcome = await renewal.value
        try expect(!cleared, "CLI consumed the obsolete grant before rotated credentials were saved")
        if case .success = outcome {} else { throw Failure(description: "Failed persistence did not recover within the same renewal") }
        try expect(Fixture.refreshCalls == 1, "Persistence recovery spent another refresh token")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated", "Rotated credentials were not saved")
        try expect(!Fixture.holdsOAuthLocks, "Successful persistence leaked OAuth locks")
    }

    private static func claudeQuitPending() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.failKeychainSave = true
        let provider = ClaudeProvider()
        let renewal = Task { await provider.fetch(Fixture.claudeAccount) }
        try await waitForFailedSave()
        #if CLAUDE_TERMINATION_DRAIN
        let ready = await provider.prepareForTermination(timeout: 0.2)
        #else
        // The old app has no termination hook and permits immediate termination.
        let ready = true
        #endif
        Fixture.lock.lock()
        Fixture.failKeychainSave = false
        Fixture.lock.unlock()
        _ = await renewal.value
        try expect(!ready, "Normal termination abandoned an unsaved rotated grant")
        #if CLAUDE_TERMINATION_DRAIN
        let drained = await provider.prepareForTermination(timeout: 1)
        try expect(drained, "Normal termination stayed blocked after credentials became durable")
        #endif
        try expect(Fixture.refreshCalls == 1, "Termination drain started another refresh request")
    }

    private static func claudeQuitInFlight() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .delayedRenewed
        let provider = ClaudeProvider()
        let renewal = Task { await provider.fetch(Fixture.claudeAccount) }
        for _ in 0..<200 {
            Fixture.lock.lock()
            let started = Fixture.refreshCalls > 0
            Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        #if CLAUDE_TERMINATION_DRAIN
        let ready = await provider.prepareForTermination(timeout: 1)
        #else
        let ready = true
        #endif
        Fixture.lock.lock()
        let durableAtQuit = ClaudeKeychain.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated"
        Fixture.lock.unlock()
        _ = await renewal.value
        try expect(ready && durableAtQuit, "Normal termination left a refresh POST in flight before its tokens were saved")
    }

    @MainActor
    private static func claudeExactPath(symlink: Bool, resolved: Bool = true) throws {
        if symlink {
            let physical = Fixture.root.appendingPathComponent("physical-profiles")
            try Foundation.FileManager.default.createDirectory(at: physical, withIntermediateDirectories: true)
            try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.claudeRoot, withDestinationURL: physical)
        }
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let selected = symlink ? (resolved ? directory.resolvingSymlinksInPath().path : directory.path) : directory.path + "/"
        let suffix = SHA256.hash(data: Data(selected.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: directory))
        _ = try switchSuccessfully(account)
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        let emitted = try String(contentsOf: pointer).trimmingCharacters(in: .newlines)
        let actualHash = SHA256.hash(data: Data(emitted.precomposedStringWithCanonicalMapping.utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(8)
        try expect(actualHash == suffix, "CLI selection changed the Keychain service of the selected account")
        try expect(emitted == selected, "CLI selection lost the exact matching path variant")
    }

    @MainActor
    private static func claudeRejectShortHash() throws {
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(directory.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(1)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: directory))
        var refused = false
        do { _ = try switchSuccessfully(account) } catch { refused = true }
        try expect(refused, "CLI accepted a service identity its native path hash cannot reproduce")
    }

    @MainActor
    private static func claudeLaunchFailed(first: Bool, enabled: Bool) throws {
        UserDefaults.standard.set(enabled, forKey: "switchClaudeCLI")
        UserDefaults.standard.set("previous-desktop", forKey: "currentClaudeAppAccount")
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        if !first {
            try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("/previous/cli/profile\n".utf8).write(to: pointer)
        }
        var account = Fixture.claudeAccount
        var target = "\n"
        if first {
            let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
            try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
            let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
            let service = Fixture.service + "-" + suffix
            account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
            target = profile.path + "\n"
        }
        Fixture.desktopFails = true
        var result: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(account) { result = $0 }
        if case .failure? = result {} else { throw Failure(description: "Desktop launch failure was not reported") }
        let selected = try? String(contentsOf: pointer)
        try expect(selected == (first ? "\n" : "/previous/cli/profile\n"), "Failed Desktop launch changed CLI account or broke first-use CLI routing")
        try expect(UserDefaults.standard.string(forKey: "currentClaudeAppAccount") == "previous-desktop", "Failed launch committed the Desktop marker")
        Fixture.desktopFails = false
        ClaudeAppSwitcher().switchTo(account) { result = $0 }
        if case .success? = result {} else { throw Failure(description: "Failure left subsequent account switches blocked") }
        try expect((try? String(contentsOf: pointer)) == (enabled ? target : "/previous/cli/profile\n"), "Successful switch ignored the CLI setting")
    }

    @MainActor
    private static func claudeConcurrentSwitch() throws {
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous/cli/profile\n".utf8).write(to: pointer)
        Fixture.holdDesktopCompletion = true
        var first: Result<Void, Error>?
        var second: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(Fixture.claudeAccount) { first = $0 }
        try expect((try String(contentsOf: pointer)) == "/previous/cli/profile\n", "Pending Desktop launch exposed an uncommitted CLI selection")
        ClaudeAppSwitcher().switchTo(Fixture.claudeAccount) { second = $0 }
        try expect(Fixture.desktopCalls == 1, "Concurrent switches entered Desktop restart twice")
        if case .failure? = second {} else { throw Failure(description: "Concurrent switch was not rejected") }
        Fixture.desktopCompletion?(.success(()))
        if case .success? = first {} else { throw Failure(description: "Original switch did not complete") }
    }

    @MainActor
    private static func claudeToggleOffDuringSwitch() throws {
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous/cli/profile\n".utf8).write(to: pointer)
        Fixture.holdDesktopCompletion = true
        var result: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(Fixture.claudeAccount) { result = $0 }
        UserDefaults.standard.set(false, forKey: "switchClaudeCLI")
        Fixture.desktopCompletion?(.success(()))
        if case .success? = result {} else { throw Failure(description: "Desktop switch did not complete") }
        try expect((try String(contentsOf: pointer)) == "/previous/cli/profile\n", "Disabling CLI switching during Desktop launch still changed the CLI account")
    }

    @MainActor
    private static func claudeToggleOnDuringSwitch(fails: Bool) throws {
        UserDefaults.standard.set(false, forKey: "switchClaudeCLI")
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous/cli/profile\n".utf8).write(to: pointer)
        Fixture.holdDesktopCompletion = true
        var result: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(Fixture.claudeAccount) { result = $0 }
        try expect((try String(contentsOf: pointer)) == "/previous/cli/profile\n", "Pending Desktop launch changed CLI routing")
        UserDefaults.standard.set(true, forKey: "switchClaudeCLI")
        Fixture.desktopCompletion?(fails ? .failure(Failure(description: "Synthetic launch failure")) : .success(()))
        if fails {
            if case .failure? = result {} else { throw Failure(description: "Desktop launch failure was not reported") }
        } else {
            if case .success? = result {} else { throw Failure(description: "Desktop switch did not complete") }
        }
        try expect((try String(contentsOf: pointer)) == (fails ? "/previous/cli/profile\n" : "\n"),
                   "Enabling CLI switching during launch did not honor the launch result")
    }

    @MainActor
    private static func claudeRemoveDuringRenewal(pending: Bool, denied: Bool = false, readded: Bool = false) async throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        Fixture.discoveredClaudeService = service
        Fixture.expectedOAuthDirectory = profile
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .heldRenewed
        Fixture.failKeychainSave = pending
        Fixture.denyKeychainDelete = denied
        let provider = ClaudeProvider()
        let store = UsageStore(providers: [.claude: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "Fixture did not discover the removable Claude profile")
        let renewal = Task { await provider.fetch(account) }
        var started = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            started = Fixture.refreshCalls > 0
            Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(started, "Fixture did not start the refresh POST")
        if pending {
            Fixture.releaseRefresh()
            try await waitForFailedSave()
        }
        var removalFailed = false
        do { try store.removeAccount(id: account.id) } catch { removalFailed = true }
        try expect(removalFailed == denied, "Account removal did not honor the Keychain deletion result")
        if readded {
            try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
            Fixture.lock.lock()
            Fixture.keychainExists = true
            Fixture.keychain = Fixture.claudeLogin("readded-login", expired: false)
            Fixture.lock.unlock()
        }
        Fixture.releaseRefresh()
        Fixture.lock.lock()
        Fixture.failKeychainSave = false
        Fixture.lock.unlock()
        _ = await renewal.value
        if readded {
            let outcome = await provider.fetch(account)
            if case .success = outcome {} else { throw Failure(description: "A removed service could not be used after a new login") }
            try expect(Fixture.lastAuthorization == "Bearer synthetic-readded-login", "Late renewal replaced the newly re-added login")
        }
        let ready = await provider.prepareForTermination(timeout: 0.5)
        try expect(ready, "A deleted Claude profile permanently blocked normal termination")
        try expect(Fixture.refreshCalls == 1, "Removal started another refresh POST")
        if denied {
            try expect(Fixture.keychainExists && ClaudeKeychain.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated",
                       "Failed deletion discarded the pending rotated grant")
        } else if !readded {
            try expect(!Fixture.keychainExists && !Foundation.FileManager.default.fileExists(atPath: profile.path),
                       "Late renewal resurrected the removed account or profile")
        }
    }

    @MainActor
    private static func claudeReaddInFlight(expired: Bool) async throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        Fixture.expectedOAuthDirectory = profile
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .heldRenewed
        let provider = ClaudeProvider()
        let old = Task { await provider.fetch(account) }
        var started = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            started = Fixture.refreshCalls > 0
            Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(started, "Old refresh did not reach the held HTTP boundary")
        try AccountRemoval.remove(account)
        await provider.accountRemoved(account)
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        Fixture.lock.lock()
        Fixture.keychainExists = true
        Fixture.keychain = Fixture.claudeLogin("readded-login", expired: expired)
        Fixture.lock.unlock()
        Task {
            try? await Task.sleep(nanoseconds: 200_000_000)
            Fixture.releaseRefresh()
        }
        async let first = provider.fetch(account)
        async let second = provider.fetch(account)
        let outcomes = await [first, second]
        _ = await old.value
        let retry = await provider.fetch(account)
        if case .success = retry {} else { throw Failure(description: "Replacement login control failed") }
        try expect(Fixture.refreshCalls == (expired ? 2 : 1), "Replacement login duplicated or skipped its refresh")
        try expect(ClaudeKeychain.parse(Fixture.keychain)?.refreshToken == (expired ? "synthetic-rotated" : "synthetic-refresh-readded-login"),
                   "Late old response changed replacement credentials")
        if expired {
            try expect(Fixture.refreshInput == "synthetic-refresh-readded-login", "Replacement renewed the removed login")
        } else {
            try expect(Fixture.lastAuthorization == "Bearer synthetic-readded-login", "Replacement did not use its new login")
        }
        for outcome in outcomes {
            if case .success = outcome {} else {
                throw Failure(description: "Replacement login inherited the removed generation's inFlight failure")
            }
        }
    }

    @MainActor
    private static func claudeRemoveDuringSave() async throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        Fixture.discoveredClaudeService = service
        Fixture.expectedOAuthDirectory = profile
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .heldRenewed
        let provider = ClaudeProvider()
        let store = UsageStore(providers: [.claude: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        let renewal = Task { await provider.fetch(account) }
        var started = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            started = Fixture.refreshCalls > 0
            Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(started, "Refresh did not reach the held HTTP boundary")
        Fixture.lock.lock()
        Fixture.pauseProfileSnapshot = true
        Fixture.lock.unlock()
        defer {
            Fixture.lock.lock()
            Fixture.resumeProfileSnapshot = true
            Fixture.lock.unlock()
        }
        Fixture.releaseRefresh()
        var paused = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            paused = Fixture.profileSnapshotPaused
            Fixture.lock.unlock()
            if paused { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(paused, "Save did not reach its directory resolution boundary")
        try store.removeAccount(id: account.id)
        try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Removal itself left the directory behind")
        Fixture.lock.lock()
        Fixture.resumeProfileSnapshot = true
        Fixture.lock.unlock()
        _ = await renewal.value
        let ready = await provider.prepareForTermination(timeout: 0.5)
        try expect(!Fixture.keychainExists && ready, "Deletion did not clear pending credentials")
        try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path),
                   "An already-started save recreated the successfully removed profile directory")
    }

    @MainActor
    private static func claudeRemovableProfile() throws -> (URL, DiscoveredAccount) {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        Fixture.discoveredClaudeService = service
        Fixture.expectedOAuthDirectory = profile
        return (profile, account)
    }

    @MainActor
    private static func claudeRemoveDuringOAuthLock() async throws {
        let (profile, account) = try claudeRemovableProfile()
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        let provider = ClaudeProvider()
        let store = UsageStore(providers: [.claude: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        Fixture.pauseProfileSnapshot = true
        let renewal = Task { await provider.fetch(account) }
        var paused = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            paused = Fixture.profileSnapshotPaused
            Fixture.lock.unlock()
            if paused { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        defer {
            Fixture.lock.lock()
            Fixture.resumeProfileSnapshot = true
            Fixture.lock.unlock()
        }
        try expect(paused, "OAuth acquisition did not reach directory resolution")
        try store.removeAccount(id: account.id)
        try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Removal itself did not remove profile")
        await provider.accountRemoved(account)
        Fixture.lock.lock()
        Fixture.resumeProfileSnapshot = true
        Fixture.lock.unlock()
        _ = await renewal.value
        try expect(Fixture.refreshCalls == 0 && !Fixture.keychainExists, "Deletion did not stop renewal")
        try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path),
                   "OAuth lock acquisition recreated a successfully removed extra profile")
    }

    @MainActor
    private static func claudeRemoveStagedCLI(primary: Bool = false, enabled: Bool = true, denied: Bool = false, readded: Bool = false) throws {
        let profile: URL?
        let account: DiscoveredAccount
        if primary {
            profile = nil
            Fixture.discoveredClaudeService = Fixture.service
            account = DiscoveredAccount(id: "claude:" + Fixture.service, provider: .claude, profileName: "main",
                                        source: .claudeKeychain(service: Fixture.service, configDir: nil))
        } else {
            (profile, account) = try claudeRemovableProfile()
        }
        if !enabled { ClaudeCLISelection.isEnabled = false }
        let previous = Fixture.root.appendingPathComponent("previous-cli")
        try Foundation.FileManager.default.createDirectory(at: previous, withIntermediateDirectories: true)
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = previous.path + "\n"
        try Data(original.utf8).write(to: pointer)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.denyKeychainDelete = denied
        let store = UsageStore(providers: [.claude: ClaudeProvider()], discovery: RealDiscovery())
        store.rediscover(force: true)
        Fixture.holdDesktopCompletion = true
        var result: Result<Void, Error>?
        ClaudeAppSwitcher().switchTo(account) { result = $0 }
        try expect(Fixture.desktopCompletion != nil, "Desktop launch was not held")
        try expect(try String(contentsOf: pointer) == original, "Staging changed CLI selection before launch")
        let launchedDirectory = try desktopDirectory(Fixture.desktopArguments)
        var removalFailed = false
        do { try store.removeAccount(id: account.id) } catch { removalFailed = true }
        try expect(removalFailed == denied && Fixture.keychainExists == denied, "Removal did not honor the deletion result")
        if let profile {
            try expect(Foundation.FileManager.default.fileExists(atPath: profile.path) == denied,
                       "Removal did not preserve only the undeleted profile")
        }
        if readded {
            if let profile { try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true) }
            Fixture.keychain = Fixture.claudeLogin("replacement-login", expired: false)
            Fixture.keychainExists = true
            store.rediscover(force: true)
        }
        let secretReads = Fixture.keychainReads
        Fixture.desktopCompletion?(.success(()))
        let selected = try String(contentsOf: pointer)
        let expected = enabled && denied ? (profile?.path ?? "") + "\n" : original
        try expect(selected == expected, "Desktop completion published a deleted CLI target over the previous valid selection")
        if enabled && !denied {
            if case .failure? = result {} else { throw Failure(description: "Deleted CLI target was reported as a successful switch") }
        } else {
            if case .success? = result {} else { throw Failure(description: "Desktop-only or undeleted target could not complete its switch") }
        }
        try expect(Fixture.keychainReads == secretReads, "CLI validation read the secret instead of checking attributes")
        try expect(UserDefaults.standard.string(forKey: "currentClaudeAppAccount") == launchedDirectory.lastPathComponent,
                   "Successful Desktop launch lost the marker for its actual data directory")
        if readded {
            try expect(ClaudeAppSwitcher().isOpenInApp(columnID: account.id) == false,
                       "A launch prepared for the removed account marked its replacement as open")
        }
    }

    @MainActor
    private static func claudeStaleUsageResult() async throws {
        let (profile, account) = try claudeRemovableProfile()
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.holdFirstUsage = true
        let provider = ClaudeProvider()
        let store = UsageStore(providers: [.claude: provider], discovery: RealDiscovery())
        store.rediscover(force: true)
        store.refreshAll(force: true)
        var started = false
        for _ in 0..<200 {
            Fixture.lock.lock()
            started = Fixture.usageCalls == 1
            Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(started, "Old usage request did not start")
        try store.removeAccount(id: account.id)
        await provider.accountRemoved(account)
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        Fixture.lock.lock()
        Fixture.keychainExists = true
        Fixture.keychain = Fixture.claudeLogin("readded-login", expired: false)
        Fixture.lock.unlock()
        store.rediscover(force: true)
        store.refreshAll(force: true)
        var fresh = false
        for _ in 0..<200 {
            fresh = store.columns.first { $0.id == account.id }?.windows.first?.utilization == 84
            if fresh { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(fresh, "Replacement usage did not complete before old reply")
        var staleObserved = false
        let observation = store.$columns.sink { columns in
            if columns.first(where: { $0.id == account.id })?.windows.first?.utilization == 12 { staleObserved = true }
        }
        defer { observation.cancel() }
        Fixture.lock.lock()
        Fixture.releaseFirstUsage = true
        Fixture.lock.unlock()
        for _ in 0..<100 {
            if staleObserved { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try expect(Fixture.usageCompletions == 2, "Old usage reply did not complete after release")
        try expect(!staleObserved, "Old usage reply overwrote the replacement account's fresh column")
        try expect(UsageCache().load(id: account.id)?.windows.first?.utilization == 84,
                   "Old usage reply overwrote the replacement account's persistent cache")
    }

    @MainActor
    private static func claudeRemoveUnmapped() throws {
        let service = Fixture.service + "-unmapped"
        Fixture.discoveredClaudeService = service
        Fixture.keychain = Fixture.claudeLogin("unmapped-login", expired: false)
        let store = UsageStore(providers: [.claude: ClaudeProvider()], discovery: RealDiscovery())
        store.rediscover(force: true)
        var failed = false
        do { try store.removeAccount(id: "claude:" + service) } catch { failed = true }
        try expect(failed && Fixture.keychainExists && store.account(for: "claude:" + service) != nil,
                   "Unmapped profile deletion bypassed the native mutation locks")
    }

    @MainActor
    private static func claudeRemoveNativeWriter(primary: Bool = true, lockKind: String = "all") throws {
        let profile: URL?
        let account: DiscoveredAccount
        if primary {
            profile = nil
            Fixture.discoveredClaudeService = Fixture.service
            account = DiscoveredAccount(id: "claude:" + Fixture.service, provider: .claude, profileName: "main",
                                        source: .claudeKeychain(service: Fixture.service, configDir: nil))
        } else {
            (profile, account) = try claudeRemovableProfile()
        }
        Fixture.keychain = Fixture.claudeLogin("native-original", expired: true)
        try Foundation.FileManager.default.createDirectory(at: Fixture.oauthDirectory, withIntermediateDirectories: true)
        let storage = Fixture.oauthDirectory.appendingPathComponent(".storage-write.lock").path
        let locks = lockKind == "legacy" ? [Fixture.legacyLock.path]
            : lockKind == "storage" ? [storage] : [Fixture.oauthLock.path, Fixture.legacyLock.path, storage]
        for path in locks { try expect(path.withCString { Darwin.mkdir($0, 0o700) } == 0, "Could not acquire native writer lease") }
        defer { for path in locks.reversed() { _ = path.withCString { Darwin.rmdir($0) } } }
        // Native secureStorage.mutate has passed its token comparison. Its backend
        // will complete the already-prepared security add-generic-password -U.
        let prepared = Fixture.claudeLogin("native-renewed", expired: false)
        let store = UsageStore(providers: [.claude: ClaudeProvider()], discovery: RealDiscovery())
        store.rediscover(force: true)
        var removed = false
        do { try store.removeAccount(id: account.id); removed = true } catch {}
        let preserved = Fixture.keychainExists && store.account(for: account.id) != nil
        let leaseIntact = locks.allSatisfy { Foundation.FileManager.default.fileExists(atPath: $0) }
        Fixture.keychain = prepared
        Fixture.keychainExists = true
        store.rediscover(force: true)
        try expect(!removed && preserved && leaseIntact,
                   "Removal reported success inside a native mutation that can recreate the deleted account")
        try expect(store.account(for: account.id) != nil, "Busy deletion hid the account instead of allowing retry")
        for path in locks.reversed() { try expect(path.withCString { Darwin.rmdir($0) } == 0, "Native writer lost its lease") }
        try store.removeAccount(id: account.id)
        store.rediscover(force: true)
        try expect(!Fixture.keychainExists && store.account(for: account.id) == nil,
                   "Deletion did not succeed after the native writer completed")
        if let profile {
            try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Retry retained the removed extra profile")
        } else {
            try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageDirectory.path), "Deletion removed main CLI config")
        }
    }

    private static func claudeRecoveryReplacement() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.replaceMarkedOwnerAfterRead = true
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(Fixture.markedOwnerReplacementObserved, "Native contender did not replace both marked directories")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path)
                   && Foundation.FileManager.default.fileExists(atPath: Fixture.legacyLock.path),
                   "Recovery removed a new native owner using the abandoned directory's cached marker")
        try expect(Fixture.refreshCalls == 0, "Recovery refreshed after losing the native lock paths")
    }

    private static func desktopDirectory(_ arguments: [String]) throws -> URL {
        let prefix = "--user-data-dir="
        guard let argument = arguments.first(where: { $0.hasPrefix(prefix) }) else {
            throw Failure(description: "Desktop launch did not specify its data directory")
        }
        return URL(fileURLWithPath: String(argument.dropFirst(prefix.count)), isDirectory: true)
    }

    @MainActor
    private static func claudeReaddedDesktop(enabled: Bool = true, primary: Bool = false, denied: Bool = false) throws {
        let profile: URL?
        let account: DiscoveredAccount
        if primary {
            profile = nil
            Fixture.discoveredClaudeService = Fixture.service
            account = DiscoveredAccount(id: "claude:" + Fixture.service, provider: .claude, profileName: "main",
                                        source: .claudeKeychain(service: Fixture.service, configDir: nil))
        } else {
            (profile, account) = try claudeRemovableProfile()
        }
        if !enabled { ClaudeCLISelection.isEnabled = false }
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = Fixture.root.appendingPathComponent("previous-cli").path + "\n"
        try Data(original.utf8).write(to: pointer)
        Fixture.keychain = Fixture.claudeLogin("account-a", expired: false)
        let first = try switchSuccessfully(account)
        let directory = try desktopDirectory(first.arguments)
        let session = directory.appendingPathComponent("synthetic-session-marker")
        try Data("account-a".utf8).write(to: session)
        let unrelated = directory.deletingLastPathComponent().appendingPathComponent("another-account")
        try Data("other".utf8).write(to: unrelated)
        let store = UsageStore(providers: [.claude: ClaudeProvider()], discovery: RealDiscovery())
        store.rediscover(force: true)
        Fixture.denyKeychainDelete = denied
        var failed = false
        do { try store.removeAccount(id: account.id) } catch { failed = true }
        try expect(failed == denied && Fixture.keychainExists == denied, "Deletion did not honor its Keychain result")
        if denied {
            let second = try switchSuccessfully(account)
            try expect(second.arguments == first.arguments && (try String(contentsOf: session)) == "account-a",
                       "Failed deletion retired a live Desktop session")
            return
        }
        try expect(!Foundation.FileManager.default.fileExists(atPath: session.path), "Successful deletion retained Desktop session data")
        // An old Desktop process may recreate its former data directory after removal.
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("account-a".utf8).write(to: session)
        if let profile { try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true) }
        Fixture.keychain = Fixture.claudeLogin("account-b", expired: false)
        Fixture.keychainExists = true
        try expect(ClaudeAppSwitcher().isOpenInApp(columnID: account.id) == false,
                   "The retired Desktop session was shown as the re-added account")
        let second = try switchSuccessfully(account)
        let replacement = try desktopDirectory(second.arguments)
        try expect(replacement != directory && !Foundation.FileManager.default.fileExists(atPath: replacement.appendingPathComponent(session.lastPathComponent).path),
                   "Re-added account reused the removed Desktop session, including writes from an old process")
        try expect(try String(contentsOf: pointer) == (enabled ? (profile?.path ?? "") + "\n" : original),
                   "Re-added Desktop switch did not respect Switch CLI")
        try expect(try String(contentsOf: unrelated) == "other", "Deletion changed another Desktop account")
        try expect(ClaudeAppSwitcher().isOpenInApp(columnID: account.id) == true, "Replacement Desktop was not marked open")
    }

    private static func claudeNativePublish() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.nativeAcquisitionAtPublish = true
        _ = await ClaudeProvider().fetch(Fixture.claudeAccount)
        try expect(Fixture.nativeAcquisitionObserved, "Fixture did not acquire the native path before publication")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path), "Publication replaced the native owner's lock")
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0, "A competing native owner did not defer renewal")
    }

    private static func claudeCrashLegacyOwner() throws {
        guard let lease = ClaudeKeychain.refreshLock(service: Fixture.service) else {
            throw Failure(description: "Could not acquire fixture OAuth locks")
        }
        withExtendedLifetime(lease) {
            for path in [Fixture.oauthLock.path, Fixture.legacyLock.path] {
                _ = removexattr(path, "dev.ustinoff.notchlimits.lock-owner", XATTR_NOFOLLOW)
                var info = stat()
                guard lstat(path, &info) == 0 else { _exit(1) }
                let record: [String: Any] = ["inode": UInt64(info.st_ino), "device": info.st_dev,
                                           "birthSeconds": Int64(info.st_birthtimespec.tv_sec),
                                           "birthNanoseconds": Int64(info.st_birthtimespec.tv_nsec)]
                do {
                    try JSONSerialization.data(withJSONObject: record)
                        .write(to: URL(fileURLWithPath: path + ".notchlimits-owner"))
                } catch { _exit(1) }
            }
            _exit(0)
        }
    }

    private static func claudeCrashOwner(live: Bool) throws {
        guard let lease = ClaudeKeychain.refreshLock(service: Fixture.service) else {
            throw Failure(description: "Could not acquire fixture OAuth locks")
        }
        withExtendedLifetime(lease) {
            FileHandle.standardOutput.write(Data("READY\n".utf8))
            if live { _ = FileHandle.standardInput.readData(ofLength: 1) }
            _exit(0) // Simulate abrupt process death without releasing the directories.
        }
    }

    private static func claudeRecoverOwner(expectBusy: Bool) async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if expectBusy {
            try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0, "Recovery stole an active or replacement owner's lock")
            try expect(Fixture.holdsOAuthLocks, "Busy owner lost its OAuth locks")
        } else {
            if case .success = outcome {} else { throw Failure(description: "Abandoned Notchlimits OAuth locks permanently blocked renewal") }
            try expect(Fixture.refreshCalls == 1, "Recovered profile did not renew exactly once")
            try expect(!Fixture.holdsOAuthLocks, "Recovered OAuth locks were not released")
        }
    }

    private static func claudeUnsupportedCLI() async throws {
        Fixture.cliVersion = "2.0.0"
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        let outcome = await ClaudeProvider().fetch(Fixture.claudeAccount)
        if case .reauth = outcome {} else { throw Failure(description: "Unsupported CLI did not defer renewal to CLI login") }
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0,
                   "Unsupported CLI's credentials were renewed or written without a shared protocol")
    }
}
