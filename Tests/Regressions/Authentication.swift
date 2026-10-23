import Foundation
import Combine
import AppKit
import Security
import Darwin
import CryptoKit

// Only OS/network boundaries are replaced. Providers, discovery, auth swaps and
// removal are compiled from their unmodified production source files.
private enum Fixture {
    static var manualPollingTimer = false
    static var pollingTick: (() -> Void)?

    static let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    static let service = "Claude Code-credentials"
    static let lock = NSLock()
    static var keychain: [String: Any] = [:]
    static var keychainWrites = 0
    static var codexKeychain: [String: Data] = [:]
    static var denyCodexRead = false
    static var denyClaudeMetadata = false
    static var denyClaudeRead = false
    static var denyClaudeReadAt = 0
    static var malformedClaudeRead = false
    static var codexHome: String?
    static var denyCredentialChmodHome: String?
    static var failCodexFileWrite = false
    static var beforeCredentialDelete: (() -> Void)?
    static var rejectSpentRefresh = false
    static var pauseAuthReadPath: String?
    static var authReadPaused = false
    static var releaseAuthRead = false
    static var authSwitchCompleted = false
    static var lastCodexAccount = ""
    static var denyCodexWrite = false
    static var denyCodexWriteAccount: String?
    static var denyCodexDeleteAccount: String?
    static var denyCodexDelete = false
    static var denyCredentialFileRemovalPath: String?
    static var denyCredentialFileRemoval = false
    static var denyProfileRemoval: String?
    static var denyProfileMove = false
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
    static var claudeMetadataDate: Date?
    static var preserveClaudeMetadataDate = false
    static var noninteractiveClaudeReads = 0
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
    static var firstUsageStatus = 200
    static var usageErrorBody: Data?
    static var usageStatus = 200
    static var replaceOAuthDuringPOST = false
    static var loginBeforeOAuth = false
    static var refreshInput = ""
    static var loginAtWriteBoundary = false
    static var cliClearedRevokedGrant = false
    static var desktopFails = false
    static var holdDesktopCompletion = false
    static var desktopCalls = 0
    static var desktopStops = 0
    static var desktopRunning = false
    static var desktopRefusesQuit = false
    static var holdDesktopStop = false
    static var desktopArguments: [String] = []
    static var claudeEntries: [String: [String: Any]]?
    static var onlyClaudeService: String?
    static var keychainExists = true
    static var denyKeychainDelete = false
    static var slowKeychainDelete = false
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
    @MainActor static var desktopStopCompletion: ((Result<Void, Error>) -> Void)?

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
        if AuthStorage$Claude.parse(keychain)?.refreshToken == "synthetic-refresh-old-login" {
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

    enum Response { case renewed, lost, temporary, unreadable, delayedLost, changedClaude, nativeLogin, forbidden, delayedRenewed, slowRenewed, heldRenewed, heldTemporary, heldLost, heldRejected }
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
        // Independent native contract: Rust canonicalize uses realpath on macOS.
        let path: String
        if let canonical = home.path.withCString({ realpath($0, nil) }) {
            path = String(cString: canonical)
            free(canonical)
        } else { path = home.path }
        let hash = SHA256.hash(data: Data(path.utf8))
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
        if let denied = Fixture.denyProfileRemoval,
           url.path == denied || url.lastPathComponent.hasPrefix(".removed-") {
            throw CocoaError(.fileWriteNoPermission)
        }
        if url.path == Fixture.denyCredentialFileRemovalPath { throw CocoaError(.fileWriteNoPermission) }
        if Fixture.denyCredentialFileRemoval && ["auth.json", ".credentials.json"].contains(url.lastPathComponent) {
            throw CocoaError(.fileWriteNoPermission)
        }
        try super.removeItem(at: url)
    }

    override func moveItem(at srcURL: URL, to dstURL: URL) throws {
        if Fixture.denyProfileMove && srcURL.path == Fixture.denyProfileRemoval {
            throw CocoaError(.fileWriteNoPermission)
        }
        try super.moveItem(at: srcURL, to: dstURL)
    }


    override func setAttributes(_ attributes: [FileAttributeKey: Any], ofItemAtPath path: String) throws {
        if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix(".auth-") {
            throw CocoaError(.fileWriteNoPermission)
        }
        if URL(fileURLWithPath: path).deletingLastPathComponent().path == Fixture.denyCredentialChmodHome {
            throw CocoaError(.fileWriteNoPermission)
        }
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
    override func fileExists(atPath path: String) -> Bool {
        let exists = super.fileExists(atPath: configPath(path))
        if path == Fixture.pauseAuthReadPath {
            Fixture.lock.lock()
            Fixture.pauseAuthReadPath = nil
            Fixture.authReadPaused = true
            Fixture.lock.unlock()
            while true {
                Fixture.lock.lock()
                let released = Fixture.releaseAuthRead
                Fixture.lock.unlock()
                if released { break }
                Thread.sleep(forTimeInterval: 0.005)
            }
        }
        return exists
    }
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
            var overrides = ["SHELL": Fixture.shell]
            if let home = Fixture.codexHome { overrides["CODEX_HOME"] = home }
            return Foundation.ProcessInfo.processInfo.environment.filter {
                !["CODEX_HOME", "ZDOTDIR"].contains($0.key)
            }.merging(overrides) { _, fixture in fixture }
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
    static func isRunning(bundleID: String) -> Bool { Fixture.desktopRunning }
    @MainActor static func stop(bundleID: String, appName: String,
                               completion: @escaping (Result<Void, Error>) -> Void) {
        Fixture.desktopStops += 1
        if Fixture.holdDesktopStop { Fixture.desktopStopCompletion = completion; return }
        if Fixture.desktopRefusesQuit {
            completion(.failure(Failure(description: "Synthetic Desktop refused quit")))
        } else {
            Fixture.desktopRunning = false
            completion(.success(()))
        }
    }
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
    if Fixture.denyClaudeMetadata, (query as NSDictionary)[kSecAttrService as String] == nil {
        return errSecInteractionNotAllowed
    }
    if let entries = Fixture.claudeEntries {
        if let service = (query as NSDictionary)[kSecAttrService as String] as? String {
            guard let json = entries[service] else { return errSecItemNotFound }
            if (query as NSDictionary)[kSecReturnData as String] as? Bool == true {
                guard !Fixture.denyClaudeRead else { return errSecInteractionNotAllowed }
                result?.pointee = try! JSONSerialization.data(withJSONObject: json) as CFData
            } else { result?.pointee = [kSecAttrService as String: service] as NSDictionary }
        } else { result?.pointee = entries.keys.map { [kSecAttrService as String: $0] } as NSArray }
        return errSecSuccess
    }
    if let only = Fixture.onlyClaudeService,
       let service = (query as NSDictionary)[kSecAttrService as String] as? String,
       service != only { return errSecItemNotFound }
    if (query as NSDictionary)[kSecReturnAttributes as String] as? Bool == true {
        if let service = (query as NSDictionary)[kSecAttrService as String] as? String {
            guard Fixture.keychainExists else { return errSecItemNotFound }
            result?.pointee = [kSecAttrService as String: service] as NSDictionary
            return errSecSuccess
        }
        if Fixture.keychainExists, let service = Fixture.discoveredClaudeService {
            var attributes: [String: Any] = [kSecAttrService as String: service]
            if let modified = Fixture.claudeMetadataDate { attributes[kSecAttrModificationDate as String] = modified }
            result?.pointee = [attributes] as NSArray
        } else { result?.pointee = NSArray() }
    } else {
        guard Fixture.keychainExists else { return errSecItemNotFound }
        Fixture.keychainReads += 1
        if !Fixture.interactionAllowed { Fixture.noninteractiveClaudeReads += 1 }
        if Fixture.denyClaudeRead || Fixture.keychainReads == Fixture.denyClaudeReadAt {
            return errSecInteractionNotAllowed
        }
        if Fixture.malformedClaudeRead { result?.pointee = Data("invalid-json".utf8) as CFData; return errSecSuccess }
        let data = try! JSONSerialization.data(withJSONObject: Fixture.keychain)
        if Fixture.slowKeychainRead { Thread.sleep(forTimeInterval: 6.5) }
        if Fixture.keychainReads == Fixture.changeLoginAfterRead {
            Fixture.tryCLILogin()
            if Fixture.claudeMetadataDate != nil && !Fixture.preserveClaudeMetadataDate {
                Fixture.claudeMetadataDate = Date(timeIntervalSince1970: 2)
            }
        }
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
        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }
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
    let boundary = Fixture.beforeCredentialDelete
    Fixture.beforeCredentialDelete = nil
    boundary?()
    Fixture.lock.lock()
    defer { Fixture.lock.unlock() }
    if Fixture.slowKeychainDelete { Thread.sleep(forTimeInterval: 6) }
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        guard !Fixture.denyCodexDelete else { return errSecAuthFailed }
        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String
        guard key != Fixture.denyCodexDeleteAccount else { return errSecAuthFailed }
        Fixture.codexKeychain[key] = nil
        return errSecSuccess
    }
    guard !Fixture.denyKeychainDelete else { return errSecAuthFailed }
    if var entries = Fixture.claudeEntries, let service = (query as NSDictionary)[kSecAttrService as String] as? String {
        entries[service] = nil
        Fixture.claudeEntries = entries
        return errSecSuccess
    }
    Fixture.keychainExists = false
    return errSecSuccess
}
func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    if (attributes as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        let key = (attributes as NSDictionary)[kSecAttrAccount as String] as! String
        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }
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
        if Fixture.rejectSpentRefresh && Fixture.refreshInput == "synthetic-already-spent" {
            return .success(Response(status: 400, data: Data(#"{"error":"refresh_token_reused"}"#.utf8), retryAfter: nil))
        }
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
        case .heldTemporary, .heldLost, .heldRejected:
            while Fixture.refreshIsPaused() { try? await Task.sleep(nanoseconds: 10_000_000) }
            switch Fixture.response {
            case .heldTemporary: return .success(Response(status: 429, data: Data(), retryAfter: 120))
            case .heldLost: return .failure(.transport("synthetic lost response"))
            default: return .success(Response(status: 400, data: Data(#"{"error":"refresh_token_reused"}"#.utf8), retryAfter: nil))
            }
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
            let utilization = first ? 12 : 84
            let data = try! JSONSerialization.data(withJSONObject: [
                "five_hour": ["utilization": utilization],
                "rate_limit": ["primary_window": ["used_percent": utilization, "limit_window_seconds": 18000]]
            ])
            Fixture.lock.lock()
            Fixture.usageCompletions += 1
            Fixture.lock.unlock()
            return .success(Response(status: first ? Fixture.firstUsageStatus : 200, data: data, retryAfter: nil))
        }
        Fixture.lastAuthorization = headers["Authorization"] ?? ""
        Fixture.lastCodexAccount = headers["ChatGPT-Account-ID"] ?? ""
        let data = Data(#"{"five_hour":{"utilization":12},"rate_limit":{"primary_window":{"used_percent":12,"limit_window_seconds":18000}}}"#.utf8)
        return .success(Response(status: Fixture.usageStatus, data: Fixture.usageErrorBody ?? data, retryAfter: nil))
    }
}

private struct Failure: Error, CustomStringConvertible { let description: String }
private func expect(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(description: message) }
}

// Control the scheduler's OS timer without replacing UsageStore.pump or its clock.
// Existing scenarios retain the normal Foundation timer boundary.
final class Timer {
    private var native: Foundation.Timer?

    static func scheduledTimer(withTimeInterval interval: TimeInterval, repeats: Bool,
                               block: @escaping (Timer) -> Void) -> Timer {
        let timer = Timer()
        if Fixture.manualPollingTimer {
            Fixture.pollingTick = { block(timer) }
        } else {
            timer.native = Foundation.Timer.scheduledTimer(withTimeInterval: interval, repeats: repeats) { [weak timer] _ in
                if let timer { block(timer) }
            }
        }
        return timer
    }

    deinit { native?.invalidate() }
}

// Count real provider calls; all token resolution, HTTP handling and store
// scheduling still run through their unmodified production implementations.
private actor ClaudePollingProbe: UsageProvider {
    private let provider = Provider$Claude()
    private var started = 0
    private var completed = 0

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        started += 1
        let result = await provider.fetch(account)
        completed += 1
        return result
    }

    func counts() -> (started: Int, completed: Int) { (started, completed) }
}

// Observe completion of the real provider without replacing its implementation.
private actor UsageCompletionProbe: UsageProvider {
    let provider: any UsageProvider
    private(set) var completed = 0
    init(_ provider: any UsageProvider) { self.provider = provider }
    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        let result = await provider.fetch(account)
        completed += 1
        return result
    }
}

@main
enum Authentication {
    static func main() async {
        do {
            switch CommandLine.arguments[1] {
            case "codex-shared-directory-file": try codexSharedDirectoryRemoval()
            case "codex-shared-directory-selected": try codexSharedDirectoryRemoval(selected: true)
            case "codex-shared-directory-keyring": try codexSharedDirectoryRemoval(peerBackend: "keyring")
            case "codex-separate-directory-file-control": try codexSharedDirectoryRemoval(alias: false)
            case "codex-separate-directory-keyring-control": try codexSharedDirectoryRemoval(peerBackend: "keyring", alias: false, selected: true)

            case "codex-shared-file-remove": try await codexSharedFallback(action: "remove", physicalAlias: true)
            case "codex-shared-file-remove-separate-control": try await codexSharedFallback(action: "remove", physicalAlias: false)
            case "codex-shared-file-copyback": try await codexSharedFallback(action: "copyback", physicalAlias: true)
            case "codex-shared-file-copyback-separate-control": try await codexSharedFallback(action: "copyback", physicalAlias: false)
            case "codex-shared-file-renew": try await codexSharedFallback(action: "renew", physicalAlias: true)
            case "codex-shared-file-renew-separate-control": try await codexSharedFallback(action: "renew", physicalAlias: false)
            case "codex-backup-recovery-file-restore": try await codexBackupRecovery(mode: "file", action: "restore")
            case "codex-backup-recovery-file-renew": try await codexBackupRecovery(mode: "file", action: "renew")
            case "codex-backup-recovery-file-control": try await codexBackupRecovery(mode: "file", fails: false)
            case "codex-backup-recovery-keyring-restore": try await codexBackupRecovery(mode: "keyring", action: "restore")
            case "codex-backup-recovery-keyring-renew": try await codexBackupRecovery(mode: "keyring", action: "renew")
            case "codex-backup-recovery-keyring-control": try await codexBackupRecovery(mode: "keyring", fails: false)
            case "codex-backup-recovery-readd": try await codexBackupRecovery(action: "readd")
            case "codex-usage-snapshot-file-login": try await usageLoginSnapshot(codex: true, backend: "file", change: "login")
            case "codex-usage-snapshot-file-none": try await usageLoginSnapshot(codex: true, backend: "file", change: "none")
            case "codex-usage-snapshot-keyring-login": try await usageLoginSnapshot(codex: true, backend: "keyring", change: "login")
            case "codex-usage-snapshot-keyring-none": try await usageLoginSnapshot(codex: true, backend: "keyring", change: "none")
            case "codex-usage-snapshot-auto-login": try await usageLoginSnapshot(codex: true, backend: "auto", change: "login")
            case "codex-usage-snapshot-auto-none": try await usageLoginSnapshot(codex: true, backend: "auto", change: "none")
            case "claude-usage-snapshot-keychain-login": try await usageLoginSnapshot(codex: false, backend: "keychain", change: "login")
            case "claude-usage-snapshot-keychain-none": try await usageLoginSnapshot(codex: false, backend: "keychain", change: "none")
            case "claude-usage-snapshot-file-login": try await usageLoginSnapshot(codex: false, backend: "file", change: "login")
            case "claude-usage-snapshot-file-none": try await usageLoginSnapshot(codex: false, backend: "file", change: "none")
            case "codex-usage-snapshot-metadata-control": try await usageLoginSnapshot(codex: true, backend: "file", change: "metadata")
            case "codex-usage-snapshot-retired-401": try await usageLoginSnapshot(codex: true, backend: "file", status: 401)
            case "codex-usage-snapshot-retired-429": try await usageLoginSnapshot(codex: true, backend: "file", status: 429)
            case "codex-usage-snapshot-unreadable": try await usageLoginSnapshot(codex: true, backend: "auto", change: "unreadable")
            case "claude-usage-snapshot-metadata-control": try await usageLoginSnapshot(codex: false, backend: "keychain", change: "metadata")
            case "claude-usage-snapshot-retired-401": try await usageLoginSnapshot(codex: false, backend: "keychain", status: 401)
            case "claude-usage-snapshot-retired-429": try await usageLoginSnapshot(codex: false, backend: "keychain", status: 429)
            case "claude-usage-snapshot-unreadable": try await usageLoginSnapshot(codex: false, backend: "keychain", change: "unreadable")

            case "codex-clone-copyback-pending-poll": try await codexCopiedGrantRetry(poll: true)
            case "codex-clone-copyback-native-logout": try await codexCopiedGrantRetry(replacement: "native-missing")
            case "codex-clone-copyback-retry": try await codexCopiedGrantRetry()
            case "codex-clone-copyback-independent-control": try await codexCopiedGrantRetry(distinct: true)
            case "codex-clone-copyback-new-backup": try await codexCopiedGrantRetry(replacement: "backup")
            case "codex-clone-copyback-new-profile": try await codexCopiedGrantRetry(replacement: "profile")
            case "codex-mixed-auto-activation-file": try codexMixedAutoActivation()
            case "codex-mixed-auto-activation-keyring-control": try codexMixedAutoActivation(fileOwner: false)
            case "codex-native-rotation-file-copied-restore": try await codexCopiedGrantNativeRotation(mode: "file", distinct: false)
            case "codex-native-rotation-file-independent-control": try await codexCopiedGrantNativeRotation(mode: "file", distinct: true)
            case "codex-native-rotation-keyring-copied-restore": try await codexCopiedGrantNativeRotation(mode: "keyring", distinct: false)
            case "codex-native-rotation-keyring-independent-control": try await codexCopiedGrantNativeRotation(mode: "keyring", distinct: true)
            case "codex-native-rotation-auto-copied-restore": try await codexCopiedGrantNativeRotation(mode: "auto", distinct: false)
            case "codex-native-rotation-auto-independent-control": try await codexCopiedGrantNativeRotation(mode: "auto", distinct: true)
            case "codex-native-rotation-copied-poll": try await codexCopiedGrantNativeRotation(poll: true)
            case "codex-firmlink-mixed-auto-selected": try await codexFirmlinkMixedAutoFileCleanup(selected: true)
            case "codex-firmlink-mixed-auto-keyring-control": try await codexFirmlinkMixedAutoFileCleanup(fileOwner: false)
            case "codex-firmlink-mixed-auto-cleanup": try await codexFirmlinkMixedAutoFileCleanup()
            case "claude-main-file-readd": try await claudeMainFallbackLogin(mode: "new-grant")
            case "claude-main-file-same-grant-readd": try await claudeMainFallbackLogin(mode: "same-grant")
            case "claude-main-file-first-shared": try await claudeMainFallbackLogin(mode: "first")
            case "claude-main-keychain-readd-control": try await claudeMainFallbackLogin(mode: "keychain")
            case "claude-main-file-unshared-control": try await claudeMainFallbackLogin(mode: "unshared")
            case "claude-main-file-unchanged-shared-control": try await claudeMainFallbackLogin(mode: "unchanged")
            case "claude-preferred-denied-stub-polling": try await claudePreferredOwnerPolling(mode: "denied")
            case "claude-preferred-malformed-stub-polling": try await claudePreferredOwnerPolling(mode: "malformed")
            case "claude-preferred-valid-fallback-control": try await claudePreferredOwnerPolling(mode: "valid-fallback")
            case "claude-preferred-keychain-stub-control": try await claudePreferredOwnerPolling(mode: "keychain-stub")
            case "claude-preferred-file-stub-control": try await claudePreferredOwnerPolling(mode: "file-stub")
            case "codex-firmlink-active-file": try await codexFirmlinkOwner()
            case "codex-firmlink-base-file": try await codexFirmlinkOwner(target: "base")
            case "codex-firmlink-active-auto-fallback": try await codexFirmlinkOwner(mode: "auto")
            case "codex-firmlink-sleeping-control": try await codexFirmlinkOwner(active: false)
            case "codex-firmlink-independent-keyring-control": try await codexFirmlinkOwner(mode: "keyring")
            case "codex-native-grant-copy-file": try await codexNativeGrantCopy(mode: "file")
            case "codex-native-grant-copy-keyring": try await codexNativeGrantCopy(mode: "keyring")
            case "codex-native-grant-copy-auto": try await codexNativeGrantCopy(mode: "auto")
            case "codex-independent-same-account-control": try await codexNativeGrantCopy(distinct: true)
            case "codex-firmlink-backup-restore": try await codexBackupPhysicalFence(action: "restore", firmlink: true)
            case "codex-firmlink-backup-pending": try await codexBackupPhysicalFence(action: "pending", firmlink: true)
            case "codex-firmlink-backup-remove": try await codexBackupPhysicalFence(action: "remove", firmlink: true)
            case "codex-firmlink-retired-usage": try await codexFirmlinkUsageRemoval()
            case "codex-firmlink-current-usage-control": try await codexFirmlinkUsageRemoval(remove: false)
            case "codex-renewal-directory-generation": try await codexRenewalDirectoryReplacement()
            case "codex-renewal-atomic-file-control": try await codexRenewalDirectoryReplacement(replaceDirectory: false)
            case "codex-rollback-implicit-file-keyring": try codexRollbackStorageMode(originalMode: "keyring")
            case "codex-rollback-implicit-file-auto": try codexRollbackStorageMode(originalMode: "auto")
            case "codex-rollback-explicit-file-control": try codexRollbackStorageMode(replacementConfig: true)
            case "codex-rollback-metadata-only-control": try codexRollbackStorageMode(replacementAuth: false)
            case "claude-primary-shared-preserves-fallback": try claudePrimarySharedFallback()
            case "claude-primary-shared-cli-off": try claudePrimarySharedFallback(switchCLI: false)
            case "claude-primary-shared-metadata-denied": try claudePrimarySharedFallback(failure: "metadata")
            case "claude-primary-shared-stale-file-owner": try claudePrimarySharedFallback(failure: "stale")
            case "claude-primary-shared-delete-denied-control": try claudePrimarySharedFallback(failure: "delete")
            case "claude-primary-shared-lone-control": try claudePrimarySharedFallback(shared: false)
            case "codex-backup-alias-fence-file": try await codexBackupPhysicalFence(mode: "file")
            case "codex-backup-alias-fence-keyring": try await codexBackupPhysicalFence(mode: "keyring")
            case "codex-backup-alias-fence-auto": try await codexBackupPhysicalFence(mode: "auto")
            case "codex-backup-direct-fence-control": try await codexBackupPhysicalFence(alias: false)
            case "codex-backup-unrelated-switch-control": try await codexBackupPhysicalFence(action: "unrelated")
            case "codex-backup-alias-pending-file": try await codexBackupPhysicalFence(mode: "file", action: "pending")
            case "codex-backup-alias-pending-keyring": try await codexBackupPhysicalFence(mode: "keyring", action: "pending")
            case "codex-backup-alias-primary-removal": try await codexBackupPhysicalFence(action: "remove")
            case "codex-retired-temporary-same-grant": try await codexRetiredResponse()
            case "codex-current-temporary-control": try await codexRetiredResponse(remove: false)
            case "codex-retired-temporary-new-grant-control": try await codexRetiredResponse(sameGrant: false)
            case "codex-retired-success-no-replay": try await codexRetiredResponse(response: "success")
            case "codex-retired-lost-no-replay": try await codexRetiredResponse(response: "lost")
            case "codex-retired-rejected-no-replay": try await codexRetiredResponse(response: "rejected")
            case "codex-retired-success-new-grant-control": try await codexRetiredResponse(response: "success", sameGrant: false)
            case "codex-rollback-new-cli-file": try codexRollbackNewLogin(replacement: "file")
            case "codex-rollback-new-cli-symlink": try codexRollbackNewLogin(replacement: "symlink")
            case "codex-rollback-missing-file-control": try codexRollbackNewLogin(replacement: "none")
            case "codex-active-alias-file": try await codexActiveAlias(mode: "file")
            case "codex-active-alias-keyring": try await codexActiveAlias(mode: "keyring")
            case "codex-active-alias-auto": try await codexActiveAlias(mode: "auto")
            case "codex-sleeping-alias-control": try await codexActiveAlias(mode: "file", active: false)
            case "codex-copyback-pinned-file": try codexPinnedCopyback()
            case "codex-copyback-pinned-keyring": try codexPinnedCopyback(mode: "keyring")
            case "codex-copyback-pinned-auto": try codexPinnedCopyback(mode: "auto")
            case "codex-copyback-stable-symlink-control": try codexPinnedCopyback(retarget: false)
            case "codex-copyback-legacy-canonical-control": try codexPinnedCopyback(retarget: false, legacy: true)
            case "codex-copyback-legacy-symlink": try codexPinnedCopyback(legacy: true)
            case "codex-copyback-pinned-rollback": try codexPinnedCopyback(rollback: true)
            case "codex-retarget-to-base-pinned": try codexPinnedRetargetToBase()
            case "claude-retired-401-new-refresh": try await claudeRetiredUsage401(mode: "new-refresh")
            case "claude-retired-401-same-grant": try await claudeRetiredUsage401(mode: "same-grant")
            case "claude-retired-401-relogin": try await claudeRetiredUsage401(mode: "relogin")
            case "claude-retired-401-new-access-control": try await claudeRetiredUsage401(mode: "new-access")
            case "claude-current-401-control": try await claudeRetiredUsage401(mode: "current")
            case "codex-native-canonical-keyring": try await codexNativeCanonical(action: "read")
            case "codex-native-canonical-auto": try await codexNativeCanonical(action: "read", mode: "auto")
            case "codex-native-canonical-save": try await codexNativeCanonical(action: "save")
            case "codex-native-canonical-remove": try await codexNativeCanonical(action: "remove")
            case "codex-native-canonical-remove-auto": try await codexNativeCanonical(action: "remove", mode: "auto")
            case "codex-native-canonical-renew": try await codexNativeCanonical(action: "renew")
            case "codex-native-canonical-switch": try await codexNativeCanonical(action: "switch")
            case "codex-native-canonical-file": try await codexNativeCanonical(action: "read", mode: "file")
            case "codex-retarget-readd-same": try await codexRetarget(action: "remove")
            case "codex-retarget-readd-new": try await codexRetarget(action: "remove", reuseGrant: false)
            case "codex-retarget-inflight": try await codexRetarget(action: "inflight")
            case "codex-retarget-pending": try await codexRetarget(action: "pending")
            case "codex-retarget-usage-aba": try await codexRetarget(action: "usage")
            case "claude-stub-login-race": try await claudeStubOwnership(state: "race")
            case "claude-stub-same-date": try await claudeStubOwnership(state: "same-date")
            case "claude-stub-legacy-marker": try await claudeStubOwnership(state: "legacy")
            case "claude-stub-owner-denied": try await claudeStubOwnership(state: "denied")
            case "claude-stub-owner-malformed": try await claudeStubOwnership(state: "malformed")
            case "claude-stub-genuine": try await claudeStubOwnership(state: "genuine")
            case "claude-stub-later-login": try await claudeStubOwnership(state: "later")
            case "claude-physical-trailing-switch": try await claudePhysicalTrailingPath(action: "switch")
            case "claude-physical-trailing-renewal": try await claudePhysicalTrailingPath(action: "renew")
            case "claude-physical-trailing-shared": try await claudePhysicalTrailingPath(action: "remove")
            case "claude-physical-trailing-shared-off": try await claudePhysicalTrailingPath(action: "remove", switchCLI: false)
            case "claude-physical-trailing-shared-fallback": try await claudePhysicalTrailingPath(action: "remove", fallback: true)
            case "codex-auto-fallback-restore-file-refusal": try await codexAutoFallbackRollback(failure: "restore")
            case "codex-auto-fallback-restore-keyring-refusal": try await codexAutoFallbackRollback(failure: "restore", backupMode: "keyring")
            case "codex-auto-fallback-selected-refusal": try await codexAutoFallbackRollback(failure: "selected")
            case "codex-auto-fallback-primary-refusal": try await codexAutoFallbackRollback(failure: "primary")
            case "codex-auto-fallback-native-progress": try await codexAutoFallbackRollback(failure: "restore", nativeProgress: true)
            case "codex-auto-fallback-restore-success": try await codexAutoFallbackRollback(failure: "none")
            case "claude-borrowed-foreign-current": try claudeBorrowedForeignCurrent()
            case "claude-borrowed-normal-retry": try claudeBorrowedNormalRetry()
            case "claude-shared-extra": try await claudeSharedExtraDirectory()
            case "claude-shared-extra-cli-off": try await claudeSharedExtraDirectory(switchCLI: false)
            case "claude-shared-extra-fallback": try await claudeSharedExtraDirectory(fallback: true)
            case "claude-shared-extra-metadata-denied": try await claudeSharedExtraDirectory(metadataDenied: true)
            case "claude-shared-extra-file-owner": try claudeSharedFileOwner()
            case "claude-incomplete-metadata-denied": try await claudeIncompleteRemoval(state: "metadata-denied")
            case "codex-restore-backup-keyring-refusal": try codexRestoreBackupRefusal(mode: "keyring")
            case "codex-restore-backup-file-refusal": try codexRestoreBackupRefusal(mode: "file")
            case "codex-restore-backup-auto-refusal": try codexRestoreBackupRefusal(mode: "auto")
            case "codex-restore-backup-native-progress": try codexRestoreBackupRefusal(mode: "keyring", nativeProgress: true)
            case "codex-legacy-backup-keyring-removal": try codexLegacyBackupRemoval(mode: "keyring")
            case "codex-legacy-backup-file-removal": try codexLegacyBackupRemoval(mode: "file")
            case "codex-legacy-backup-auto-removal": try codexLegacyBackupRemoval(mode: "auto")
            case "codex-legacy-backup-refusal": try codexLegacyBackupRemoval(mode: "keyring", denied: true)

            case "claude-incomplete-native-oauth": try await claudeIncompleteRemoval(state: "oauth")
            case "claude-incomplete-native-storage": try await claudeIncompleteRemoval(state: "storage")
            case "claude-incomplete-native-legacy": try await claudeIncompleteRemoval(state: "legacy")
            case "claude-incomplete-completed-keychain": try await claudeIncompleteRemoval(state: "keychain")
            case "claude-incomplete-completed-file": try await claudeIncompleteRemoval(state: "file")
            case "claude-incomplete-symlink": try await claudeIncompleteRemoval(state: "symlink")
            case "claude-incomplete-empty": try await claudeIncompleteRemoval(state: "empty")
            case "claude-incomplete-stub": try await claudeIncompleteRemoval(state: "stub")
            case "claude-incomplete-unreadable-owner": try await claudeIncompleteRemoval(state: "unreadable")
            case "claude-incomplete-stub-refusal": try await claudeIncompleteRemoval(state: "stub-refusal")
            case "claude-incomplete-missing": try await claudeIncompleteRemoval(state: "missing")
            case "codex-primary-backup-keyring-refusal": try await codexBackupRemovalRefusal()
            case "codex-selected-backup-keyring-refusal": try await codexBackupRemovalRefusal(primary: false)
            case "codex-primary-backup-file-refusal": try await codexBackupRemovalRefusal(mode: "file")
            case "codex-keyring-delete-restores-backup": try await codexBackupRemovalRefusal(targetDenied: true)
            case "codex-file-delete-restores-backup": try await codexBackupRemovalRefusal(mode: "file", targetDenied: true)

            case "codex-retired-usage-same-grant": try await codexRetiredUsage401(sameGrant: true)
            case "codex-relogin-usage-401": try await codexRetiredUsage401(relogin: true)
            case "codex-copyback-file-relogin": try codexCopybackRelogin(mode: "file")
            case "codex-copyback-keyring-native": try codexCopybackRelogin(mode: "auto", baseMode: "keyring")
            case "codex-copyback-legacy-relogin": try codexCopybackRelogin(legacy: true)
            case "codex-removal-file-selection-rollback": try await codexRemovalSelectionRollback(mode: "file")
            case "codex-removal-primary-selection-rollback": try await codexRemovalSelectionRollback(primary: true)
            case "codex-removal-native-progress-rollback": try await codexRemovalSelectionRollback(nativeProgress: true)
            case "claude-native-shared-owner-removal": try claudeNativeHashedOwnerRemoval(shared: true)

            case "claude-native-hashed-owner-removal": try claudeNativeHashedOwnerRemoval()

            case "codex-retired-usage-401": try await codexRetiredUsage401()
            case "codex-copyback-relogin": try codexCopybackRelogin()
            case "codex-removal-selection-rollback": try await codexRemovalSelectionRollback()
            case "codex-native-parent-removal": try await nativeParentRemoval(codex: true)
            case "claude-native-parent-removal": try await nativeParentRemoval(codex: false)
            case "codex-usage-region-403": try await codexUsageRegion403()

            case "claude-root-retarget-physical-owner": try claudeRootRetargetRemoval(identity: "physical")
            case "claude-root-retarget-logical-owner": try claudeRootRetargetRemoval(identity: "logical")
            case "claude-root-retarget-file-owner": try claudeRootRetargetRemoval(identity: "file")
            case "claude-root-stable-physical-owner": try claudeRootRetargetRemoval(identity: "physical", retarget: false)
            case "claude-root-stable-logical-owner": try claudeRootRetargetRemoval(identity: "logical", retarget: false)
            case "claude-root-stable-file-owner": try claudeRootRetargetRemoval(identity: "file", retarget: false)
            case "codex-uncertain-login-file": try await codexUncertainOwner()
            case "codex-uncertain-login-keyring": try await codexUncertainOwner(mode: "keyring")
            case "codex-uncertain-login-auto": try await codexUncertainOwner(mode: "auto")
            case "codex-uncertain-same-grant": try await codexUncertainOwner(change: "same-grant")
            case "codex-uncertain-owner-denied": try await codexUncertainOwner(mode: "auto", change: "denied")
            case "codex-uncertain-metadata-control": try await codexUncertainOwner(change: "metadata")
            case "codex-uncertain-unchanged-control": try await codexUncertainOwner(change: "none")
            case "codex-rejected-login-control": try await codexUncertainOwner(response: "rejected")
            case "codex-renewed-login-control": try await codexUncertainOwner(response: "success")
            case "codex-owner-inventory-denied-remove": try codexDeniedOwnerInventory(action: "remove")
            case "codex-owner-inventory-denied-save": try codexDeniedOwnerInventory(action: "save")
            case "codex-owner-inventory-denied-delete": try codexDeniedOwnerInventory(action: "delete")
            case "codex-owner-inventory-missing-control": try codexMissingOwnerInventoryControl()
            case "codex-primary-backup-discovery-file": try codexPrimaryBackupAlias(action: "discovery")
            case "codex-primary-backup-discovery-keyring": try codexPrimaryBackupAlias(action: "discovery", mode: "keyring")
            case "codex-primary-backup-discovery-auto": try codexPrimaryBackupAlias(action: "discovery", mode: "auto")
            case "codex-primary-backup-stale-remove": try codexPrimaryBackupAlias(action: "stale")
            case "codex-primary-backup-stale-keyring-remove": try codexPrimaryBackupAlias(action: "stale", mode: "keyring")
            case "codex-primary-backup-recovery-discovery": try codexPrimaryBackupAlias(action: "discovery", recovery: true)
            case "codex-primary-backup-recovery-direct-remove": try codexPrimaryBackupAlias(action: "direct", recovery: true)
            case "codex-primary-backup-data-alias-remove": try codexPrimaryBackupAlias(action: "direct", dataAlias: true)
            case "codex-primary-backup-lost-selection-discovery": try codexPrimaryBackupAlias(action: "discovery", lostSelection: true)
            case "codex-primary-backup-lost-selection-remove": try codexPrimaryBackupAlias(action: "stale", lostSelection: true)
            case "codex-primary-backup-separate-default-control": try codexPrimaryBackupAlias(action: "discovery", separate: true)
            case "codex-uncertain-near-window-file": try await codexCachedRenewalOwner()
            case "codex-uncertain-near-window-keyring": try await codexCachedRenewalOwner(mode: "keyring")
            case "codex-uncertain-near-window-auto": try await codexCachedRenewalOwner(mode: "auto")
            case "codex-uncertain-completed-login": try await codexCachedRenewalOwner(afterResponse: true)
            case "codex-uncertain-completed-metadata-control": try await codexCachedRenewalOwner(afterResponse: true, metadataOnly: true)
            case "codex-rejected-near-window-login": try await codexCachedRenewalOwner(mode: "auto", rejected: true)
            case "codex-primary-backup-ancestor-remove": try codexBackupDirectoryGuard(ancestor: true)
            case "codex-primary-backup-data-ancestor-remove": try codexBackupDirectoryGuard(ancestor: true, dataAlias: true)
            case "codex-primary-backup-orphan-menu": try codexBackupDirectoryGuard(menu: true)
            case "codex-primary-backup-ancestor-orphan-menu": try codexBackupDirectoryGuard(ancestor: true, menu: true)
            case "codex-primary-backup-independent-keyring-control": try codexBackupDirectoryGuard(dataAlias: true, keyringPeer: true)
            case "codex-primary-backup-native-ancestor-control": try codexBackupPrimaryAncestorControl()
            case "codex-primary-backup-spoofed-default-remove": try codexBackupPrimaryAncestorControl(spoofed: true)
            case "codex-primary-inventory-denied-auto": try codexPrimaryRemovalInventory()
            case "codex-primary-inventory-denied-keyring": try codexPrimaryRemovalInventory(mode: "keyring")
            case "codex-primary-inventory-denied-swapped": try codexPrimaryRemovalInventory(selected: true)
            case "codex-primary-inventory-denied-direct": try codexPrimaryRemovalInventory(direct: true)
            case "codex-primary-inventory-readable-control": try codexPrimaryRemovalInventory(state: "readable")
            case "codex-primary-inventory-missing-control": try codexPrimaryRemovalInventory(state: "missing")
            case "codex-primary-peer-unreadable-auto": try codexCompleteRemovalPeer()
            case "codex-primary-peer-file-auto": try codexCompleteRemovalPeer(peerState: "file")
            case "codex-backup-peer-file-auto": try codexCompleteRemovalPeer(peerState: "file", backup: true)
            case "codex-primary-peer-keyring-control": try codexCompleteRemovalPeer(peerState: "keyring")
            case "codex-primary-peer-no-fallback-control": try codexCompleteRemovalPeer(fallback: false)
            case "codex-primary-keyring-unreadable-peer-control": try codexCompleteRemovalPeer(mode: "keyring")
            case "codex-shared-auto-link-removal-control": try codexSharedAutoLinkRemoval()
            case "codex-shared-auto-link-credential-only": try codexSharedAutoLinkRemoval(direct: true)
            case "claude-canonical-main-discovery": try claudeCanonicalMain()
            case "claude-canonical-main-stale-removal": try claudeCanonicalMain(staleRemoval: true)
            case "claude-owner-denied-fallback": try await claudeOwnerFallback()
            case "claude-owner-preflight-denied": try await claudeOwnerFallback(preflight: true)
            case "claude-owner-malformed-fallback": try await claudeOwnerFallback(malformed: true)
            case "codex-root-symlink-keyring": try codexRootSymlink(mode: "keyring")
            case "codex-root-symlink-file": try codexRootSymlink(mode: "file")
            case "codex-readd-during-removal-usage": try await readdDuringRemovalUsage(codex: true)
            case "claude-readd-during-removal-usage": try await readdDuringRemovalUsage(codex: false)
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
            case "codex-quit-inflight": try await codexQuit(inFlight: true)
            case "codex-quit-pending": try await codexQuit(inFlight: false)
            case "codex-quit-without-claude": try await codexQuit(inFlight: false, withoutClaude: true)
            case "codex-quit-timeout": try await codexQuitTimeout()
            case "codex-auto-copyback": try codexAutoCopyback(fallback: false)
            case "codex-auto-copyback-fallback": try codexAutoCopyback(fallback: true)
            case "claude-profile-cleanup-denied": try await profileRemovalDenied(codex: false, moveDenied: false)
            case "codex-profile-cleanup-denied": try await profileRemovalDenied(codex: true, moveDenied: false)
            case "claude-profile-move-denied": try await profileRemovalDenied(codex: false, moveDenied: true)
            case "claude-profile-rollback-heartbeat": try await profileRemovalDenied(codex: false, moveDenied: false, credentialDenied: true)
            case "codex-profile-move-denied": try await profileRemovalDenied(codex: true, moveDenied: true)
            case "codex-active-removal": try await codexActiveRemoval()
            case "codex-primary-removal": try await codexActiveRemoval(primary: true)
            case "codex-primary-direct-removal": try await codexActiveRemoval(primary: true, unswapped: true)
            case "codex-removal-quit-refused": try await codexActiveRemoval(refusesQuit: true)
            case "codex-removal-sync-guard": try await codexActiveRemoval(synchronous: true)
            case "codex-removal-switch-barrier": try await codexRemovalSwitchBarrier()
            case "codex-auto-renew-unavailable": try await codexAutoRenewalUnavailable()
            case "codex-auto-force-unavailable": try await codexAutoRenewalUnavailable(force: true)
            case "codex-auto-renew-recovery": try await codexAutoRenewalUnavailable(recovery: true)
            case "codex-canonical-base-keyring": try await codexCanonicalBaseRemoval()
            case "codex-canonical-base-file": try await codexCanonicalBaseRemoval(mode: "file")
            case "codex-canonical-base-direct": try await codexCanonicalBaseRemoval(direct: true)
            case "codex-canonical-base-activate": try codexCanonicalBaseActivation()
            case "codex-canonical-base-legacy": try await codexLegacyBaseAlias()
            case "codex-canonical-base-menu": try codexBaseProfileMenu()
            case "codex-usage-switch-snapshot": try await codexUsageSwitchSnapshot()
            case "codex-save-prepare-file": try codexSavePreparationFailure(auto: false)
            case "codex-save-prepare-auto": try codexSavePreparationFailure(auto: true)
            case "claude-rollback-collision": try await removalRollbackCollision(codex: false)
            case "codex-rollback-collision": try await removalRollbackCollision(codex: true)
            case "claude-rollback-pending-collision": try await removalRollbackCollision(codex: false, pending: true)
            case "codex-rollback-pending-collision": try await removalRollbackCollision(codex: true, pending: true)
            case "claude-rollback-replacement": try await removalRollbackCollision(codex: false, replacement: true)
            case "codex-rollback-replacement": try await removalRollbackCollision(codex: true, replacement: true)
            case "claude-rollback-native-owner": try await removalRollbackCollision(codex: false, nativeLock: true)
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
        let task = Task { await Provider$Codex().fetch(account) }
        try await waitForRefresh(1)
        // The server has accepted the grant; Keychain becomes unreadable before persistence.
        Fixture.denyCodexRead = true
        Fixture.releaseRefresh()
        _ = await task.value
        Fixture.denyCodexRead = false
        let outcome = await Provider$Codex().fetch(account)
        let saved = Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated"
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
        let provider = Provider$Codex()
        let store = UsageStore(providers: [.codex: provider], discovery: Discovery$Real())
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
        let saved = Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated-synthetic-refresh-generation-b"
        print("replacement rotation retained: \(saved), refresh POST count: \(Fixture.refreshCalls)")
        if case .success = outcome {} else {
            throw Failure(description: "Removed generation's late response erased the re-added generation's pending rotation")
        }
        try expect(saved && Fixture.refreshCalls == 2, "Replacement generation lost its rotated grant")
    }

    @MainActor
    private static func codexSwitchInFlight(mode: String = "keyring", alias: Bool = false) async throws {
        let main = AuthSwap$Codex.baseHome
        let home = ProfileDirectories.codexRoot.appendingPathComponent("switching")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(home, account: "switching", mode: mode, expired: true)
        let account = DiscoveredAccount(id: "codex:switching", provider: .codex, profileName: "switching", source: .codexHome(home))
        let target = alias ? ProfileDirectories.codexRoot.appendingPathComponent("switch-alias") : home
        if alias { try Foundation.FileManager.default.createSymbolicLink(at: target, withDestinationURL: home) }
        Fixture.response = .heldRenewed
        let renewal = Task { await Provider$Codex().fetch(account) }
        try await waitForRefresh(1)
        var switched = false
        do { try AuthSwap$Codex.activate(columnID: alias ? "codex:switch-alias" : account.id, home: target); switched = true } catch {}
        let oldGrantPublished = switched && Renewal$Codex.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-refresh-switching"
        Fixture.releaseRefresh()
        _ = await renewal.value
        print("switch exposed a grant while its refresh response was in flight: \(oldGrantPublished)")
        try expect(!oldGrantPublished, "Switch exposed an already-submitted refresh grant to the native Desktop/CLI before rotation was persisted")
        try AuthSwap$Codex.activate(columnID: account.id, home: home)
        try expect(Renewal$Codex.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-rotated",
                   "Switch did not recover after renewal persisted its grant")
    }

    @MainActor
    private static func claudeFileDiscovery() async throws {
        Fixture.keychainExists = false
        let home = Fixture.storageDirectory
        try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("file-login", expired: false))
            .write(to: home.appendingPathComponent(".credentials.json"))
        let accounts = Discovery$Real().discover().filter { $0.provider == .claude }
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
        let home = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        try Data("cli_auth_credentials_store = \"\"\"keyring\"\"\"\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == "secure", "Valid TOML multiline basic string was rejected as an unknown storage setting")
    }

    private static func codexTOMLBackend() throws {
        let home = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(home, account: "old-direct-login", mode: "keyring")
        try Data("features = { secret_auth_storage = true }\ncli_auth_credentials_store = 'keyring'\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(Provider$Codex.readAuth(codexHome: home) == nil, "Valid inline TOML features bypassed the encrypted-backend guard and loaded an obsolete direct Keychain login")
    }


    @MainActor
    private static func codexSwitchPending(deniedRemoval: Bool = false) async throws {
        let main = AuthSwap$Codex.baseHome
        let home = ProfileDirectories.codexRoot.appendingPathComponent("pending-switch")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(home, account: "pending-switch", mode: "keyring", expired: true)
        let account = DiscoveredAccount(id: "codex:pending-switch", provider: .codex, profileName: "pending-switch", source: .codexHome(home))
        Fixture.denyCodexWrite = true
        _ = await Provider$Codex().fetch(account)
        if deniedRemoval {
            Fixture.denyCodexDelete = true
            var failed = false
            do { try AccountRemoval.remove(account) } catch { failed = true }
            try expect(failed, "Denied removal reported success")
            Fixture.denyCodexDelete = false
        } else {
            var failed = false
            do { try AuthSwap$Codex.activate(columnID: account.id, home: home) } catch { failed = true }
            try expect(failed && Provider$Codex.readAuth(codexHome: main)?.accountID == "main",
                       "Switch published an unsaved refresh grant")
        }
        Fixture.denyCodexWrite = false
        let result = await Provider$Codex().fetch(account)
        if case .success = result {} else { throw Failure(description: "Pending persistence did not recover") }
        try expect(Fixture.refreshCalls == 1, "Pending persistence repeated the refresh POST")
        try AuthSwap$Codex.activate(columnID: account.id, home: home)
        try expect(Renewal$Codex.refreshToken(main.appendingPathComponent("auth.json")) == "synthetic-rotated", "Switch lost the durable grant")
    }

    @MainActor
    private static func codexAutoFileSource() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("auto-file")
        try Fixture.codexLogin(home, account: "file-owner", mode: "file", expired: true)
        try Fixture.codexMode(home, "auto")
        let account = DiscoveredAccount(id: "codex:auto-file", provider: .codex, profileName: "auto-file", source: .codexHome(home))
        Fixture.response = .heldRenewed
        let task = Task { await Provider$Codex().fetch(account) }
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
        let provider = Provider$Claude()
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
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
        try expect(AuthStorage$Claude.parse(json)?.refreshToken == "synthetic-rotated" && json["unknown"] as? String == "preserved",
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
        let provider = Provider$Claude()
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
        let task = Task { await Provider$Claude().fetch(account) }
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
        let home = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        let forms = [
            "cli_auth_credentials_store = '''keyring'''\n",
            "cli_auth_credentials_store = \"\"\"\nkey\\\n ring\"\"\"\n",
            "cli_auth_credentials_store = 'keyring'\nfeatures = { secret_auth_storage = false }\n",
        ]
        for text in forms {
            try Data(text.utf8).write(to: home.appendingPathComponent("config.toml"))
            try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == "secure", "Valid native TOML form did not select Keychain")
        }
        for features in ["features = { 'secret_auth_storage' = true }", "[ 'features' ]\nsecret_auth_storage = true", "features . secret_auth_storage = true"] {
            try Data(("cli_auth_credentials_store = 'keyring'\n" + features + "\n").utf8).write(to: home.appendingPathComponent("config.toml"))
            try expect(Provider$Codex.readAuth(codexHome: home) == nil, "Valid TOML syntax bypassed the encrypted backend guard")
        }
    }


    private static func codexBaseAlias() async throws {
        let main = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(main, account: "main", mode: "keyring", expired: true)
        let home = ProfileDirectories.codexRoot.appendingPathComponent("base-alias")
        try Foundation.FileManager.default.createDirectory(at: ProfileDirectories.codexRoot, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: home, withDestinationURL: main)
        let account = DiscoveredAccount(id: "codex:base-alias", provider: .codex, profileName: "base-alias", source: .codexHome(home))
        _ = await Provider$Codex().fetch(account)
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


    @MainActor
    private static func codexQuit(inFlight: Bool, withoutClaude: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("quit-profile")
        try Fixture.codexLogin(home, account: "quit-profile", mode: "keyring", expired: true)
        let account = DiscoveredAccount(id: "codex:quit-profile", provider: .codex, profileName: "quit-profile", source: .codexHome(home))
        let provider = Provider$Codex()
        var task: Task<FetchOutcome, Never>?
        if inFlight {
            Fixture.response = .heldRenewed
            task = Task { await provider.fetch(account) }
            try await waitForRefresh(1)
        } else {
            Fixture.denyCodexWrite = true
            _ = await provider.fetch(account)
        }
        let application = NSApplication()
        let delegate = RegressionTerminationDelegate()
        if withoutClaude { delegate.claudeProvider = nil }
        let reply = delegate.applicationShouldTerminate(application)
        // A .terminateNow reply also approves quitting without a later callback.
        let immediate = reply == .terminateNow
        for _ in 0..<100 {
            if application.approved != nil { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        let approvedBeforeDurable = immediate || application.approved == true
        Fixture.denyCodexWrite = false
        Fixture.releaseRefresh()
        if let task { _ = await task.value }
        for _ in 0..<500 {
            if application.approved != nil { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        try expect(!approvedBeforeDurable, "Normal quit abandoned the only rotated Codex credentials or an accepted refresh POST")
        try expect(application.approved == true, "Quit did not complete after Codex credentials became durable")
        try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated", "Quit lost the rotated grant")
        try expect(Fixture.refreshCalls == 1, "Termination retried the refresh POST")
    }

    private static func codexQuitTimeout() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("quit-timeout")
        try Fixture.codexLogin(home, account: "quit-timeout", mode: "keyring", expired: true)
        let account = DiscoveredAccount(id: "codex:quit-timeout", provider: .codex, profileName: "quit-timeout", source: .codexHome(home))
        let provider = Provider$Codex()
        Fixture.denyCodexWrite = true
        _ = await provider.fetch(account)
        #if CODEX_TERMINATION_DRAIN
        let ready = await Renewal$Codex.shared.prepareForTermination(timeout: 0.05)
        #else
        let ready = true
        #endif
        try expect(!ready, "Quit was approved despite a denied write of rotated Codex credentials")
        Fixture.denyCodexWrite = false
        _ = await provider.fetch(account)
        try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated", "Cancelled quit lost its pending grant")
        let other = try Fixture.codexAccount("after-cancelled-quit")
        _ = await provider.fetch(other)
        try expect(Fixture.refreshCalls == 2, "A cancelled quit permanently disabled automatic renewal")
    }

    @MainActor
    private static func profileRemovalDenied(codex: Bool, moveDenied: Bool, credentialDenied: Bool = false) async throws {
        let account: DiscoveredAccount
        let directory: URL
        var original: Data
        let claude = Provider$Claude()
        let provider = Provider$Codex()
        var claudeRenewal: Task<FetchOutcome, Never>?
        if codex {
            directory = ProfileDirectories.codexRoot.appendingPathComponent("deny-directory")
            try Fixture.codexLogin(directory, account: "keep-login", mode: "keyring", expired: true)
            account = DiscoveredAccount(id: "codex:deny-directory", provider: .codex, profileName: "deny-directory", source: .codexHome(directory))
            original = Fixture.codexKeychain[Fixture.codexKey(directory)]!
            if moveDenied { Fixture.denyCodexWrite = true; _ = await provider.fetch(account) }
        } else {
            let (found, file) = try claudeFileAccount(primary: false, expired: true)
            account = found; directory = file.deletingLastPathComponent()
            original = try Data(contentsOf: file)
            if moveDenied || credentialDenied {
                Fixture.failClaudeFileWrite = true
                claudeRenewal = Task { await claude.fetch(account) }
                for _ in 0..<300 {
                    if Fixture.claudeFileWriteFailures > 0 { break }
                    try await Task.sleep(nanoseconds: 5_000_000)
                }
                try expect(Fixture.claudeFileWriteFailures > 0, "Claude did not reach pending persistence")
                // The preflight may reserialize unchanged JSON before the POST.
                original = try Data(contentsOf: file)
            }
        }
        let store = UsageStore(providers: [.claude: claude, .codex: provider], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "Removal profile was not discovered")
        let desktopKey = AppSwitcher$Claude.key(for: account.id)
        Fixture.denyProfileRemoval = directory.path
        Fixture.denyProfileMove = moveDenied
        Fixture.denyKeychainDelete = credentialDenied
        Fixture.slowKeychainDelete = credentialDenied
        var failed = false
        do { try store.removeAccount(id: account.id) } catch { failed = true }
        let retained: Bool
        if codex { retained = Fixture.codexKeychain[Fixture.codexKey(directory)] == original }
        else { retained = (try? Data(contentsOf: directory.appendingPathComponent(".credentials.json"))) == original }
        let remains = Foundation.FileManager.default.fileExists(atPath: directory.path)
        Fixture.denyProfileRemoval = nil
        Fixture.denyProfileMove = false
        Fixture.denyKeychainDelete = false
        Fixture.slowKeychainDelete = false
        if moveDenied || credentialDenied {
            try expect(failed && retained && remains, "Failed profile removal lost credentials or reported success")
            try expect(AppSwitcher$Claude.key(for: account.id) == desktopKey, "Failed removal retired the Desktop session")
            Fixture.denyCodexWrite = false
            Fixture.failClaudeFileWrite = false
            if let claudeRenewal { _ = await claudeRenewal.value }
            if codex {
                _ = await provider.fetch(account)
                try expect(Renewal$Codex.refreshToken(directory.appendingPathComponent("auth.json")) == "synthetic-rotated", "Failed directory removal discarded a pending rotation")
            } else {
                _ = await claude.fetch(account)
                try expect(AuthStorage$Claude.credentials(service: account.id.replacingOccurrences(of: "claude:", with: ""))?.refreshToken == "synthetic-rotated", "Failed directory removal discarded a pending Claude rotation")
            }
            try expect(Fixture.refreshCalls == 1, "Failed directory removal repeated the refresh POST")
        } else {
            try expect(!failed && !retained && !remains, "Directory cleanup failure left a half-removed account and blocked same-name re-addition")
            try expect(store.account(for: account.id) == nil, "Logged-out hidden directory remained discoverable")
            // Recreate the exact name and verify discovery sees the new generation.
            if codex { try Fixture.codexLogin(directory, account: "replacement", mode: "keyring") }
            else {
                try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
                    .write(to: directory.appendingPathComponent(".credentials.json"))
            }
            store.rediscover(force: true)
            try expect(store.account(for: account.id) != nil, "Same-name profile could not be re-added after cleanup failure")
        }
    }

    @MainActor
    private static func codexActiveRemoval(refusesQuit: Bool = false, synchronous: Bool = false,
                                           primary: Bool = false, unswapped: Bool = false) async throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("active-removed")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(profile, account: "removed", mode: "file")
        let originalMain = Provider$Codex.readAuth(codexHome: main)!
        if !unswapped { try AuthSwap$Codex.activate(columnID: "codex:active-removed", home: profile) }
        // Desktop's refresh POST is accepted for B. It must exit before A is restored.
        Fixture.desktopRunning = true
        Fixture.desktopRefusesQuit = refusesQuit
        CLISelection$Claude.isEnabled = false
        let account = DiscoveredAccount(id: primary ? AuthSwap$Codex.defaultColumnID : "codex:active-removed", provider: .codex,
                                        profileName: primary ? "main" : "active-removed", source: .codexHome(primary ? main : profile))
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        var failed = false
        #if COORDINATED_CODEX_REMOVAL
        if !synchronous {
            let result: Result<Void, Error> = await withCheckedContinuation { continuation in
                store.removeAccount(id: account.id) { continuation.resume(returning: $0) }
            }
            if case .failure = result { failed = true }
        } else {
            do { try store.removeAccount(id: account.id) } catch { failed = true }
        }
        #else
        do { try store.removeAccount(id: account.id) } catch { failed = true }
        #endif
        if refusesQuit || synchronous {
            try expect(failed && AuthSwap$Codex.isSwapped && Provider$Codex.readAuth(codexHome: main)?.accountID == "removed", "Desktop exit refusal changed the active login or deleted credentials")
            try expect(Foundation.FileManager.default.fileExists(atPath: profile.path), "Refused removal deleted the profile")
            return
        }
        // Model native persist_tokens: reload current storage, replace response
        // tokens and save. A terminated process cannot perform this late write.
        if Fixture.desktopRunning, let record = try AuthStorage$Codex(home: main).load() {
            var root = try JSONSerialization.jsonObject(with: record.data) as! [String: Any]
            var tokens = root["tokens"] as! [String: Any]
            tokens["access_token"] = "synthetic-native-removed-access"
            tokens["refresh_token"] = "synthetic-native-removed-refresh"
            root["tokens"] = tokens
            try AuthStorage$Codex(home: main).save(JSONSerialization.data(withJSONObject: root))
        }
        try expect(!failed && !Fixture.desktopRunning && Fixture.desktopStops == 1, "Removal did not wait for Desktop exit")
        if primary {
            try expect(Provider$Codex.readAuth(codexHome: main) == nil, "Primary account was not removed")
            try expect(Provider$Codex.readAuth(codexHome: profile)?.accountID == "removed", "Primary deletion lost the selected profile's login")
        } else {
            try expect(Provider$Codex.readAuth(codexHome: main)?.accessToken == originalMain.accessToken, "Late native refresh overwrote the restored primary login")
            try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Selected profile was not removed")
        }
        try expect(Fixture.desktopCalls == 0 && !CLISelection$Claude.isEnabled, "Removal launched Desktop or changed the Claude CLI setting")
    }

    @MainActor
    private static func codexRemovalSwitchBarrier() async throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("removal-barrier")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(profile, account: "removed", mode: "file")
        let account = DiscoveredAccount(id: "codex:removal-barrier", provider: .codex, profileName: "removal-barrier", source: .codexHome(profile))
        try AuthSwap$Codex.activate(columnID: account.id, home: profile)
        Fixture.desktopRunning = true
        Fixture.holdDesktopStop = true
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        var removed: Result<Void, Error>?
        #if COORDINATED_CODEX_REMOVAL
        store.removeAccount(id: account.id) { removed = $0 }
        #else
        removed = Result { try store.removeAccount(id: account.id) }
        #endif
        try expect(removed == nil && AuthSwap$Codex.isSwapped, "Removal changed credentials before Desktop exited")
        let other = try Fixture.codexAccount("other")
        var switched = false
        AppSwitcher$Codex().switchTo(other) { if case .success = $0 { switched = true } }
        try expect(!switched && Fixture.desktopCalls == 0, "A concurrent switch bypassed the removal exit barrier")
        var secondFailed = false
        #if COORDINATED_CODEX_REMOVAL
        store.removeAccount(id: account.id) { if case .failure = $0 { secondFailed = true } }
        #endif
        try expect(secondFailed, "Duplicate removal entered the same Desktop exit barrier")
        Fixture.desktopRunning = false
        Fixture.desktopStopCompletion?(.success(()))
        Fixture.desktopStopCompletion = nil
        if case .success? = removed {} else { throw Failure(description: "Removal did not complete after Desktop exit") }
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "main", "Removal barrier lost the primary login")
    }

    private static func codexAutoCopyback(fallback: Bool) throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("auto-copyback")
        try Fixture.codexLogin(main, account: "main", mode: "file")
        try Fixture.codexLogin(profile, account: "profile", mode: "auto", expired: true)
        if fallback { try Fixture.writeAuth(profile, account: "stale-other", refresh: "stale-other", expired: false) }
        try AuthSwap$Codex.activate(columnID: "codex:auto-copyback", home: profile)
        // Native Desktop refreshed its current login while it owned the base home.
        try Fixture.writeAuth(main, account: "profile", refresh: "native-rotated-profile", expired: false)
        Fixture.denyCodexRead = true
        var switched = false
        do { try AuthSwap$Codex.restoreDefault(); switched = true } catch {}
        Fixture.denyCodexRead = false
        let grant = Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json"))
        let orphanRoot = AuthSwap$Codex.stashHome.deletingLastPathComponent()
        let orphanCount = (try? Foundation.FileManager.default.contentsOfDirectory(at: orphanRoot, includingPropertiesForKeys: nil))?
            .filter { $0.lastPathComponent.hasPrefix("orphaned-") }.count ?? 0
        print("AUDIT switch accepted: \(switched), native grant returned to profile: \(grant == "native-rotated-profile"), orphan copies: \(orphanCount)")
        try expect(!switched || grant == "native-rotated-profile", "Auto copyback mistook denied Keychain access for a replaced login and orphaned the native rotation")
    }


    private static func codexAutoRenewalUnavailable(force: Bool = false, recovery: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("auto-unavailable")
        try Fixture.codexLogin(home, account: "owner", mode: "auto", expired: recovery)
        let secure = Fixture.codexKeychain[Fixture.codexKey(home)]!
        try Fixture.writeAuth(home, account: "owner", refresh: "synthetic-already-spent", expired: !force)
        Fixture.rejectSpentRefresh = true
        Fixture.denyCodexRead = true
        Fixture.usageStatus = force ? 401 : 200
        let account = DiscoveredAccount(id: "codex:auto-unavailable", provider: .codex,
                                        profileName: "auto-unavailable", source: .codexHome(home))
        let provider = Provider$Codex()
        _ = await provider.fetch(account)
        let deferred = Fixture.refreshCalls == 0
        Fixture.denyCodexRead = false
        try expect(deferred && Fixture.codexKeychain[Fixture.codexKey(home)] == secure,
                   "Auto renewal spent a stale fallback grant while the preferred Keychain owner was unavailable")
        Fixture.usageStatus = 200
        _ = await provider.fetch(account)
        try expect(Fixture.refreshCalls == (recovery ? 1 : 0), "Unlocking Keychain did not resume renewal of its own grant")
        if recovery {
            try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated",
                       "The Keychain owner's rotation was not persisted after recovery")
        }
    }

    @MainActor
    private static func codexCanonicalBaseRemoval(mode: String = "keyring", direct: Bool = false) async throws {
        let owner = ProfileDirectories.codexRoot.appendingPathComponent("base-owner")
        try Fixture.codexLogin(owner, account: "primary", mode: mode)
        if direct { Fixture.codexHome = owner.path }
        else { try Foundation.FileManager.default.createSymbolicLink(at: AuthSwap$Codex.baseHome, withDestinationURL: owner) }
        let project = owner.appendingPathComponent("state_5.sqlite")
        try Data("synthetic-projects-and-threads".utf8).write(to: project)
        let primary = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                       profileName: "main", source: .codexHome(AuthSwap$Codex.baseHome))
        let duplicate = DiscoveredAccount(id: "codex:base-owner", provider: .codex,
                                         profileName: "base-owner", source: .codexHome(owner))
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let onlyPrimary = store.discoveredAccounts.filter { $0.provider == .codex }.map(\.id) == [primary.id]
        Fixture.desktopRunning = true
        let original = try AuthSwap$Codex.authData(home: owner)
        // A stale menu or direct caller must not treat the physical base as an extra profile.
        var refused = false
        do { try AccountRemoval.remove(duplicate) } catch { refused = true }
        let retained = try AuthSwap$Codex.authData(home: owner) == original
        try expect(refused && retained && Foundation.FileManager.default.fileExists(atPath: project.path),
                   "A duplicate canonical-base column deleted credentials/projects under a running Desktop")
        try expect(onlyPrimary && !AccountRemoval.isExtraProfile(primary) && !AccountRemoval.isExtraProfile(duplicate),
                   "The native base home was discovered/classified as an independently removable profile")
        let result: Result<Void, Error> = await withCheckedContinuation { continuation in
            store.removeAccount(id: primary.id) { continuation.resume(returning: $0) }
        }
        if case .success = result {} else { throw Failure(description: "Primary removal failed after Desktop exit") }
        try expect(Fixture.desktopStops == 1 && !Fixture.desktopRunning && Fixture.desktopCalls == 0,
                   "Canonical primary removal did not stop Desktop without launching it")
        try expect(Foundation.FileManager.default.fileExists(atPath: project.path)
                   && Foundation.FileManager.default.fileExists(atPath: owner.appendingPathComponent("config.toml").path),
                   "Primary removal deleted projects or native configuration because CODEX_HOME was inside the managed root")
        try expect(try AuthSwap$Codex.authData(home: owner) == nil, "Primary credentials were not removed")
    }

    @MainActor
    private static func codexBaseProfileMenu() throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("native-base")
        Fixture.codexHome = home.path
        try Fixture.codexMode(home, "keyring")
        let project = home.appendingPathComponent("state_5.sqlite")
        try Data("synthetic-projects".utf8).write(to: project)
        let unfinished = ProfileDirectories.codexRoot.appendingPathComponent("unfinished-extra")
        try Foundation.FileManager.default.createDirectory(at: unfinished, withIntermediateDirectories: true)
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let entries = RegressionProfileMenu(store: store).profiles()
        try expect(!entries.contains { AuthSwap$Codex.isBaseHome($0.url) },
                   "The native base home was offered as an unfinished profile directory after its login was removed")
        try expect(entries.contains { $0.url.path == unfinished.path }, "A genuine unfinished extra profile disappeared from the menu")
        try expect(try String(contentsOf: project) == "synthetic-projects", "Menu discovery changed native project data")
    }

    private static func codexUsageSwitchSnapshot() async throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("snapshot-switch")
        try Fixture.codexLogin(main, account: "main-a", mode: "file")
        try Fixture.codexLogin(profile, account: "profile-b", mode: "file")
        let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                       profileName: "main", source: .codexHome(main))
        Fixture.pauseAuthReadPath = main.appendingPathComponent("auth.json").path
        let fetch = Task { await Provider$Codex().fetch(account) }
        var paused = false
        for _ in 0..<300 {
            Fixture.lock.lock(); paused = Fixture.authReadPaused; Fixture.lock.unlock()
            if paused { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(paused, "Usage did not reach the credential-read boundary")
        let switching = Task.detached {
            try AuthSwap$Codex.activate(columnID: "codex:snapshot-switch", home: profile)
            Fixture.lock.lock(); Fixture.authSwitchCompleted = true; Fixture.lock.unlock()
        }
        // The old code commits B while A's read is paused. A consistent read
        // keeps switching behind its snapshot until the boundary is released.
        for _ in 0..<300 {
            Fixture.lock.lock(); let completed = Fixture.authSwitchCompleted; Fixture.lock.unlock()
            if completed { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock()
        _ = await fetch.value
        try await switching.value
        try expect(Fixture.lastCodexAccount == "main-a", "A primary-column usage request read the selected profile's credentials during a switch")
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "profile-b", "The switch did not complete after the usage snapshot")
    }

    private static func codexCanonicalBaseActivation() throws {
        let owner = ProfileDirectories.codexRoot.appendingPathComponent("base-owner")
        try Fixture.codexLogin(owner, account: "primary", mode: "keyring")
        try Foundation.FileManager.default.createSymbolicLink(at: AuthSwap$Codex.baseHome, withDestinationURL: owner)
        let original = try AuthSwap$Codex.authData(home: owner)
        var refused = false
        do { try AuthSwap$Codex.activate(columnID: "codex:base-owner", home: owner) } catch { refused = true }
        try expect(refused && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID
                   && AuthSwap$Codex.authData(home: owner) == original,
                   "Activation created a sleeping duplicate of the native-owned base grant")
    }

    @MainActor
    private static func codexLegacyBaseAlias() async throws {
        let owner = ProfileDirectories.codexRoot.appendingPathComponent("legacy-base")
        try Fixture.codexLogin(owner, account: "primary", mode: "keyring", expired: true)
        try Foundation.FileManager.default.createSymbolicLink(at: AuthSwap$Codex.baseHome, withDestinationURL: owner)
        let old = try AuthSwap$Codex.authData(home: owner)!
        try Fixture.codexMode(AuthSwap$Codex.stashHome, "file")
        try old.write(to: AuthSwap$Codex.stashHome.appendingPathComponent("auth.json"))
        UserDefaults.standard.set("codex:legacy-base", forKey: "codexAppAccountID")
        UserDefaults.standard.set(owner.path, forKey: "codexAppAccountHome")
        UserDefaults.standard.set("file", forKey: "codexAppStashStore")
        let native = Fixture.root.appendingPathComponent("native-response")
        try Fixture.writeAuth(native, account: "primary", refresh: "current-native-grant", expired: false)
        Fixture.codexKeychain[Fixture.codexKey(owner)] = try Data(contentsOf: native.appendingPathComponent("auth.json"))
        let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                       profileName: "main", source: .codexHome(AuthSwap$Codex.baseHome))
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 0 && !AuthSwap$Codex.isSwapped,
                   "A saved canonical-base alias renewed the spent primary backup instead of using the live native home")
        let other = try Fixture.codexAccount("real-profile")
        guard case .codexHome(let home) = other.source else { fatalError() }
        try AuthSwap$Codex.activate(columnID: other.id, home: home)
        try AuthSwap$Codex.restoreDefault()
        try expect(Renewal$Codex.refreshToken(owner.appendingPathComponent("auth.json")) == "current-native-grant",
                   "Recovery from a legacy base alias restored its stale backup over the current native login")
    }

    private static func codexSavePreparationFailure(auto: Bool) throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("prepared-switch")
        try Fixture.codexLogin(main, account: "main-a", mode: "file")
        if auto { try Fixture.codexMode(main, "auto"); Fixture.denyCodexWrite = true }
        try Fixture.codexLogin(profile, account: "profile-b", mode: "file")
        Fixture.denyCredentialChmodHome = main.path
        var failed = false
        do { try AuthSwap$Codex.activate(columnID: "codex:prepared-switch", home: profile) } catch { failed = true }
        let actual = Provider$Codex.readAuth(codexHome: main)?.accountID
        let marker = AuthSwap$Codex.activeColumnID
        Fixture.denyCredentialChmodHome = nil
        Fixture.denyCodexWrite = false
        try AuthSwap$Codex.activate(columnID: "codex:prepared-switch", home: profile)
        try AuthSwap$Codex.restoreDefault()
        let restored = Provider$Codex.readAuth(codexHome: main)?.accountID
        print("Preparation refused: \(failed), actual owner after refusal: \(actual ?? "nil"), restored owner: \(restored ?? "nil")")
        try expect(failed && actual == "main-a" && marker == AuthSwap$Codex.defaultColumnID && restored == "main-a",
                   "A partial credential save changed ownership before commit and retry overwrote the primary backup")
        let leftovers = try Foundation.FileManager.default.contentsOfDirectory(atPath: main.path)
        try expect(!leftovers.contains { $0.hasPrefix(".auth-") }, "Failed credential preparation retained temporary secrets")
    }

    @MainActor
    private static func removalRollbackCollision(codex: Bool, pending: Bool = false,
                                                 replacement: Bool = false, nativeLock: Bool = false) async throws {
        let account: DiscoveredAccount
        let home: URL
        let claude = Provider$Claude(), provider = Provider$Codex()
        var renewal: Task<FetchOutcome, Never>?
        if codex {
            home = ProfileDirectories.codexRoot.appendingPathComponent("rollback-collision")
            try Fixture.codexLogin(home, account: "retained", mode: replacement ? "file" : "keyring", expired: pending)
            account = DiscoveredAccount(id: "codex:rollback-collision", provider: .codex,
                                        profileName: "rollback-collision", source: .codexHome(home))
            if pending { Fixture.denyCodexWrite = true; _ = await provider.fetch(account) }
            Fixture.denyCodexDelete = true
            // A file-mode replacement needs a refused unlink instead of a Keychain error.
            if replacement { try Fixture.codexMode(home, "auto") }
        } else {
            let found = try claudeFileAccount(primary: false, expired: pending)
            account = found.0; home = found.1.deletingLastPathComponent()
            if pending {
                Fixture.failClaudeFileWrite = true
                renewal = Task { await claude.fetch(account) }
                for _ in 0..<300 {
                    if Fixture.claudeFileWriteFailures > 0 { break }
                    try await Task.sleep(nanoseconds: 5_000_000)
                }
                try expect(Fixture.claudeFileWriteFailures > 0, "Pending Claude rotation was not reached")
            }
            Fixture.denyKeychainDelete = true
        }
        let oldSettings = home.appendingPathComponent("settings.json")
        try Data("original-settings".utf8).write(to: oldSettings)
        let nested = home.appendingPathComponent("projects/shared", isDirectory: true)
        try Foundation.FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: nested.appendingPathComponent("original"))
        try Data("old-conflict".utf8).write(to: nested.appendingPathComponent("conflict"))
        let native = home.appendingPathComponent(".oauth_refresh.lock")
        var nativeInode: UInt64?
        Fixture.beforeCredentialDelete = {
            try! Foundation.FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
            try! Data("new".utf8).write(to: nested.appendingPathComponent("conflict"))
            try! Data("new".utf8).write(to: nested.appendingPathComponent("bootstrap"))
            if replacement {
                if codex { try! Fixture.writeAuth(home, account: "replacement", refresh: "replacement-grant", expired: false) }
                else {
                    try! JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
                        .write(to: home.appendingPathComponent(".credentials.json"))
                }
            }
            if nativeLock {
                try! Foundation.FileManager.default.createDirectory(at: native, withIntermediateDirectories: true)
                nativeInode = (try! Foundation.FileManager.default.attributesOfItem(atPath: native.path)[.systemFileNumber] as! NSNumber).uint64Value
            }
        }
        let store = UsageStore(providers: [.claude: claude, .codex: provider], discovery: Discovery$Real())
        store.rediscover(force: true)
        var failed = false
        do { try store.removeAccount(id: account.id) } catch { failed = true }
        Fixture.denyCodexDelete = false
        Fixture.denyKeychainDelete = false
        let accessible: Bool
        if codex {
            accessible = Provider$Codex.readAuth(codexHome: home)?.accountID == (replacement ? "replacement" : "retained")
        } else {
            guard case .claudeKeychain(let service, _) = account.source else { fatalError() }
            accessible = AuthStorage$Claude.credentials(service: service)?.refreshToken == (replacement ? "synthetic-refresh-replacement" : "synthetic-refresh-file-owner")
        }
        // Check visibility before the pending writer resumes, so a fresh save
        // cannot conceal a broken rollback that orphaned the original profile.
        try expect(failed && accessible, "Refused removal stranded the profile when its original directory was recreated")
        try expect(try String(contentsOf: oldSettings) == "original-settings"
                   && String(contentsOf: nested.appendingPathComponent("original")) == "old"
                   && String(contentsOf: nested.appendingPathComponent("conflict")) == "new"
                   && String(contentsOf: nested.appendingPathComponent("bootstrap")) == "new",
                   "Rollback lost original data or overwrote a concurrent client's files")
        if nativeLock {
            let inode = (try Foundation.FileManager.default.attributesOfItem(atPath: native.path)[.systemFileNumber] as! NSNumber).uint64Value
            try expect(inode == nativeInode, "Rollback replaced the native client's OAuth lock")
            try Foundation.FileManager.default.removeItem(at: native)
        }
        Fixture.denyCodexWrite = false
        Fixture.failClaudeFileWrite = false
        if let renewal { _ = await renewal.value }
        if pending {
            if codex {
                _ = await provider.fetch(account)
                try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated", "Rollback discarded the pending Codex rotation")
            } else {
                _ = await claude.fetch(account)
                guard case .claudeKeychain(let service, _) = account.source else { fatalError() }
                try expect(AuthStorage$Claude.credentials(service: service)?.refreshToken == "synthetic-rotated", "Rollback discarded the pending Claude rotation")
            }
            try expect(Fixture.refreshCalls == 1, "Rollback retried a refresh POST instead of preserving the pending grant")
        }
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "Refused removal erased the discovered profile")
        try store.removeAccount(id: account.id)
        try expect(!Foundation.FileManager.default.fileExists(atPath: home.path), "Retry could not complete removal after rollback")
        if codex { try Fixture.codexLogin(home, account: "readded", mode: "keyring") }
        else {
            try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("readded", expired: false))
                .write(to: home.appendingPathComponent(".credentials.json"))
        }
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "Rollback/retry blocked same-name profile re-addition")
    }

    private static func codexStoreRead(_ mode: String, missing: Bool = false, denied: Bool = false) throws {
        let home = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(home, account: "secure", mode: "keyring")
        if missing { Fixture.codexKeychain = [:] }
        Fixture.denyCodexRead = denied
        try Fixture.writeAuth(home, account: "stale-file", refresh: "stale-file-refresh", expired: false)
        try Fixture.codexMode(home, mode)
        let auth = Provider$Codex.readAuth(codexHome: home)
        if mode == "ephemeral" || mode == "unknown" || mode == "keyring" && denied {
            try expect(auth == nil, "Persistent file credentials bypassed the selected Codex storage mode")
        } else {
            let expected = mode == "file" || missing || denied ? "stale-file" : "secure"
            try expect(auth?.accountID == expected, "Codex loaded a stale or wrong credential backend")
        }
        if mode == "ephemeral" || mode == "file" { try expect(Fixture.codexSecretReads == 0, "Storage mode probed an unrelated Keychain secret") }
    }

    private static func codexStoreDiscovery(symlink: Bool = false) throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(main, account: "main", mode: "keyring")
        try Fixture.codexLogin(profile, account: "profile", mode: "keyring")
        if symlink {
            let alias = Fixture.root.appendingPathComponent("codex-alias")
            try Foundation.FileManager.default.createSymbolicLink(at: alias, withDestinationURL: profile)
            try expect(Provider$Codex.readAuth(codexHome: alias)?.accountID == "profile", "Keychain service key ignored the canonical CODEX_HOME")
        }
        let reads = Fixture.codexSecretReads
        let accounts = Discovery$Real().discover().filter { $0.provider == .codex }
        try expect(Set(accounts.map(\.id)) == [AuthSwap$Codex.defaultColumnID, "codex:secure"], "Keychain-only Codex accounts were not discovered")
        try expect(Fixture.codexSecretReads == reads, "Discovery read credential secrets instead of metadata")
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "main", "Keychain primary account could not be read")
    }

    @MainActor
    private static func codexStoreSwitch(baseMode: String = "keyring", profileMode: String = "keyring", fallback: Bool = false) throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(main, account: "main", mode: fallback ? "file" : baseMode)
        try Fixture.codexMode(main, baseMode)
        try Fixture.codexLogin(profile, account: "profile", mode: profileMode)
        Fixture.denyCodexWrite = fallback
        let projects = main.appendingPathComponent("synthetic-projects")
        try Data("preserved".utf8).write(to: projects)
        CLISelection$Claude.isEnabled = false // Claude's setting cannot change Codex switching.
        do { try AuthSwap$Codex.activate(columnID: "codex:secure", home: profile) }
        catch { throw Failure(description: "Codex switch rejected an existing persistent Keychain profile") }
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "profile", "Desktop/CLI did not select the profile in the base backend")
        try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.stashHome)?.accountID == "main", "Main credentials were not retained in their backend")
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
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "main", "Main account did not restore")
        try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "native-rotated", "Native refreshed profile credentials were not returned to their selected backend")
        try expect(try String(contentsOf: projects) == "preserved", "Switch changed Desktop projects")
        if baseMode != "file" && !fallback { try expect(!Foundation.FileManager.default.fileExists(atPath: main.appendingPathComponent("auth.json").path), "Switch exported base Keychain credentials to auth.json") }
        if profileMode != "file" { try expect(!Foundation.FileManager.default.fileExists(atPath: profile.appendingPathComponent("auth.json").path), "Switch exported profile Keychain credentials to auth.json") }
    }

    private static func codexStoreRenewal(mode: String = "keyring", denied: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("secure")
        try Fixture.codexLogin(home, account: "secure", mode: mode, expired: true)
        let account = DiscoveredAccount(id: "codex:secure", provider: .codex, profileName: "secure", source: .codexHome(home))
        Fixture.denyCodexWrite = denied
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Sleeping Keychain profile was not renewed")
        if denied {
            try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-refresh-secure", "Denied persistence did not preserve the stored grant")
            Fixture.denyCodexWrite = false
        }
        let outcome = await Provider$Codex().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Keychain renewal did not recover persistence") }
        try expect(Fixture.refreshCalls == 1 && Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated", "Keychain persistence lost tokens or repeated the refresh POST")
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
        let home = AuthSwap$Codex.baseHome
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
        try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == "secure", "Codex ignored root/managed storage settings or parsed a nested/string value as root")
    }

    private static func codexStoreEncryptedBackend() throws {
        let home = AuthSwap$Codex.baseHome
        try Fixture.writeAuth(home, account: "stale", refresh: "stale", expired: false)
        try Data("cli_auth_credentials_store = 'keyring'\n[features]\nsecret_auth_storage = true\n".utf8)
            .write(to: home.appendingPathComponent("config.toml"))
        try expect(Provider$Codex.readAuth(codexHome: home) == nil,
                   "Encrypted secrets mode was mistaken for a direct Keychain or file login")
    }

    private static func codexStoreEphemeralSwitch(alreadyActive: Bool = false) throws {
        let main = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("file")
        try Fixture.writeAuth(main, account: "stale-main", refresh: "stale", expired: false)
        try Fixture.codexMode(main, "ephemeral")
        try Fixture.codexLogin(profile, account: "profile", mode: "file")
        let before = try Data(contentsOf: main.appendingPathComponent("auth.json"))
        if alreadyActive {
            UserDefaults.standard.set("codex:file", forKey: "codexAppAccountID")
            UserDefaults.standard.set(profile.path, forKey: "codexAppAccountHome")
        }
        let previousID = AuthSwap$Codex.activeColumnID
        var failed = false
        do { try AuthSwap$Codex.activate(columnID: "codex:file", home: profile) } catch { failed = true }
        try expect(failed && AuthSwap$Codex.activeColumnID == previousID,
                   "Ephemeral mode allowed a persistent Desktop/CLI switch")
        try expect(try Data(contentsOf: main.appendingPathComponent("auth.json")) == before, "Ephemeral mode mutated a persistent cache")
    }

    @MainActor
    private static func profileIdentity() throws {
        let main = AuthSwap$Codex.baseHome
        let extra = ProfileDirectories.codexRoot.appendingPathComponent("default")
        try Fixture.writeAuth(main, account: "synthetic-main", refresh: "main-refresh")
        try Fixture.writeAuth(extra, account: "synthetic-extra", refresh: "extra-refresh")
        let accounts = Discovery$Real().discover()
        try expect(accounts.count == 2, "Expected both Codex accounts")
        try expect(Set(accounts.map(\.id)).count == 2, "Main and default profile share one ID")
        try expect(accounts.filter(\.isActive).count == 1, "Two accounts marked active")
        let profile = accounts.first { $0.profileName == "default" }!
        try AuthSwap$Codex.activate(columnID: profile.id, home: extra)
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "synthetic-extra", "Wrong account activated")
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: main)?.accountID == "synthetic-main", "Main sign-in not restored")
        try AccountRemoval.remove(profile)
        try expect(Foundation.FileManager.default.fileExists(atPath: main.appendingPathComponent("auth.json").path),
                   "Removing default profile removed main sign-in")
        try expect(!Foundation.FileManager.default.fileExists(atPath: extra.path),
                   "Profile not removed: source=\(profile.source), root=\(ProfileDirectories.codexRoot.path), folder=\(extra.path)")
    }

    private static func lostResponse() async throws {
        let account = try Fixture.codexAccount("lost")
        Fixture.response = .lost
        _ = await Provider$Codex().fetch(account)
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Lost response reused refresh token: \(Fixture.refreshCalls) POSTs")
    }

    private static func profileCollision() throws {
        let names = ["default", "profile:default", "profile:profile:default", "work"]
        try Fixture.writeAuth(AuthSwap$Codex.baseHome, account: "synthetic-main", refresh: "main-refresh")
        for name in names {
            try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent(name),
                                  account: "synthetic-" + name, refresh: "refresh-" + name)
        }
        let accounts = Discovery$Real().discover()
        try expect(accounts.count == names.count + 1, "Imported profiles missing")
        try expect(Set(accounts.map(\.id)).count == accounts.count, "Imported profiles share an ID")
        try expect(AuthSwap$Codex.profileColumnID("work") == "codex:work", "Existing ordinary profile ID changed")
        for name in names {
            let account = accounts.first { $0.profileName == name }!
            guard case .codexHome(let home) = account.source else { continue }
            try AuthSwap$Codex.activate(columnID: account.id, home: home)
            try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.baseHome)?.accountID == "synthetic-" + name,
                       "Switching imported profile chose another account")
            try expect(Discovery$Real().discover().filter(\.isActive).count == 1, "Multiple imported profiles active")
        }
        try AuthSwap$Codex.restoreDefault()
        let imported = accounts.first { $0.profileName == "profile:default" }!
        try AccountRemoval.remove(imported)
        try expect(Discovery$Real().discover().count == names.count, "Wrong number of profiles after removal")
        try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.baseHome)?.accountID == "synthetic-main",
                   "Imported profile removal changed main account")
    }

    private static func profileActiveMigration() throws {
        let name = "profile:default"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        try Fixture.writeAuth(AuthSwap$Codex.baseHome, account: "synthetic-main", refresh: "main-refresh")
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        try Fixture.writeAuth(ProfileDirectories.codexRoot.appendingPathComponent("default"),
                              account: "synthetic-default-profile", refresh: "default-refresh")
        try AuthSwap$Codex.activate(columnID: AuthSwap$Codex.profileColumnID(name), home: home)
        UserDefaults.standard.set("codex:" + name, forKey: "codexAppAccountID")
        let accounts = Discovery$Real().discover()
        try expect(accounts.filter(\.isActive).count == 1, "Legacy active ID marks two profiles active")
        let active = accounts.first(where: \.isActive)!
        try expect(active.profileName == name, "Legacy active ID migrated to the wrong profile")
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == "synthetic-imported",
                   "Legacy migration saved live credentials to the wrong profile")
        try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.baseHome)?.accountID == "synthetic-main",
                   "Legacy migration did not restore main account")
    }

    @MainActor
    private static func profileSettingsMigration() throws {
        let name = "profile:work"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        UserDefaults.standard.set(["codex:" + name], forKey: "hiddenColumns")
        UserDefaults.standard.set(["codex:" + name: "Private account"], forKey: "columnNames")
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.columns.count == 1, "Imported profile missing")
        try expect(store.visibleColumns.isEmpty, "Previously hidden imported profile became visible")
        try expect(store.columns[0].customName == "Private account", "Imported profile's custom name was lost")
    }

    @MainActor
    private static func profileSettingsExisting() throws {
        let name = "profile:work"
        let home = ProfileDirectories.codexRoot.appendingPathComponent(name)
        let currentID = AuthSwap$Codex.profileColumnID(name)
        try Fixture.writeAuth(home, account: "synthetic-imported", refresh: "imported-refresh")
        UserDefaults.standard.set(["codex:" + name], forKey: "hiddenColumns")
        UserDefaults.standard.set(["codex:" + name: "Legacy name", currentID: "Current name",
                                   "claude:unrelated": "Unrelated name"], forKey: "columnNames")
        let first = UsageStore(providers: [:], discovery: Discovery$Real())
        first.rediscover(force: true)
        try expect(first.columns[0].customName == "Current name", "Current custom name was overwritten")
        first.setCustomName("Edited name", for: currentID)
        first.setHidden(currentID, hidden: false)
        let restarted = UsageStore(providers: [:], discovery: Discovery$Real())
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
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
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
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
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
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Write failure reused refresh token: \(Fixture.refreshCalls) POSTs")
        try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-refresh-save",
                   "Fixture did not produce a real write failure")
        try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
        let outcome = await Provider$Codex().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Pending tokens not recovered after restoring write access") }
        try expect(Fixture.refreshCalls == 1, "Saving pending tokens made another refresh request")
        try expect(Renewal$Codex.refreshToken(home.appendingPathComponent("auth.json")) == "synthetic-rotated",
                   "Rotated tokens were lost")
    }

    private static func temporaryResponse() async throws {
        let account = try Fixture.codexAccount("temporary")
        Fixture.response = .temporary
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Temporary response retried in the same fetch")
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 2, "Explicit temporary response blocked later renewal")
    }

    private static func unreadableResponse() async throws {
        let account = try Fixture.codexAccount("unreadable")
        Fixture.response = .unreadable
        _ = await Provider$Codex().fetch(account)
        _ = await Provider$Codex().fetch(account)
        try expect(Fixture.refreshCalls == 1, "Unreadable success response reused refresh token")
    }

    private static func concurrentRefresh() async throws {
        let account = try Fixture.codexAccount("concurrent")
        Fixture.response = .delayedLost
        async let first = Provider$Codex().fetch(account)
        async let second = Provider$Codex().fetch(account)
        _ = await (first, second)
        try expect(Fixture.refreshCalls == 1, "Concurrent fetches reused refresh token: \(Fixture.refreshCalls) POSTs")
    }

    private static func claudeLoginChanged() async throws {
        let old = Fixture.claudeLogin("old-login", expired: true)
        let expected = AuthStorage$Claude.parse(old)!
        let fresh = OAuth$Claude.Tokens(accessToken: "synthetic-stale", expiresAt: Date().addingTimeInterval(3_600),
                                       refreshToken: "synthetic-stale-refresh", refreshTokenExpiresAt: nil, scopes: nil)
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        #if LEGACY_CLAUDE_SAVE
        _ = AuthStorage$Claude.save(service: Fixture.service, tokens: fresh)
        #else
        _ = AuthStorage$Claude.save(service: Fixture.service, tokens: fresh, expected: expected)
        #endif
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Stale refresh response overwrote newer Keychain login")

        Fixture.keychain = old
        Fixture.response = .changedClaude
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if case .success = outcome {} else { throw Failure(description: "New CLI login not used for usage") }
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Stale response cached after CLI login")
        try expect(Fixture.keychain["unknown"] as? String == "preserved", "Unrelated Keychain fields lost")
    }

    private static func claudePendingChanged() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.failKeychainSave = true
        let provider = Provider$Claude()
        let renewal = Task { await provider.fetch(Fixture.claudeAccount) }
        try await waitForFailedSave()
        Fixture.lock.lock()
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        Fixture.failKeychainSave = false
        Fixture.lock.unlock()
        _ = await renewal.value
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 1, "Pending save made another refresh request")
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Pending save replaced newer CLI login")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Old cached tokens survived CLI login")
    }

    private static func claudeWriteRace(afterRead: Int) async throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.changeLoginAfterRead = afterRead
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if Fixture.pendingCLILogin { Fixture.tryCLILogin() }
        try expect(Fixture.keychainReads >= afterRead, "Target Keychain read did not happen")
        if case .success = outcome {} else { throw Failure(description: "Usage did not complete") }
        try expect(!Fixture.pendingCLILogin, "CLI could not acquire the released storage lock")
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "Keychain write replaced a concurrent CLI login after read \(afterRead)")
    }

    private static func claudeLockBusy(stale: Bool) throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageLock, withIntermediateDirectories: true)
        if stale {
            try Foundation.FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-60)],
                                                             ofItemAtPath: Fixture.storageLock.path)
        }
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        try expect(!AuthStorage$Claude.canWrite(service: Fixture.service), "CLI-owned lock allowed a Keychain write")
        try expect(Fixture.keychainWrites == 0, "Busy storage lock still wrote credentials")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Another process's storage lock was removed")
    }

    private static func claudeLockLost() throws {
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.replaceLockAfterRead = 1
        try expect(!AuthStorage$Claude.canWrite(service: Fixture.service), "Lost storage lock allowed a Keychain write")
        try expect(Fixture.keychainWrites == 0, "Credentials written after storage lock changed owner")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Releasing a lost lock removed the CLI's replacement lock")
    }

    private static func claudeLockHeartbeat() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.slowKeychainRead = true
        let started = Date()
        let writer = Task.detached { AuthStorage$Claude.canWrite(service: Fixture.service) }
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
        let service = AuthStorage$Claude.baseService + "-" + suffix
        Fixture.expectedLock = profile.appendingPathComponent(".storage-write.lock")
        Fixture.keychain = Fixture.claudeLogin("work", expired: true)
        try expect(AuthStorage$Claude.canWrite(service: service), "Main profile's lock blocked a separate profile")
        try expect(Fixture.observedProfileLock, "Extra profile write did not acquire that profile's CLI lock")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageLock.path),
                   "Extra profile write removed main profile's lock")
    }

    private static func claudeNativeLogin(writeBoundary: Bool = false) async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = writeBoundary ? .renewed : .nativeLogin
        Fixture.loginAtWriteBoundary = writeBoundary
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if case .success = outcome {} else { throw Failure(description: "Renewal did not complete") }
        try expect(Fixture.nativeLoginPending, "Native CLI login entered during the refresh HTTP request")
        try expect(Fixture.oauthHeldDuringPOST && Fixture.oauthHeldDuringWrite,
                   "OAuth locks did not cover the entire read/refresh/save cycle")
        try expect(Fixture.noninteractiveWrites, "Keychain write could display a dialog while holding OAuth locks")
        try expect(Fixture.interactionAllowed, "Legacy Keychain interaction policy was not restored")
        Fixture.tryNativeLogin()
        try expect(!Fixture.nativeLoginPending, "OAuth locks were not released after saving")
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.accessToken == "synthetic-new-login",
                   "CLI login after renewal did not survive")
    }

    private static func claudeNoWritePermission() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.denyNoninteractiveWrite = true
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if case .failure = outcome {} else { throw Failure(description: "Missing write permission did not defer renewal") }
        try expect(Fixture.refreshCalls == 0, "Renewal spent a refresh token without noninteractive write permission")
        try expect(Fixture.interactionAllowed, "Failed Keychain preflight did not restore interaction policy")
        try expect(!Fixture.holdsOAuthLocks, "Failed Keychain preflight leaked OAuth locks")
    }

    private static func claudeOAuthHeartbeat() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .slowRenewed
        let started = Date()
        let renewal = Task { await Provider$Claude().fetch(Fixture.claudeAccount) }
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
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
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
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 0, "Used credentials read before acquiring the OAuth locks")
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Did not adopt the login committed before lock acquisition")
    }

    private static func claudeConcurrentRefresh() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .delayedRenewed
        let provider = Provider$Claude()
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
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
        try expect(Fixture.keychainWrites == 1, "Saved credentials after losing the OAuth lease")
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.accessToken == "synthetic-old-login", "Lost lease changed credentials")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path), "Released another OAuth lock owner")
    }

    private static func claudeCacheLogin() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        let provider = Provider$Claude()
        _ = await provider.fetch(Fixture.claudeAccount)
        Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.lastAuthorization == "Bearer synthetic-new-login", "Usage retained a cached token from the previous CLI login")
        try expect(Fixture.refreshCalls == 0, "Changing to a live login unnecessarily refreshed it")
    }

    private static func claudeNetworkRecovery() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .lost
        let provider = Provider$Claude()
        let failed = await provider.fetch(Fixture.claudeAccount)
        if case .failure = failed {} else { throw Failure(description: "Network error incorrectly requested login") }
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-refresh-old-login", "Network failure erased credentials")
        try expect(!Fixture.holdsOAuthLocks, "Network error leaked OAuth locks")
        Fixture.response = .renewed
        let recovered = await provider.fetch(Fixture.claudeAccount)
        if case .success = recovered {} else { throw Failure(description: "Renewal did not recover after network returned") }
        try expect(Fixture.refreshCalls == 2, "Network recovery failed to retry on the next polling cycle")
    }

    private static func claudeRefreshNoRetry() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
        try expect(!Fixture.allowHTTPRetry, "Rotating Claude refresh POST enabled automatic HTTP retries")
    }

    private static func claudeRefreshForbidden() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.response = .forbidden
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if case .failure = outcome {} else { throw Failure(description: "Regional/proxy 403 incorrectly requested login") }
        try expect(!Fixture.holdsOAuthLocks, "Forbidden response leaked OAuth locks")
    }

    private static func claudeUsageForbidden() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.usageStatus = 403
        let provider = Provider$Claude()
        _ = await provider.fetch(Fixture.claudeAccount)
        _ = await provider.fetch(Fixture.claudeAccount)
        try expect(Fixture.refreshCalls == 0, "Usage 403 caused unnecessary refresh-token rotation")
    }

    private static func claudeOAuthProfile() async throws {
        let profile = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        Fixture.expectedOAuthDirectory = profile
        let suffix = SHA256.hash(data: Data(profile.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = AuthStorage$Claude.baseService + "-" + suffix
        let account = DiscoveredAccount(id: "claude:work", provider: .claude, profileName: "work",
                                        source: .claudeKeychain(service: service, configDir: profile))
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory.appendingPathComponent(".oauth_refresh.lock"), withIntermediateDirectories: true)
        Fixture.keychain = Fixture.claudeLogin("work", expired: true)
        let outcome = await Provider$Claude().fetch(account)
        if case .success = outcome {} else { throw Failure(description: "Main OAuth lock blocked a separate profile") }
        try expect(Fixture.oauthHeldDuringPOST && Fixture.oauthHeldDuringWrite, "Profile did not use its own OAuth locks")
        try expect(!Fixture.holdsOAuthLocks, "Profile OAuth locks were not released")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.storageDirectory.appendingPathComponent(".oauth_refresh.lock").path), "Profile renewal removed main lock")
    }

    @MainActor
    private static func switchSuccessfully(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        var result: Result<Void, Error>?
        AppSwitcher$Claude().switchTo(account) { result = $0 }
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
        let provider = Provider$Claude()
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
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated", "Rotated credentials were not saved")
        try expect(!Fixture.holdsOAuthLocks, "Successful persistence leaked OAuth locks")
    }

    private static func claudeQuitPending() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.failKeychainSave = true
        let provider = Provider$Claude()
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
        let provider = Provider$Claude()
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
        let durableAtQuit = AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated"
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
        AppSwitcher$Claude().switchTo(account) { result = $0 }
        if case .failure? = result {} else { throw Failure(description: "Desktop launch failure was not reported") }
        let selected = try? String(contentsOf: pointer)
        try expect(selected == (first ? "\n" : "/previous/cli/profile\n"), "Failed Desktop launch changed CLI account or broke first-use CLI routing")
        try expect(UserDefaults.standard.string(forKey: "currentClaudeAppAccount") == "previous-desktop", "Failed launch committed the Desktop marker")
        Fixture.desktopFails = false
        AppSwitcher$Claude().switchTo(account) { result = $0 }
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
        AppSwitcher$Claude().switchTo(Fixture.claudeAccount) { first = $0 }
        try expect((try String(contentsOf: pointer)) == "/previous/cli/profile\n", "Pending Desktop launch exposed an uncommitted CLI selection")
        AppSwitcher$Claude().switchTo(Fixture.claudeAccount) { second = $0 }
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
        AppSwitcher$Claude().switchTo(Fixture.claudeAccount) { result = $0 }
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
        AppSwitcher$Claude().switchTo(Fixture.claudeAccount) { result = $0 }
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
        let provider = Provider$Claude()
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
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
            try expect(Fixture.keychainExists && AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated",
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
        let provider = Provider$Claude()
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
        try expect(AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == (expired ? "synthetic-rotated" : "synthetic-refresh-readded-login"),
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
        let provider = Provider$Claude()
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
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
        let provider = Provider$Claude()
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
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
        if !enabled { CLISelection$Claude.isEnabled = false }
        let previous = Fixture.root.appendingPathComponent("previous-cli")
        try Foundation.FileManager.default.createDirectory(at: previous, withIntermediateDirectories: true)
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = previous.path + "\n"
        try Data(original.utf8).write(to: pointer)
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.denyKeychainDelete = denied
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        Fixture.holdDesktopCompletion = true
        var result: Result<Void, Error>?
        AppSwitcher$Claude().switchTo(account) { result = $0 }
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
            try expect(AppSwitcher$Claude().isOpenInApp(columnID: account.id) == false,
                       "A launch prepared for the removed account marked its replacement as open")
        }
    }

    @MainActor
    private static func claudeStaleUsageResult() async throws {
        let (profile, account) = try claudeRemovableProfile()
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
        Fixture.holdFirstUsage = true
        let provider = Provider$Claude()
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
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
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
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
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
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
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
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
        if !enabled { CLISelection$Claude.isEnabled = false }
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
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
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
        try expect(AppSwitcher$Claude().isOpenInApp(columnID: account.id) == false,
                   "The retired Desktop session was shown as the re-added account")
        let second = try switchSuccessfully(account)
        let replacement = try desktopDirectory(second.arguments)
        try expect(replacement != directory && !Foundation.FileManager.default.fileExists(atPath: replacement.appendingPathComponent(session.lastPathComponent).path),
                   "Re-added account reused the removed Desktop session, including writes from an old process")
        try expect(try String(contentsOf: pointer) == (enabled ? (profile?.path ?? "") + "\n" : original),
                   "Re-added Desktop switch did not respect Switch CLI")
        try expect(try String(contentsOf: unrelated) == "other", "Deletion changed another Desktop account")
        try expect(AppSwitcher$Claude().isOpenInApp(columnID: account.id) == true, "Replacement Desktop was not marked open")
    }

    private static func claudeNativePublish() async throws {
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        Fixture.nativeAcquisitionAtPublish = true
        _ = await Provider$Claude().fetch(Fixture.claudeAccount)
        try expect(Fixture.nativeAcquisitionObserved, "Fixture did not acquire the native path before publication")
        try expect(Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path), "Publication replaced the native owner's lock")
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0, "A competing native owner did not defer renewal")
    }

    private static func claudeCrashLegacyOwner() throws {
        guard let lease = AuthStorage$Claude.refreshLock(service: Fixture.service) else {
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
        guard let lease = AuthStorage$Claude.refreshLock(service: Fixture.service) else {
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
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if expectBusy {
            try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0, "Recovery stole an active or replacement owner's lock")
            try expect(Fixture.holdsOAuthLocks, "Busy owner lost its OAuth locks")
        } else {
            if case .success = outcome {} else { throw Failure(description: "Abandoned Notchlimits OAuth locks permanently blocked renewal") }
            try expect(Fixture.refreshCalls == 1, "Recovered profile did not renew exactly once")
            try expect(!Fixture.holdsOAuthLocks, "Recovered OAuth locks were not released")
        }
    }

    @MainActor
    private static func claudeCanonicalMain(staleRemoval: Bool = false) throws {
        Fixture.keychainExists = false
        let owner = ProfileDirectories.claudeRoot.appendingPathComponent("native-base")
        try Foundation.FileManager.default.createDirectory(at: owner, withIntermediateDirectories: true)
        let file = owner.appendingPathComponent(".credentials.json")
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("primary", expired: false)).write(to: file)
        let settings = owner.appendingPathComponent("settings.json")
        try Data("native-settings".utf8).write(to: settings)
        try Foundation.FileManager.default.createSymbolicLink(at: Fixture.storageDirectory, withDestinationURL: owner)
        let hash = SHA256.hash(data: Data(owner.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let duplicate = DiscoveredAccount(id: "claude:" + Fixture.service + "-" + hash,
                                          provider: .claude, profileName: "native-base",
                                          source: .claudeKeychain(service: Fixture.service + "-" + hash, configDir: owner))
        if staleRemoval {
            // A stale file alias may be refused or remove only a missing service.
            _ = try? AccountRemoval.remove(duplicate)
            try expect(Foundation.FileManager.default.fileExists(atPath: settings.path)
                       && AuthStorage$Claude.credentials(service: Fixture.service) != nil,
                       "A stale alias column removed the main Claude login and configuration")
            try expect(!AccountRemoval.isExtraProfile(duplicate), "A canonical main alias was classified as disposable")
        } else {
            let found = Discovery$Real().discover().filter { $0.provider == .claude }
            try expect(found.map(\.id) == ["claude:" + Fixture.service],
                       "One physical main Claude home was discovered as two file-backed logins")
        }
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(!RegressionProfileMenu(store: store).profiles().contains { $0.url.path == owner.path },
                   "The main Claude home was offered as an unfinished extra profile")
        try store.removeAccount(id: "claude:" + Fixture.service)
        try expect(!Foundation.FileManager.default.fileExists(atPath: file.path)
                   && (try String(contentsOf: settings)) == "native-settings",
                   "Primary removal deleted native configuration instead of credentials only")
        try expect(!RegressionProfileMenu(store: store).profiles().contains { $0.url.path == owner.path },
                   "Logged-out native Claude configuration became an unfinished extra profile")
    }

    private static func claudeOwnerFallback(preflight: Bool = false, malformed: Bool = false) async throws {
        let (account, file) = try claudeFileAccount()
        Fixture.keychainExists = true
        Fixture.keychain = Fixture.claudeLogin("keychain-owner", expired: true)
        let originalKeychain = try JSONSerialization.data(withJSONObject: Fixture.keychain, options: [.sortedKeys])
        let originalFile = try Data(contentsOf: file)
        Fixture.denyClaudeRead = !preflight && !malformed
        Fixture.denyClaudeReadAt = preflight ? 3 : 0
        Fixture.malformedClaudeRead = malformed
        let provider = Provider$Claude()
        _ = await provider.fetch(account)
        let unchanged = try JSONSerialization.data(withJSONObject: Fixture.keychain, options: [.sortedKeys]) == originalKeychain
        try expect(Fixture.refreshCalls == 0 && unchanged && (try Data(contentsOf: file)) == originalFile,
                   "Claude spent a fallback grant while the preferred Keychain owner was unavailable")
        Fixture.denyClaudeRead = false
        Fixture.denyClaudeReadAt = 0
        Fixture.malformedClaudeRead = false
        let result = await provider.fetch(account)
        if case .success = result {} else { throw Failure(description: "Claude renewal did not resume after Keychain recovery") }
        try expect(Fixture.refreshCalls == 1 && Fixture.refreshInput == "synthetic-refresh-keychain-owner"
                   && AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated",
                   "Recovered Keychain login did not renew using its own grant")
        try expect(try Data(contentsOf: file) == originalFile, "Keychain recovery changed the unrelated fallback")
    }

    @MainActor
    private static func codexRootSymlink(mode: String) throws {
        let physical = Fixture.root.appendingPathComponent("physical-profiles")
        let profile = physical.appendingPathComponent("linked-owner")
        try Fixture.codexLogin(profile, account: "linked-owner", mode: mode)
        try Fixture.codexLogin(AuthSwap$Codex.baseHome, account: "primary", mode: "file")
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: physical)
        let logical = ProfileDirectories.codexRoot.appendingPathComponent("linked-owner")
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let id = "codex:linked-owner"
        guard let account = store.account(for: id), case .codexHome(let discovered) = account.source else {
            throw Failure(description: "A symlinked Codex profile root hid a valid login")
        }
        try expect(discovered.path == logical.path && Provider$Codex.readAuth(codexHome: logical)?.accountID == "linked-owner",
                   "Discovery did not retain the logical profile path and canonical Keychain identity")
        try AuthSwap$Codex.activate(columnID: id, home: logical)
        try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.baseHome)?.accountID == "linked-owner",
                   "A profile under a symlinked root could not activate")
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: AuthSwap$Codex.baseHome)?.accountID == "primary",
                   "Switching under a symlinked root lost the primary login")
        Fixture.denyCodexDelete = mode == "keyring"
        if Fixture.denyCodexDelete {
            var refused = false
            do { try store.removeAccount(id: id) } catch { refused = true }
            try expect(refused && Provider$Codex.readAuth(codexHome: logical)?.accountID == "linked-owner",
                       "Refused deletion did not restore the symlinked profile")
        }
        Fixture.denyCodexDelete = false
        try store.removeAccount(id: id)
        try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Removal left the profile name occupied")
        try Fixture.codexLogin(logical, account: "replacement", mode: mode)
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil && Provider$Codex.readAuth(codexHome: logical)?.accountID == "replacement",
                   "A profile under a symlinked root could not be re-added")
    }

    @MainActor
    private static func readdDuringRemovalUsage(codex: Bool) async throws {
        let account: DiscoveredAccount
        let home: URL
        if codex {
            home = ProfileDirectories.codexRoot.appendingPathComponent("readd-overlap")
            try Fixture.codexLogin(home, account: "old-owner", mode: "keyring")
            account = DiscoveredAccount(id: "codex:readd-overlap", provider: .codex,
                                        profileName: "readd-overlap", source: .codexHome(home))
        } else {
            let found = try claudeFileAccount(primary: false, expired: false)
            account = found.0; home = found.1.deletingLastPathComponent()
        }
        Fixture.holdFirstUsage = true
        defer { Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock() }
        let store = UsageStore(providers: [.codex: Provider$Codex(), .claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        store.setCustomName("old-owner-name", for: account.id)
        store.refreshAll()
        for _ in 0..<200 {
            if Fixture.usageCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.usageCalls == 1, "Old usage request did not reach its response barrier")
        Fixture.beforeCredentialDelete = {
            if codex { try! Fixture.codexLogin(home, account: "replacement", mode: "file") }
            else {
                try! Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
                try! JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
                    .write(to: home.appendingPathComponent(".credentials.json"))
            }
        }
        try store.removeAccount(id: account.id)
        store.refreshAll()
        var fresh = false
        for _ in 0..<200 {
            fresh = store.columns.first { $0.id == account.id }?.windows.first?.utilization == 84
            if fresh { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(fresh && Fixture.usageCalls == 2, "Same-name re-add during removal permanently stopped usage polling")
        try expect(store.columns.first { $0.id == account.id }?.customName == nil,
                   "Replacement column inherited the removed generation's custom name")
        Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        for _ in 0..<200 {
            if Fixture.usageCompletions == 2 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        try expect(Fixture.usageCompletions == 2
                   && store.columns.first { $0.id == account.id }?.windows.first?.utilization == 84
                   && UsageCache().load(id: account.id)?.windows.first?.utilization == 84,
                   "Removed generation's late usage reply replaced the new profile's result or cache")
    }

    private static func claudeUnsupportedCLI() async throws {
        Fixture.cliVersion = "2.0.0"
        Fixture.keychain = Fixture.claudeLogin("old-login", expired: true)
        let outcome = await Provider$Claude().fetch(Fixture.claudeAccount)
        if case .reauth = outcome {} else { throw Failure(description: "Unsupported CLI did not defer renewal to CLI login") }
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0,
                   "Unsupported CLI's credentials were renewed or written without a shared protocol")
    }

    @MainActor
    private static func codexRetiredUsage401(sameGrant: Bool = false, relogin: Bool = false) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("late-401")
        try Fixture.codexLogin(home, account: "old", mode: "keyring", expired: false)
        let account = DiscoveredAccount(id: "codex:late-401", provider: .codex,
                                        profileName: "late-401", source: .codexHome(home))
        Fixture.holdFirstUsage = true
        Fixture.firstUsageStatus = 401
        defer { Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock() }
        let provider = Provider$Codex()
        let old = Task { await provider.fetch(account) }
        for _ in 0..<200 {
            if Fixture.usageCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.usageCalls == 1, "Old usage request did not reach its barrier")
        let original = Fixture.codexKeychain[Fixture.codexKey(home)]
        if !relogin { try AccountRemoval.remove(account) }
        try Fixture.codexLogin(home, account: "replacement", mode: "keyring", expired: false)
        if sameGrant { Fixture.codexKeychain[Fixture.codexKey(home)] = original }
        let expected = Fixture.codexKeychain[Fixture.codexKey(home)]
        _ = await provider.fetch(account)
        Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        _ = await old.value
        print("Refresh POSTs caused by an old generation's 401: \(Fixture.refreshCalls); submitted grant: \(Fixture.refreshInput)")
        try expect(Fixture.refreshCalls == 0 && Fixture.codexKeychain[Fixture.codexKey(home)] == expected,
                   "A retired generation's late usage 401 refreshed the replacement login")
    }

    private static func codexCopybackRelogin(mode: String = "keyring", baseMode: String = "file", legacy: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("same-account")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("other")
        try Fixture.codexLogin(base, account: "primary", mode: baseMode)
        try Fixture.codexLogin(profile, account: "same-account", mode: mode)
        try Fixture.codexLogin(other, account: "other", mode: "file")
        try AuthSwap$Codex.activate(columnID: "codex:same-account", home: profile)
        if legacy { UserDefaults.standard.removeObject(forKey: "codexAppSourceAuth") }
        let oldNative = try AuthSwap$Codex.authData(home: base)
        var replacement = try JSONSerialization.jsonObject(with: AuthSwap$Codex.authData(home: profile)!) as! [String: Any]
        var tokens = replacement["tokens"] as! [String: Any]
        tokens["refresh_token"] = "new-cli-session-grant"
        tokens["access_token"] = "new-cli-session-access"
        replacement["tokens"] = tokens
        let expected = try JSONSerialization.data(withJSONObject: replacement)
        if mode == "file" { try expected.write(to: profile.appendingPathComponent("auth.json"), options: .atomic) }
        else { Fixture.codexKeychain[Fixture.codexKey(profile)] = expected }
        try AuthSwap$Codex.activate(columnID: "codex:other", home: other)
        let actual = Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json"))
        print("Profile grant after a completed CLI re-login and Desktop switch: \(actual ?? "nil")")
        try expect(actual == "new-cli-session-grant", "Copyback replaced a completed CLI re-login for the same account with the old Desktop session")
        let archives = try Foundation.FileManager.default.contentsOfDirectory(at: AuthSwap$Codex.stashHome.deletingLastPathComponent(), includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("orphaned-") }
        let retained = archives.contains { (try? AuthSwap$Codex.authData(home: $0)) == oldNative }
        try expect(retained, "The current native session was not recoverable from its original storage backend")
        try AuthSwap$Codex.activate(columnID: "codex:same-account", home: profile)
        try expect(Renewal$Codex.refreshToken(base.appendingPathComponent("auth.json")) == "new-cli-session-grant", "A later switch did not use the completed CLI re-login")
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary", "Preserving a newer CLI login lost the primary backup")
    }

    @MainActor
    private static func codexRemovalSelectionRollback(mode: String = "keyring", primary: Bool = false,
                                                       nativeProgress: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("active-denied")
        try Fixture.codexLogin(base, account: "primary", mode: primary ? "keyring" : "file")
        try Fixture.codexLogin(profile, account: "selected", mode: mode)
        let id = "codex:active-denied"
        try AuthSwap$Codex.activate(columnID: id, home: profile)
        if nativeProgress { try Fixture.writeAuth(base, account: "selected", refresh: "native-progress", expired: false) }
        let expected = try AuthSwap$Codex.authData(home: base)
        Fixture.desktopRunning = true
        Fixture.denyCodexDelete = mode != "file" || primary
        Fixture.denyCredentialFileRemoval = mode == "file" && !primary
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let result: Result<Void, Error> = await withCheckedContinuation { c in
            store.removeAccount(id: primary ? AuthSwap$Codex.defaultColumnID : id) { c.resume(returning: $0) }
        }
        let failed: Bool
        if case .failure = result { failed = true } else { failed = false }
        try expect(failed && AuthSwap$Codex.activeColumnID == id && (try AuthSwap$Codex.authData(home: base)) == expected,
                   "A refused account deletion changed the CLI login and active selection instead of rolling them back")
        Fixture.denyCodexDelete = false
        Fixture.denyCredentialFileRemoval = false
        if nativeProgress {
            // A successful copyback before the refused delete becomes the next
            // source baseline; another native refresh must still copy back later.
            try Fixture.writeAuth(base, account: "selected", refresh: "native-after-rollback", expired: false)
            let other = ProfileDirectories.codexRoot.appendingPathComponent("after-rollback")
            try Fixture.codexLogin(other, account: "other", mode: "file")
            try AuthSwap$Codex.activate(columnID: "codex:after-rollback", home: other)
            try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "native-after-rollback",
                       "Selection rollback restored an obsolete source identity and stranded a later native rotation")
        }
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary", "Failed removal discarded the only primary backup")
    }

    @MainActor
    private static func nativeParentRemoval(codex: Bool) async throws {
        let parent = (codex ? ProfileDirectories.codexRoot : ProfileDirectories.claudeRoot).appendingPathComponent("container")
        let native = parent.appendingPathComponent("native-home")
        let account: DiscoveredAccount
        if codex {
            Fixture.codexHome = native.path
            try Fixture.codexLogin(native, account: "primary", mode: "file")
            try Fixture.codexLogin(parent, account: "extra", mode: "keyring")
            account = DiscoveredAccount(id: "codex:container", provider: .codex, profileName: "container", source: .codexHome(parent))
        } else {
            Fixture.keychainExists = false
            try Foundation.FileManager.default.createDirectory(at: native, withIntermediateDirectories: true)
            try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("primary", expired: false)).write(to: native.appendingPathComponent(".credentials.json"))
            try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("extra", expired: false)).write(to: parent.appendingPathComponent(".credentials.json"))
            try Foundation.FileManager.default.createSymbolicLink(at: Fixture.storageDirectory, withDestinationURL: native)
            let hash = SHA256.hash(data: Data(parent.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
            account = DiscoveredAccount(id: "claude:" + Fixture.service + "-" + hash, provider: .claude,
                                        profileName: "container", source: .claudeKeychain(service: Fixture.service + "-" + hash, configDir: parent))
        }
        let project = native.appendingPathComponent("native-settings-and-projects")
        try Data("preserve-native-state".utf8).write(to: project)
        Fixture.desktopRunning = true
        let result: Result<Void, Error> = await withCheckedContinuation { c in
            AccountRemoval.remove(account) { c.resume(returning: $0) }
        }
        let retained = Foundation.FileManager.default.fileExists(atPath: project.path)
        print("Native child home retained: \(retained); Desktop stops: \(Fixture.desktopStops); removal result: \(result)")
        try expect(retained, "Deleting a managed parent profile removed the native main home nested beneath it")
        if codex { Fixture.codexKeychain[Fixture.codexKey(parent)] = nil }
        else { try Foundation.FileManager.default.removeItem(at: parent.appendingPathComponent(".credentials.json")) }
        let store = UsageStore(providers: [.codex: Provider$Codex(), .claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(!RegressionProfileMenu(store: store).profiles().contains { $0.url.path == parent.path },
                   "An unfinished parent profile containing the main home was offered for destructive deletion")
    }

    private static func codexUsageRegion403() async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("regional")
        try Fixture.codexLogin(home, account: "valid-login", mode: "keyring", expired: false)
        let account = DiscoveredAccount(id: "codex:regional", provider: .codex,
                                        profileName: "regional", source: .codexHome(home))
        Fixture.usageStatus = 403
        Fixture.usageErrorBody = Data(#"{"error":{"code":"unsupported_country_region_territory"}}"#.utf8)
        Fixture.response = .forbidden
        let outcome = await Provider$Codex().fetch(account)
        let asksForLogin: Bool
        if case .reauth = outcome { asksForLogin = true } else { asksForLogin = false }
        print("Usage region denial refresh POSTs: \(Fixture.refreshCalls); asks for login: \(asksForLogin)")
        try expect(Fixture.refreshCalls == 0 && !asksForLogin, "A regional usage 403 rotated a valid grant and requested another login")
    }


    @MainActor
    private static func claudeNativeHashedOwnerRemoval(shared: Bool = false) throws {
        let owner = ProfileDirectories.claudeRoot.appendingPathComponent("native-alias-login")
        try Foundation.FileManager.default.createDirectory(at: owner, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: Fixture.storageDirectory, withDestinationURL: owner)
        let settings = owner.appendingPathComponent("settings.json")
        try Data("native-settings".utf8).write(to: settings)
        let hash = SHA256.hash(data: Data(owner.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + hash
        Fixture.onlyClaudeService = service
        Fixture.discoveredClaudeService = service
        Fixture.keychain = Fixture.claudeLogin("native-hashed-owner", expired: false)
        let file = owner.appendingPathComponent(".credentials.json")
        let primary = Fixture.claudeLogin("primary-owner", expired: false)
        if shared {
            Fixture.onlyClaudeService = nil
            Fixture.claudeEntries = [Fixture.service: primary, service: Fixture.keychain]
            try JSONSerialization.data(withJSONObject: primary).write(to: file)
            CLISelection$Claude.isEnabled = false
        }
        let fallbackBefore = shared ? try Data(contentsOf: file) : nil
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let account = store.account(for: "claude:" + service)
        try expect(account != nil && AuthStorage$Claude.contains(service: Fixture.service) == shared,
                   "Fixture did not expose exactly one genuine hashed Keychain login")
        try expect(AuthStorage$Claude.configPath(for: service) == owner.path,
                   "The hashed Keychain service did not resolve to its exact native CLI path")
        var failed = false
        do { try store.removeAccount(id: "claude:" + service) } catch { failed = true }
        print("Genuine hashed Keychain owner deletion refused: \(failed); credentials retained: \(Fixture.keychainExists)")
        let removed = shared ? Fixture.claudeEntries?[service] == nil : !Fixture.keychainExists
        try expect(!failed && removed && Foundation.FileManager.default.fileExists(atPath: settings.path),
                   "Canonical main protection made a genuine independent hashed Keychain login undeletable")
        if shared {
            try expect(AuthStorage$Claude.credentials(service: Fixture.service)?.refreshToken == "synthetic-refresh-primary-owner"
                       && (try Data(contentsOf: file)) == fallbackBefore
                       && !CLISelection$Claude.isEnabled,
                       "Removing a hashed service changed the main login, fallback file or Switch CLI setting")
        }
    }

    @MainActor
    private static func claudeIncompleteRemoval(state: String) async throws {
        Fixture.keychainExists = false
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("unfinished-login")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let native = Fixture.storageDirectory.appendingPathComponent("settings.json")
        try Foundation.FileManager.default.createDirectory(at: native.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("preserve-main-config".utf8).write(to: native)
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let menu = RegressionProfileMenu(store: store)
        try expect(menu.profiles().contains { $0.url.path == directory.path }, "Fixture did not expose an unfinished profile")
        if state == "symlink" {
            let physical = Fixture.root.appendingPathComponent("physical-incomplete-profile")
            try Foundation.FileManager.default.moveItem(at: directory, to: physical)
            try Foundation.FileManager.default.createSymbolicLink(at: directory, withDestinationURL: physical)
        }
        let physical = directory.resolvingSymlinksInPath()
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous-cli-profile\n".utf8).write(to: pointer)
        CLISelection$Claude.isEnabled = false
        let hash = SHA256.hash(data: Data(directory.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + hash
        let current = directory.appendingPathComponent(".oauth_refresh.lock")
        let legacy = URL(fileURLWithPath: directory.resolvingSymlinksInPath().path + ".lock")
        let storage = directory.appendingPathComponent(".storage-write.lock")
        let nativeLocks: [URL]
        switch state {
        case "oauth": nativeLocks = [current, legacy, storage]
        case "legacy": nativeLocks = [legacy]
        case "storage": nativeLocks = [storage]
        default: nativeLocks = []
        }
        for lock in nativeLocks { try Foundation.FileManager.default.createDirectory(at: lock, withIntermediateDirectories: true) }
        // These changes happen after menu enumeration, while confirmation is open.
        if ["oauth", "keychain", "unreadable", "metadata-denied"].contains(state) {
            Fixture.claudeEntries = [service: Fixture.claudeLogin("completed-native-login", expired: false)]
        } else if ["stub", "stub-refusal"].contains(state) {
            Fixture.claudeEntries = [service: ["trustedDeviceToken": "synthetic-device-stub"]]
        }
        if state == "file" {
            try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("completed-file-login", expired: false))
                .write(to: directory.appendingPathComponent(".credentials.json"))
        }
        if state == "unreadable" { Fixture.denyClaudeRead = true }
        if state == "metadata-denied" { Fixture.denyClaudeMetadata = true }
        if state == "missing" { try Foundation.FileManager.default.removeItem(at: directory) }
        Fixture.denyKeychainDelete = state == "stub-refusal"
        var nativeWriterBlocked = false
        Fixture.expectedOAuthDirectory = directory
        Fixture.beforeCredentialDelete = {
            let acquired = Darwin.mkdir(legacy.path, 0o700)
            nativeWriterBlocked = acquired != 0 && errno == EEXIST
            if acquired == 0 { _ = Darwin.rmdir(legacy.path) }
        }
        menu.remove(path: directory.path)
        let succeeds = ["empty", "stub", "symlink"].contains(state)
        let retained = Foundation.FileManager.default.fileExists(atPath: directory.path)
        print("Unfinished profile state=\(state), directory retained=\(retained), error=\(String(describing: menu.failure))")
        try expect((menu.failure == nil) == succeeds && retained == (!succeeds && state != "missing"),
                   "Unfinished-profile deletion removed a native owner, new login or refused stub, or could not remove an empty profile")
        try expect(nativeLocks.allSatisfy { Foundation.FileManager.default.fileExists(atPath: $0.path) },
                   "Unfinished-profile deletion removed a native lock owner")
        for lock in [current, legacy, storage] where !nativeLocks.contains(lock) {
            try expect(!Foundation.FileManager.default.fileExists(atPath: lock.path), "Refused unfinished-profile deletion leaked a newly acquired lock")
        }
        if state == "stub" {
            try expect(nativeWriterBlocked && Fixture.claudeEntries?[service] == nil,
                       "Unfinished-profile deletion retained the native non-login stub or removed it without OAuth leases")
        } else if Fixture.claudeEntries != nil {
            try expect(Fixture.claudeEntries?[service] != nil, "Refused unfinished-profile deletion removed Keychain data")
        }
        if state == "file" {
            try expect(AuthStorage$Claude.credentials(service: service)?.refreshToken == "synthetic-refresh-completed-file-login",
                       "A completed fallback login was removed through a stale unfinished-profile menu")
        }
        try expect(try String(contentsOf: native) == "preserve-main-config"
                   && (try String(contentsOf: pointer)) == "/previous-cli-profile\n"
                   && !CLISelection$Claude.isEnabled && Fixture.desktopCalls == 0 && Fixture.desktopStops == 0,
                   "Unfinished-profile removal changed native settings, Desktop or CLI routing")
        if succeeds {
            try expect(!Foundation.FileManager.default.fileExists(atPath: physical.appendingPathComponent(".oauth_refresh.lock").path)
                       && !Foundation.FileManager.default.fileExists(atPath: physical.appendingPathComponent(".storage-write.lock").path),
                       "Successful unfinished-profile deletion leaked native locks in the physical directory")
            try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            Fixture.claudeEntries = [service: Fixture.claudeLogin("readded-owner", expired: false)]
            store.rediscover(force: true)
            try expect(store.account(for: "claude:" + service) != nil, "The removed unfinished profile could not be re-added")
        }
    }

    @MainActor
    private static func codexBackupRemovalRefusal(mode: String = "keyring", primary: Bool = true,
                                                 targetDenied: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("selected-for-primary-delete")
        let id = "codex:selected-for-primary-delete"
        try Fixture.codexLogin(base, account: "primary-to-delete", mode: mode)
        try Fixture.codexLogin(profile, account: "selected", mode: "file")
        try AuthSwap$Codex.activate(columnID: id, home: profile)
        let backup = AuthSwap$Codex.stashHome
        let expectedSelected = try AuthSwap$Codex.authData(home: base)
        let expectedPrimary = try AuthSwap$Codex.authData(home: backup)
        try expect(expectedPrimary != nil, "Fixture did not preserve a primary backup")
        if mode == "keyring" { Fixture.denyCodexDeleteAccount = Fixture.codexKey(targetDenied ? base : backup) }
        else { Fixture.denyCredentialFileRemovalPath = (targetDenied ? base : backup).appendingPathComponent("auth.json").path }
        Fixture.desktopRunning = true
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        let result: Result<Void, Error> = await withCheckedContinuation { c in
            store.removeAccount(id: primary ? AuthSwap$Codex.defaultColumnID : id) { c.resume(returning: $0) }
        }
        let failed: Bool
        if case .failure = result { failed = true } else { failed = false }
        print("Codex backup removal mode=\(mode), primary=\(primary), targetDenied=\(targetDenied), failure=\(failed), active=\(AuthSwap$Codex.activeColumnID)")
        try expect(failed && AuthSwap$Codex.activeColumnID == id
                   && (try AuthSwap$Codex.authData(home: base)) == expectedSelected
                   && (try AuthSwap$Codex.authData(home: backup)) == expectedPrimary
                   && store.account(for: AuthSwap$Codex.defaultColumnID) != nil && store.account(for: id) != nil
                   && Foundation.FileManager.default.fileExists(atPath: profile.path),
                   "A refused backup or target deletion reported success, changed selection, hid a live backup or removed the selected profile")
        try expect(Fixture.desktopStops == 1 && Fixture.desktopCalls == 0,
                   "Removal did not wait for Desktop exit without launching it")
        Fixture.denyCodexDeleteAccount = nil
        Fixture.denyCredentialFileRemovalPath = nil
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary-to-delete",
                   "A refused deletion lost the recoverable primary login")
        try expect(mode == "file" || Fixture.codexKeychain[Fixture.codexKey(backup)] == nil,
                   "Successful restoration did not remove the primary Keychain backup")
    }

    @MainActor
    private static func claudeSharedExtraDirectory(switchCLI: Bool = true, fallback: Bool = false,
                                                   metadataDenied: Bool = false) async throws {
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("shared-extra")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let settings = directory.appendingPathComponent("settings.json")
        try Data("shared-cli-settings".utf8).write(to: settings)
        func service(_ path: String) -> String {
            let hash = SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
            return Fixture.service + "-" + hash
        }
        let first = service(directory.path), second = service(directory.path + "/")
        Fixture.claudeEntries = [first: Fixture.claudeLogin("first-owner", expired: false),
                                second: Fixture.claudeLogin("second-owner", expired: false)]
        let file = directory.appendingPathComponent(".credentials.json")
        let fallbackData = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("second-owner", expired: false))
        if fallback { try fallbackData.write(to: file) }
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        guard let survivor = store.account(for: "claude:" + second) else { throw Failure(description: "Fixture did not discover the second Keychain owner") }
        try expect(store.account(for: "claude:" + first) != nil
                   && AuthStorage$Claude.configPath(for: second) == directory.path + "/",
                   "Fixture did not expose independent native path variants")
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous-cli-profile\n".utf8).write(to: pointer)
        CLISelection$Claude.isEnabled = switchCLI
        var switched: Result<Void, Error>?
        AppSwitcher$Claude().switchTo(survivor) { switched = $0 }
        if case .success? = switched {} else { throw Failure(description: "The surviving account did not switch Desktop before removal") }
        let expectedPointer = switchCLI ? directory.path + "/\n" : "/previous-cli-profile\n"
        try expect(try String(contentsOf: pointer) == expectedPointer, "CLI did not honor Switch CLI before removal")
        Fixture.denyClaudeMetadata = metadataDenied
        var failed = false
        do { try store.removeAccount(id: "claude:" + first) } catch { failed = true }
        let retained = Foundation.FileManager.default.fileExists(atPath: settings.path)
        let route = AuthStorage$Claude.configPath(for: second)
        print("Shared extra removal failed=\(failed), config retained=\(retained), route=\(route ?? "nil"), survivor retained=\(Fixture.claudeEntries?[second] != nil)")
        try expect(failed == metadataDenied && retained && route == directory.path + "/"
                   && Fixture.claudeEntries?[second] != nil
                   && (Fixture.claudeEntries?[first] != nil) == metadataDenied,
                   "Removing one Claude owner destroyed another account's config/route or ignored unavailable ownership metadata")
        if fallback { try expect(try Data(contentsOf: file) == fallbackData, "Shared removal changed another login's fallback file") }
        try expect(try String(contentsOf: pointer) == expectedPointer && CLISelection$Claude.isEnabled == switchCLI
                   && AppSwitcher$Claude().isOpenInApp(columnID: survivor.id) == true,
                   "Shared removal changed the survivor's Desktop/CLI selection")
        Fixture.denyClaudeMetadata = false
        if !metadataDenied {
            try store.removeAccount(id: survivor.id)
            try expect(!Foundation.FileManager.default.fileExists(atPath: directory.path)
                       && Fixture.claudeEntries?[second] == nil, "The final shared owner did not release its profile")
            try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            Fixture.claudeEntries = [second: Fixture.claudeLogin("readded-owner", expired: false)]
            store.rediscover(force: true)
            try expect(store.account(for: survivor.id) != nil, "The last removed shared profile could not be re-added")
        }
    }

    @MainActor
    private static func claudeSharedFileOwner() throws {
        let (account, file) = try claudeFileAccount(primary: false, expired: false)
        let directory = file.deletingLastPathComponent()
        let hash = SHA256.hash(data: Data((directory.path + "/").utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + hash
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: account.id) != nil, "Fixture did not discover the original file login")
        let before = try Data(contentsOf: file)
        Fixture.claudeEntries = [service: Fixture.claudeLogin("new-keychain-owner", expired: false)]
        var failed = false
        do { try store.removeAccount(id: account.id) } catch { failed = true }
        try expect(failed && (try Data(contentsOf: file)) == before && Fixture.claudeEntries?[service] != nil
                   && AuthStorage$Claude.configPath(for: service) == directory.path + "/",
                   "A stale file-only column deleted a newly shared directory or falsely reported removing the ambiguous fallback")
    }

    @MainActor
    private static func claudeBorrowedForeignCurrent() throws {
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("retry-after-collision")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let settings = directory.appendingPathComponent("settings.json")
        try Data("old-settings".utf8).write(to: settings)
        let hash = SHA256.hash(data: Data(directory.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + hash
        Fixture.claudeEntries = [service: Fixture.claudeLogin("pending-owner", expired: true)]
        let account = DiscoveredAccount(id: "claude:" + service, provider: .claude, profileName: "retry-after-collision",
                                        source: .claudeKeychain(service: service, configDir: directory))
        guard let lease = AuthStorage$Claude.refreshLock(service: service) else { throw Failure(description: "Fixture could not acquire the renewal lease") }
        defer { lease.release() }
        let foreign = directory.appendingPathComponent(".oauth_refresh.lock")
        Fixture.beforeCredentialDelete = {
            // Native mkdir precedes waiting on our adjacent legacy lock.
            try! Foundation.FileManager.default.createDirectory(at: foreign, withIntermediateDirectories: true)
            try! Data("new-native-settings".utf8).write(to: settings)
        }
        Fixture.denyKeychainDelete = true
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        try expect(refused && lease.isHeld && Foundation.FileManager.default.fileExists(atPath: foreign.path),
                   "Fixture did not retain both the borrowed lease and native replacement after rollback collision")
        var native = stat()
        try expect(lstat(foreign.path, &native) == 0, "Fixture could not identify the new native lock")
        Fixture.denyKeychainDelete = false
        var retryFailed = false
        do { try AccountRemoval.remove(account) } catch { retryFailed = true }
        var after = stat()
        let retained = lstat(foreign.path, &after) == 0 && after.st_ino == native.st_ino && after.st_dev == native.st_dev
        print("Retry failed=\(retryFailed), native current lock retained=\(retained), credentials retained=\(Fixture.claudeEntries?[service] != nil)")
        try expect(retryFailed && retained && Fixture.claudeEntries?[service] != nil && lease.isHeld,
                   "Retry borrowed a staged lease and bypassed the new native OAuth owner")
        _ = Darwin.rmdir(foreign.path)
        lease.release()
        try AccountRemoval.remove(account)
        try expect(Fixture.claudeEntries?[service] == nil && !Foundation.FileManager.default.fileExists(atPath: directory.path),
                   "Removal remained blocked after both prior owners released their locks")
    }

    @MainActor
    private static func claudeBorrowedNormalRetry() throws {
        let (_, account) = try claudeRemovableProfile()
        Fixture.keychain = Fixture.claudeLogin("retry-owner", expired: false)
        guard case .claudeKeychain(let service, _) = account.source,
              let lease = AuthStorage$Claude.refreshLock(service: service) else { throw Failure(description: "Fixture could not acquire the lease") }
        defer { lease.release() }
        Fixture.denyKeychainDelete = true
        var failed = false
        do { try AccountRemoval.remove(account) } catch { failed = true }
        try expect(failed && lease.isHeld, "Refused removal did not restore its own lease")
        Fixture.denyKeychainDelete = false
        try AccountRemoval.remove(account)
        try expect(!Fixture.keychainExists, "A valid borrowed lease could not be reused after ordinary rollback")
    }

    @MainActor
    private static func codexRestoreBackupRefusal(mode: String, nativeProgress: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("other-before-main-delete")
        let id = "codex:other-before-main-delete"
        try Fixture.codexLogin(base, account: "primary-to-delete", mode: mode)
        try Fixture.codexLogin(profile, account: "other", mode: "file")
        try AuthSwap$Codex.activate(columnID: id, home: profile)
        let backup = AuthSwap$Codex.stashHome
        if nativeProgress { try writeNativeCodexGrant(base, grant: "native-before-refused-restore") }
        let selected = try AuthSwap$Codex.authData(home: base)
        let primary = try AuthStorage$Codex(home: backup).load()?.data
        if mode == "file" { Fixture.denyCredentialFileRemovalPath = backup.appendingPathComponent("auth.json").path }
        else { Fixture.denyCodexDeleteAccount = Fixture.codexKey(backup) }
        var refused = false
        do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
        print("Restore mode=\(mode), refused=\(refused), active=\(AuthSwap$Codex.activeColumnID)")
        try expect(refused && AuthSwap$Codex.activeColumnID == id
                   && (try AuthSwap$Codex.authData(home: base)) == selected
                   && (try AuthStorage$Codex(home: backup).load()?.data) == primary,
                   "Restore reported success after refused cleanup or lost the selected login/primary backup")
        Fixture.denyCodexDeleteAccount = nil
        Fixture.denyCredentialFileRemovalPath = nil
        if nativeProgress {
            try writeNativeCodexGrant(base, grant: "native-after-refused-restore")
            try AuthSwap$Codex.restoreDefault()
            try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "native-after-refused-restore",
                       "Refused restore discarded the updated copyback identity for a later native rotation")
        } else { try AuthSwap$Codex.restoreDefault() }
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        try store.removeAccount(id: AuthSwap$Codex.defaultColumnID)
        try expect(try AuthStorage$Codex(home: backup).load() == nil,
                   "A prior cleanup refusal hid a live backup from later primary removal")
    }

    private static func writeNativeCodexGrant(_ home: URL, grant: String) throws {
        var root = try JSONSerialization.jsonObject(with: AuthSwap$Codex.authData(home: home)!) as! [String: Any]
        var tokens = root["tokens"] as! [String: Any]
        tokens["refresh_token"] = grant
        root["tokens"] = tokens
        try AuthStorage$Codex(home: home).save(JSONSerialization.data(withJSONObject: root))
    }

    @MainActor
    private static func codexLegacyBackupRemoval(mode: String, denied: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("legacy-hidden-backup")
        try Fixture.codexLogin(base, account: "legacy-primary", mode: mode)
        try Fixture.codexLogin(profile, account: "other", mode: "file")
        try AuthSwap$Codex.activate(columnID: "codex:legacy-hidden-backup", home: profile)
        let backup = AuthSwap$Codex.stashHome
        let primary = try AuthStorage$Codex(home: backup).load()!
        // Model state persisted by the old successful restore with refused cleanup.
        try AuthStorage$Codex(home: base).save(primary.data)
        for key in ["codexAppAccountID", "codexAppAccountHome", "codexAppStashStore", "codexAppSourceAuth"] {
            UserDefaults.standard.removeObject(forKey: key)
        }
        if denied { Fixture.denyCodexDeleteAccount = Fixture.codexKey(backup) }
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        var failed = false
        do { try store.removeAccount(id: AuthSwap$Codex.defaultColumnID) } catch { failed = true }
        let remaining = try AuthStorage$Codex(home: backup).load()?.data
        print("Legacy backup mode=\(mode), denied=\(denied), removal failed=\(failed), backup retained=\(remaining != nil)")
        try expect(failed == denied && (remaining != nil) == denied,
                   "Primary removal ignored an untracked native backup or its deletion refusal")
        if denied {
            try expect((try AuthSwap$Codex.authData(home: base)) == primary.data
                       && store.account(for: AuthSwap$Codex.defaultColumnID) != nil,
                       "Refused legacy-backup cleanup removed the primary login or column")
            Fixture.denyCodexDeleteAccount = nil
            try store.removeAccount(id: AuthSwap$Codex.defaultColumnID)
        }
        try expect(try AuthStorage$Codex(home: backup).load() == nil, "Successful primary removal retained legacy backup credentials")
    }

    @MainActor
    private static func claudePhysicalTrailingPath(action: String, switchCLI: Bool = true,
                                                   fallback: Bool = false) async throws {
        let physical = Fixture.root.appendingPathComponent("physical-profiles")
        try Foundation.FileManager.default.createDirectory(at: physical, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.claudeRoot, withDestinationURL: physical)
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.resolvingSymlinksInPath().path + "/"
        func service(_ path: String) -> String {
            Fixture.service + "-" + SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        }
        let selected = service(path)
        let first = service(directory.path)
        let settings = directory.appendingPathComponent("settings.json")
        try Data("shared-settings".utf8).write(to: settings)
        let provider = Provider$Claude()
        if action == "remove" {
            Fixture.claudeEntries = [first: Fixture.claudeLogin("first", expired: false),
                                    selected: Fixture.claudeLogin("selected", expired: false)]
        } else {
            Fixture.onlyClaudeService = selected
            Fixture.discoveredClaudeService = selected
            Fixture.keychain = Fixture.claudeLogin("selected", expired: action == "renew")
        }
        let store = UsageStore(providers: [.claude: provider], discovery: Discovery$Real())
        store.rediscover(force: true)
        guard let account = store.account(for: "claude:" + selected) else {
            throw Failure(description: "Fixture did not discover the physical trailing-path login")
        }
        if action == "renew" {
            Fixture.expectedOAuthDirectory = directory
            Fixture.expectedLock = directory.appendingPathComponent(".storage-write.lock")
            let outcome = await provider.fetch(account)
            if case .success = outcome {} else { throw Failure(description: "Physical trailing-path credentials could not renew") }
            try expect(Fixture.refreshCalls == 1 && Fixture.observedProfileLock
                       && Fixture.oauthHeldDuringPOST && Fixture.oauthHeldDuringWrite
                       && AuthStorage$Claude.parse(Fixture.keychain)?.refreshToken == "synthetic-rotated",
                       "Physical trailing-path renewal lost its grant or native lease protection")
            try expect(!Foundation.FileManager.default.fileExists(atPath: Fixture.oauthLock.path)
                       && !Foundation.FileManager.default.fileExists(atPath: Fixture.legacyLock.path),
                       "Physical trailing-path renewal stranded OAuth locks")
            return
        }
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        let previous = "/previous-cli-profile\n"
        try Data(previous.utf8).write(to: pointer)
        if !switchCLI { CLISelection$Claude.isEnabled = false }
        if action == "remove" {
            let file = directory.appendingPathComponent(".credentials.json")
            let data = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("selected", expired: false))
            if fallback { try data.write(to: file) }
            try store.removeAccount(id: "claude:" + first)
            try expect(Foundation.FileManager.default.fileExists(atPath: settings.path)
                       && Fixture.claudeEntries?[selected] != nil && Fixture.claudeEntries?[first] == nil,
                       "Removing a logical path owner destroyed the physical trailing-path owner's configuration")
            if fallback { try expect(try Data(contentsOf: file) == data, "Shared removal changed the survivor's fallback") }
        }
        _ = try switchSuccessfully(account)
        try expect(try String(contentsOf: pointer) == (switchCLI ? path + "\n" : previous),
                   "Physical trailing-path switching changed the service hash or ignored Switch CLI")
        try expect(AppSwitcher$Claude().isOpenInApp(columnID: account.id) == true,
                   "Physical trailing-path Desktop selection was not recorded")
        if action == "remove" {
            try store.removeAccount(id: account.id)
            try expect(!Foundation.FileManager.default.fileExists(atPath: directory.path)
                       && Fixture.claudeEntries?[selected] == nil, "The last physical owner could not remove its profile")
            try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            Fixture.claudeEntries = [selected: Fixture.claudeLogin("replacement", expired: false)]
            store.rediscover(force: true)
            guard let replacement = store.account(for: account.id) else { throw Failure(description: "Physical trailing-path profile could not be re-added") }
            _ = try switchSuccessfully(replacement)
            try expect(try String(contentsOf: pointer) == (switchCLI ? path + "\n" : previous),
                       "Re-added physical profile ignored its exact CLI path or setting")
        }
    }

    @MainActor
    private static func codexAutoFallbackRollback(failure: String, backupMode: String = "file",
                                                  nativeProgress: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("auto-selected")
        let id = "codex:auto-selected"
        if backupMode == "keyring" { try Fixture.codexLogin(base, account: "primary", mode: "auto") }
        else {
            try Fixture.writeAuth(base, account: "primary", refresh: "primary-refresh", expired: false)
            try Fixture.codexMode(base, "auto")
        }
        try Fixture.codexLogin(profile, account: "selected", mode: "keyring")
        Fixture.denyCodexWrite = backupMode == "file"
        try AuthSwap$Codex.activate(columnID: id, home: profile)
        Fixture.denyCodexWrite = false
        if backupMode == "keyring" {
            // A native auto file fallback survives until Keychain recovers.
            let selected = try AuthSwap$Codex.authData(home: base)!
            Fixture.codexKeychain[Fixture.codexKey(base)] = nil
            try selected.write(to: base.appendingPathComponent("auth.json"))
        }
        let backup = AuthSwap$Codex.stashHome
        let selected = try AuthStorage$Codex(home: base).load(verifyingOwner: true)!
        let primary = try AuthStorage$Codex(home: backup).load(verifyingOwner: true)!
        try expect(selected.backend == .file && primary.backend == (backupMode == "file" ? .file : .keyring),
                   "Fixture did not establish the original auto fallback and backup backends")
        let account = DiscoveredAccount(id: id, provider: .codex, profileName: "auto-selected", source: .codexHome(profile))
        if failure == "restore" {
            if backupMode == "file" { Fixture.denyCredentialFileRemovalPath = backup.appendingPathComponent("auth.json").path }
            else { Fixture.denyCodexDeleteAccount = Fixture.codexKey(backup) }
        } else if failure == "selected" { Fixture.denyCodexDeleteAccount = Fixture.codexKey(profile) }
        else if failure == "primary" { Fixture.denyCodexDeleteAccount = Fixture.codexKey(base) }
        var refused = false
        do {
            if failure == "selected" { try AccountRemoval.remove(account) }
            else if failure == "primary" {
                try AccountRemoval.remove(DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                                           profileName: "main", source: .codexHome(base)))
            } else { try AuthSwap$Codex.restoreDefault() }
        } catch { refused = true }
        let shouldFail = failure != "none"
        let actual = Provider$Codex.readAuth(codexHome: base)?.accountID
        print("Auto fallback operation=\(failure), backup=\(backupMode), refused=\(refused), live owner=\(actual ?? "nil")")
        try expect(refused == shouldFail && AuthSwap$Codex.activeColumnID == (shouldFail ? id : AuthSwap$Codex.defaultColumnID)
                   && actual == (shouldFail ? "selected" : "primary"),
                   "Auto rollback left a different native owner above the selected file fallback")
        if shouldFail {
            try expect((try AuthSwap$Codex.authData(home: base)) == selected.data
                       && (try AuthSwap$Codex.authData(home: backup)) == primary.data
                       && (try AuthSwap$Codex.authData(home: profile)) == selected.data,
                       "Refused auto rollback lost the selected grant, primary backup or profile copyback")
            let outcome = await Provider$Codex().fetch(account)
            if case .success = outcome {} else { throw Failure(description: "Rolled-back selection could not fetch usage") }
            try expect(Fixture.lastCodexAccount == "selected" && Fixture.refreshCalls == 0,
                       "Usage read a different account or renewed active native credentials after rollback")
        }
        Fixture.denyCredentialFileRemovalPath = nil
        Fixture.denyCodexDeleteAccount = nil
        if nativeProgress { try writeNativeCodexGrant(base, grant: "native-after-auto-rollback") }
        if shouldFail { try AuthSwap$Codex.restoreDefault() }
        try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID
                   && Provider$Codex.readAuth(codexHome: base)?.accountID == "primary"
                   && (try AuthSwap$Codex.authData(home: backup)) == nil,
                   "Auto rollback could not retry restoration and clean the primary backup")
        if nativeProgress {
            try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "native-after-auto-rollback",
                       "Auto rollback lost the source identity for subsequent native copyback")
        }
    }

    @MainActor
    private static func codexNativeCanonical(action: String, mode: String = "keyring") async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("native-canonical")
        try Fixture.writeAuth(home, account: "native-owner", refresh: "native-refresh", expired: action == "renew")
        let file = home.appendingPathComponent("auth.json")
        let original = try Data(contentsOf: file)
        let key = Fixture.codexKey(home)
        Fixture.codexKeychain[key] = original
        try Foundation.FileManager.default.removeItem(at: file)
        try Fixture.codexMode(home, mode)
        let account = DiscoveredAccount(id: "codex:native-canonical", provider: .codex,
                                        profileName: "native-canonical", source: .codexHome(home))
        if mode != "keyring" {
            try Fixture.writeAuth(home, account: "file-owner", refresh: "file-refresh", expired: false)
        }
        switch action {
        case "read":
            let expected = mode == "file" ? "file-owner" : "native-owner"
            let actual = Provider$Codex.readAuth(codexHome: home)?.accountID
            print("Native mode=\(mode), expected owner=\(expected), actual=\(actual ?? "nil")")
            try expect(actual == expected, "Native canonical Keychain ownership disagrees with Codex storage selection")
            try expect(Discovery$Real().discover().contains { $0.id == account.id }, "Native canonical login was hidden from discovery")
        case "save":
            try Fixture.writeAuth(home, account: "updated-owner", refresh: "updated-refresh", expired: false)
            let updated = try Data(contentsOf: file)
            try Foundation.FileManager.default.removeItem(at: file)
            try AuthStorage$Codex(home: home).save(updated)
            try expect(Fixture.codexKeychain[key] == updated && Fixture.codexKeychain.count == 1,
                       "Save created a shadow Keychain entry instead of updating the native canonical owner")
        case "remove":
            try AccountRemoval.remove(account)
            try expect(Fixture.codexKeychain[key] == nil && !Foundation.FileManager.default.fileExists(atPath: home.path),
                       "Successful removal left the real native Keychain login or its profile intact")
        case "renew":
            let outcome = await Provider$Codex().fetch(account)
            if case .success = outcome {} else { throw Failure(description: "Native canonical Keychain login could not renew") }
            try expect(Fixture.refreshCalls == 1 && Fixture.codexKeychain.count == 1
                       && Fixture.codexKeychain[key] != original
                       && Renewal$Codex.refreshToken(file) == "synthetic-rotated",
                       "Native canonical renewal lost its grant or wrote a shadow Keychain entry")
        case "switch":
            let base = AuthSwap$Codex.baseHome
            try Fixture.codexLogin(base, account: "primary", mode: "file")
            try AuthSwap$Codex.activate(columnID: account.id, home: home)
            try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "native-owner",
                       "Switch did not publish the native canonical Keychain login")
            try AuthSwap$Codex.restoreDefault()
            try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary"
                       && Fixture.codexKeychain[key] == original,
                       "Native canonical copyback lost the selected login or primary account")
        default: throw Failure(description: "Unknown canonical scenario")
        }
    }

    @MainActor
    private static func codexRetarget(action: String, reuseGrant: Bool = true) async throws {
        let first = Fixture.root.appendingPathComponent("physical-a")
        let second = Fixture.root.appendingPathComponent("physical-b")
        for root in [first, second] { try Foundation.FileManager.default.createDirectory(at: root, withIntermediateDirectories: true) }
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: first)
        let home = ProfileDirectories.codexRoot.appendingPathComponent("retargeted")
        try Fixture.writeAuth(home, account: "original", refresh: "original-refresh", expired: action != "usage")
        let file = home.appendingPathComponent("auth.json")
        let original = try Data(contentsOf: file)
        let account = DiscoveredAccount(id: "codex:retargeted", provider: .codex, profileName: "retargeted", source: .codexHome(home))
        let provider = Provider$Codex()
        let store = UsageStore(providers: [.codex: provider], discovery: Discovery$Real())
        store.rediscover(force: true)
        if action == "usage" {
            Fixture.holdFirstUsage = true
            Fixture.firstUsageStatus = 401
        } else if action == "pending" { Fixture.failCodexFileWrite = true }
        else { Fixture.response = .heldRenewed }
        let request = Task { await provider.fetch(account) }
        if action == "usage" {
            var started = false
            for _ in 0..<200 {
                Fixture.lock.lock(); started = Fixture.usageCalls > 0; Fixture.lock.unlock()
                if started { break }
                try await Task.sleep(nanoseconds: 1_000_000)
            }
            try expect(started, "Fixture did not pause the original usage request")
        } else {
            try await waitForRefresh(1)
            if action == "pending" { _ = await request.value }
        }
        try Foundation.FileManager.default.removeItem(at: ProfileDirectories.codexRoot)
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: second)
        try Fixture.writeAuth(home, account: "replacement", refresh: "replacement-refresh", expired: false)
        if ["remove", "usage"].contains(action) {
            try store.removeAccount(id: account.id)
            if action == "usage" {
                // Return to the old physical path: only the logical generation
                // can distinguish this re-addition from the retired usage request.
                try Foundation.FileManager.default.removeItem(at: ProfileDirectories.codexRoot)
                try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: first)
            } else { try Fixture.writeAuth(home, account: "replacement", refresh: "replacement-refresh", expired: false) }
        }
        if reuseGrant { try original.write(to: file) }
        let expected = try Data(contentsOf: file)
        if action == "usage" {
            Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        } else if action == "pending" {
            Fixture.failCodexFileWrite = false
            let ready = await Renewal$Codex.shared.prepareForTermination(timeout: 2)
            try expect(ready, "Pinned rotation could not become durable after retargeting")
        } else { Fixture.releaseRefresh() }
        _ = await request.value
        let actual = try Data(contentsOf: file)
        try expect(actual == expected, "Retired or redirected request changed a replacement profile after symlink retargeting")
        if ["inflight", "pending"].contains(action) {
            let originalFile = first.appendingPathComponent("retargeted/auth.json")
            try expect(Renewal$Codex.refreshToken(originalFile) == "synthetic-rotated" && Fixture.refreshCalls == 1,
                       "Retargeting lost the original owner's only rotated grant or replayed its refresh")
        } else if action == "usage" {
            try expect(Fixture.refreshCalls == 0, "Retired usage spent the re-added profile's refresh grant after an ABA retarget")
        } else { try expect(Fixture.refreshCalls == 1, "Removal replayed a retired refresh grant") }
    }

    @MainActor
    private static func claudeStubOwnership(state: String) async throws {
        let service = Fixture.service
        let id = "claude:" + service
        Fixture.onlyClaudeService = service
        Fixture.discoveredClaudeService = service
        Fixture.claudeMetadataDate = Date(timeIntervalSince1970: 1)
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        let stub: [String: Any] = ["trustedDeviceToken": "synthetic-stub"]
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        if ["race", "same-date", "later"].contains(state) {
            Fixture.keychain = stub
            if state != "later" { Fixture.changeLoginAfterRead = 2 }
            Fixture.preserveClaudeMetadataDate = state == "same-date"
            store.start()
            for _ in 0..<200 {
                try await Task.sleep(nanoseconds: 1_000_000)
                if store.columns.isEmpty { break }
            }
            if state == "later" {
                try expect(store.columns.isEmpty, "A genuine native stub did not leave discovery")
                Fixture.keychain = Fixture.claudeLogin("new-login", expired: false)
                Fixture.claudeMetadataDate = Date(timeIntervalSince1970: 2)
            }
        } else {
            Fixture.keychain = state == "genuine" ? stub : Fixture.claudeLogin("new-login", expired: false)
            UserDefaults.standard.set([service: Fixture.claudeMetadataDate!.timeIntervalSince1970], forKey: "claudeKeychainStubs")
            if ["denied", "malformed"].contains(state) {
                try JSONSerialization.data(withJSONObject: stub).write(to: Fixture.storageDirectory.appendingPathComponent(".credentials.json"))
                Fixture.denyClaudeRead = state == "denied"
                Fixture.malformedClaudeRead = state == "malformed"
            }
        }
        store.rediscover(force: true)
        let visible = store.account(for: id) != nil
        print("Stub state=\(state), account visible=\(visible)")
        try expect(visible == (state != "genuine"), "Stub cache hid a newer/unreadable preferred login or retained a genuine stub")
        if !["race", "same-date", "later"].contains(state) {
            try expect(Fixture.noninteractiveClaudeReads == Fixture.keychainReads && Fixture.interactionAllowed,
                       "Stub verification enabled a Keychain prompt or left interaction disabled")
        }
    }

    @MainActor
    private static func codexRollbackNewLogin(replacement: String) throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "keychain-owner", mode: "auto")
        try Fixture.writeAuth(base, account: "old-fallback", refresh: "old-fallback-grant", expired: false)
        let file = base.appendingPathComponent("auth.json")
        let before = try Data(contentsOf: file)
        let nativeBefore = Fixture.codexKeychain[Fixture.codexKey(base)]
        let target = Fixture.root.appendingPathComponent("cli-login-target/auth.json")
        var replacementData: Data?
        Fixture.denyCodexDelete = true
        Fixture.beforeCredentialDelete = {
            guard replacement != "none" else { return }
            let home = replacement == "symlink" ? target.deletingLastPathComponent() : base
            try! Fixture.writeAuth(home, account: "new-cli-login", refresh: "new-cli-grant", expired: false)
            replacementData = try! Data(contentsOf: home.appendingPathComponent("auth.json"))
            if replacement == "symlink" {
                try! Foundation.FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
            }
        }
        let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                        profileName: "main", source: .codexHome(base))
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        let actual = try Data(contentsOf: file)
        try expect(refused && Fixture.codexKeychain[Fixture.codexKey(base)] == nativeBefore,
                   "Denied deletion did not preserve the native Keychain login")
        try expect(actual == (replacementData ?? before), "Deletion rollback overwrote a concurrent CLI file login")
        if replacement == "symlink" {
            var info = stat()
            let status = file.path.withCString { Darwin.lstat($0, &info) }
            try expect(status == 0 && info.st_mode & S_IFMT == S_IFLNK
                       && Data(contentsOf: target) == replacementData,
                       "Deletion rollback replaced a new symlink or changed its credentials target")
        } else if replacement == "none" {
            let permissions = try Foundation.FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
            try expect(permissions?.intValue == 0o600, "Rollback exposed the restored credentials")
        }
        let leftovers = try Foundation.FileManager.default.contentsOfDirectory(atPath: base.path)
        try expect(!leftovers.contains { $0.hasPrefix(".auth-restore-") }, "Rollback leaked its prepared credentials")
    }

    @MainActor
    private static func codexActiveAlias(mode: String, active: Bool = true) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("active-owner")
        let alias = ProfileDirectories.codexRoot.appendingPathComponent("owner-alias")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(profile, account: "selected", mode: mode, expired: true)
        try Fixture.codexLogin(alias, account: "previous-alias-owner", mode: mode, expired: true)
        let store = UsageStore(providers: [.codex: Provider$Codex()], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: "codex:owner-alias") != nil, "The original alias profile was not discovered")
        try Foundation.FileManager.default.removeItem(at: alias)
        try Foundation.FileManager.default.createSymbolicLink(at: alias, withDestinationURL: profile)
        if active { try AuthSwap$Codex.activate(columnID: "codex:active-owner", home: profile) }
        let originalBase = try AuthSwap$Codex.authData(home: base)
        store.refreshAll()
        for _ in 0..<200 {
            if Fixture.refreshCalls > 0 { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        try expect(Fixture.refreshCalls == (active ? 0 : 1), "A stale canonical alias renewed the selected Desktop/CLI grant")
        try expect(try AuthSwap$Codex.authData(home: base) == originalBase, "Alias renewal replaced the native login")
        if active {
            try expect(AuthSwap$Codex.liveHome(columnID: "codex:owner-alias", home: alias).path == base.path,
                       "Usage through a canonical alias ignored the selected native account")
            try writeNativeCodexGrant(base, grant: "native-after-alias-observation")
            let native = try AuthSwap$Codex.authData(home: base)
            var refused = false
            do { try AuthSwap$Codex.activate(columnID: "codex:owner-alias", home: alias) } catch { refused = true }
            try expect(refused && AuthSwap$Codex.authData(home: base) == native,
                       "Switching through a stale alias republished the selected profile's old grant")
        }
    }

    @MainActor
    private static func codexPinnedCopyback(mode: String = "file", retarget: Bool = true,
                                            legacy: Bool = false, rollback: Bool = false) throws {
        let first = legacy && !retarget ? ProfileDirectories.codexRoot : Fixture.root.appendingPathComponent("owner-a")
        let second = Fixture.root.appendingPathComponent("owner-b")
        for directory in [first, second] {
            try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        if first.path != ProfileDirectories.codexRoot.path {
            try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: first)
        }
        let home = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let a = first.appendingPathComponent("selected"), b = second.appendingPathComponent("selected")
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "primary", mode: rollback ? "keyring" : "file")
        try Fixture.codexLogin(home, account: "selected", mode: mode)
        let original = try AuthSwap$Codex.authData(home: home)!
        try Fixture.codexMode(b, mode)
        if mode == "file" { try original.write(to: b.appendingPathComponent("auth.json")) }
        else { Fixture.codexKeychain[Fixture.codexKey(b)] = original }
        let id = "codex:selected"
        try AuthSwap$Codex.activate(columnID: id, home: home)
        if legacy { UserDefaults.standard.removeObject(forKey: "codexAppAccountPhysicalHome") }
        try writeNativeCodexGrant(base, grant: "native-rotated-grant")
        if retarget {
            try Foundation.FileManager.default.removeItem(at: ProfileDirectories.codexRoot)
            try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: second)
        }
        if rollback {
            Fixture.denyCodexDeleteAccount = Fixture.codexKey(AuthSwap$Codex.stashHome)
            let account = DiscoveredAccount(id: id, provider: .codex, profileName: "selected", source: .codexHome(home))
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(refused && AuthSwap$Codex.activeColumnID == id, "Refused deletion lost the selected native owner")
            Fixture.denyCodexDeleteAccount = nil
            try writeNativeCodexGrant(base, grant: "native-after-refused-delete")
        }
        let rotated = try AuthSwap$Codex.authData(home: base)!
        try AuthSwap$Codex.restoreDefault()
        try expect(try AuthSwap$Codex.authData(home: b) == original, "Copyback redirected native credentials into another physical owner")
        if legacy && retarget {
            try expect(try AuthSwap$Codex.authData(home: a) == original, "Unproven legacy ownership overwrote the original credentials")
            let parent = AuthSwap$Codex.stashHome.deletingLastPathComponent()
            let orphans = try Foundation.FileManager.default.contentsOfDirectory(at: parent, includingPropertiesForKeys: nil)
                .filter { $0.lastPathComponent.hasPrefix("orphaned-") }
            try expect(try orphans.contains { try AuthSwap$Codex.authData(home: $0) == rotated },
                       "An unpinned legacy selection lost its current native credentials")
        } else {
            try expect(try AuthSwap$Codex.authData(home: a) == rotated, "Copyback lost the pinned owner's rotated grant")
        }
        try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary"
                   && UserDefaults.standard.string(forKey: "codexAppAccountPhysicalHome") == nil,
                   "Default restoration lost the primary login or retained a selected physical owner")
    }

    @MainActor
    private static func codexPinnedRetargetToBase() throws {
        let base = Fixture.root.appendingPathComponent("native-root/selected")
        Fixture.codexHome = base.path
        let first = Fixture.root.appendingPathComponent("physical-profiles")
        try Foundation.FileManager.default.createDirectory(at: first, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: first)
        let home = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(home, account: "selected", mode: "file")
        let primary = try AuthSwap$Codex.authData(home: base)
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: home)
        try Foundation.FileManager.default.removeItem(at: ProfileDirectories.codexRoot)
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: base.deletingLastPathComponent())
        try expect(AuthSwap$Codex.activeColumnID == "codex:selected"
                   && AuthSwap$Codex.liveHome(columnID: AuthSwap$Codex.defaultColumnID, home: base) == AuthSwap$Codex.stashHome,
                   "Retargeting the logical profile to base relabeled the selected account as primary")
        try expect(try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: base) == primary,
                   "Retargeting hid the primary account's backup")
        try AuthSwap$Codex.restoreDefault()
        try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "primary", "Retargeted selection could not restore primary")
    }

    @MainActor
    private static func claudeRetiredUsage401(mode: String) async throws {
        let provider = Provider$Claude()
        let account = Fixture.claudeAccount
        let original = Fixture.claudeLogin("same-owner", expired: false)
        Fixture.keychain = original
        Fixture.holdFirstUsage = true; Fixture.firstUsageStatus = 401
        let old = Task { await provider.fetch(account) }
        var started = false
        for _ in 0..<200 {
            Fixture.lock.lock(); started = Fixture.usageCalls == 1; Fixture.lock.unlock()
            if started { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(started, "Old usage did not reach its response barrier")
        if mode != "current" {
            if mode != "relogin" {
                try AccountRemoval.remove(account)
                await provider.accountRemoved(account)
                Fixture.keychainExists = true
            }
            Fixture.keychain = mode == "new-access" ? Fixture.claudeLogin("replacement", expired: false) : original
            if ["new-refresh", "relogin"].contains(mode) {
                var oauth = Fixture.keychain["claudeAiOauth"] as! [String: Any]
                oauth["refreshToken"] = "synthetic-refresh-readded-session"
                Fixture.keychain["claudeAiOauth"] = oauth
            }
            if case .success = await provider.fetch(account) {} else { throw Failure(description: "Fresh Claude login control failed") }
            try expect(Fixture.refreshCalls == 0, "A fresh replacement login was renewed before the late usage response")
        }
        Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        _ = await old.value
        if case .success = await provider.fetch(account) {} else { throw Failure(description: "Late usage poisoned current Claude credentials") }
        try expect(Fixture.refreshCalls == (mode == "current" ? 1 : 0), "A retired usage 401 spent a replacement Claude refresh grant")
    }


    @MainActor
    private static func codexRollbackStorageMode(originalMode: String = "keyring",
                                                  replacementConfig: Bool = false,
                                                  replacementAuth: Bool = true) throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("rollback-storage-mode")
        try Fixture.codexLogin(home, account: "old-keyring-owner", mode: originalMode)
        let account = DiscoveredAccount(id: "codex:rollback-storage-mode", provider: .codex,
                                        profileName: "rollback-storage-mode", source: .codexHome(home))
        Fixture.denyCodexDelete = true
        Fixture.beforeCredentialDelete = {
            if replacementAuth {
                try! Fixture.writeAuth(home, account: "replacement-file-owner", refresh: "replacement-file-grant", expired: false)
            } else {
                try! Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
                try! Data("new-cli-settings".utf8).write(to: home.appendingPathComponent("settings.json"))
            }
            if replacementConfig { try! Fixture.codexMode(home, "file") }
        }
        var failed = false
        do { try AccountRemoval.remove(account) } catch { failed = true }
        try expect(failed, "Credential deletion refusal was not propagated")
        try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == (replacementAuth ? "replacement-file-owner" : "old-keyring-owner"),
                   "Rollback hid the replacement CLI login behind old storage settings or lost the old login")
        try expect(try AuthStorage$Codex(home: home).mode.rawValue == (replacementAuth ? "file" : originalMode),
                   "Rollback changed the effective storage backend of its surviving owner")
        if !replacementAuth {
            try expect(try String(contentsOf: home.appendingPathComponent("settings.json")) == "new-cli-settings",
                       "Rollback replaced concurrent CLI metadata")
        }
    }

    @MainActor
    private static func claudePrimarySharedFallback(switchCLI: Bool = true, failure: String = "",
                                                     shared: Bool = true) throws {
        let owner = ProfileDirectories.claudeRoot.appendingPathComponent("primary-shared-owner")
        try Foundation.FileManager.default.createDirectory(at: owner, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: Fixture.storageDirectory, withDestinationURL: owner)
        let hash = SHA256.hash(data: Data(owner.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let survivor = Fixture.service + "-" + hash
        let original = Fixture.claudeLogin("primary-owner", expired: false)
        let other = Fixture.claudeLogin("surviving-hashed-owner", expired: false)
        Fixture.claudeEntries = shared ? [Fixture.service: original, survivor: other] : [Fixture.service: original]
        let file = owner.appendingPathComponent(".credentials.json")
        let fallback = try JSONSerialization.data(withJSONObject: shared ? other : original)
        try fallback.write(to: file)
        let settings = owner.appendingPathComponent("settings.json")
        try Data("preserve-native-settings".utf8).write(to: settings)
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        store.rediscover(force: true)
        guard let primary = store.account(for: "claude:" + Fixture.service) else { throw Failure(description: "Primary fixture was not discovered") }
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        try Foundation.FileManager.default.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("/previous-cli-profile\n".utf8).write(to: pointer)
        CLISelection$Claude.isEnabled = switchCLI
        if shared {
            guard let selected = store.account(for: "claude:" + survivor) else { throw Failure(description: "Survivor fixture was not discovered") }
            var result: Result<Void, Error>?
            AppSwitcher$Claude().switchTo(selected) { result = $0 }
            if case .success? = result {} else { throw Failure(description: "Survivor Desktop switch failed") }
        }
        let selectedPointer = try String(contentsOf: pointer)
        if failure == "metadata" { Fixture.denyClaudeMetadata = true }
        if failure == "delete" { Fixture.denyKeychainDelete = true }
        if failure == "stale" { Fixture.claudeEntries?[Fixture.service] = nil }
        var failed = false
        do { try store.removeAccount(id: primary.id) } catch { failed = true }
        try expect(failed == !failure.isEmpty, "Shared primary removal ignored an unavailable or stale credential owner")
        try expect((Fixture.claudeEntries?[Fixture.service] != nil) == ["metadata", "delete"].contains(failure),
                   "Removal changed a refused primary Keychain login")
        if !failed {
            store.rediscover(force: true)
            try expect(store.account(for: primary.id) == nil, "A shared fallback resurrected the removed primary column")
        }
        if shared {
            try expect(Fixture.claudeEntries?[survivor] != nil && (try? Data(contentsOf: file)) == fallback,
                       "Removing primary Claude deleted a surviving owner's common fallback")
            try expect(AppSwitcher$Claude().isOpenInApp(columnID: "claude:" + survivor) == true,
                       "Primary removal changed the surviving Desktop selection")
        } else {
            try expect(!Foundation.FileManager.default.fileExists(atPath: file.path), "Lone primary removal retained its own fallback login")
        }
        try expect(try String(contentsOf: pointer) == selectedPointer && CLISelection$Claude.isEnabled == switchCLI
                   && String(contentsOf: settings) == "preserve-native-settings",
                   "Primary removal changed native settings or Switch CLI selection")
    }

    @MainActor
    private static func codexBackupPhysicalFence(mode: String = "file", alias: Bool = true,
                                                  action: String = "restore", firmlink: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("previous-owner")
        let next = ProfileDirectories.codexRoot.appendingPathComponent("next-selected")
        try Fixture.codexLogin(base, account: "primary", mode: mode, expired: true)
        try Fixture.codexLogin(selected, account: "selected", mode: mode)
        try Fixture.codexLogin(next, account: "next-selected", mode: mode)
        try Fixture.codexLogin(other, account: "previous-owner", mode: mode, expired: true)
        try expect(Discovery$Real().discover().contains { $0.id == "codex:previous-owner" }, "Alias owner fixture was not discovered")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        try Foundation.FileManager.default.removeItem(at: other)
        let destination = firmlink ? URL(fileURLWithPath: "/System/Volumes/Data" + AuthSwap$Codex.stashHome.path) : AuthSwap$Codex.stashHome
        try Foundation.FileManager.default.createSymbolicLink(at: other, withDestinationURL: destination)
        let before = try AuthSwap$Codex.authData(home: base)
        let pending = action == "pending"
        if pending {
            Fixture.failCodexFileWrite = mode == "file"
            Fixture.denyCodexWrite = mode != "file"
        }
        Fixture.response = pending ? .renewed : .heldRenewed
        let request = Task {
            await Renewal$Codex.shared.renew(columnID: alias ? "codex:previous-owner" : AuthSwap$Codex.defaultColumnID,
                                            home: alias ? other : base, force: false)
        }
        try await waitForRefresh(1)
        if pending {
            try expect(await request.value == .unavailable, "Accepted refresh did not reach pending persistence")
            Fixture.failCodexFileWrite = false; Fixture.denyCodexWrite = false
        }
        var refused = false
        do {
            if action == "remove" {
                try AccountRemoval.remove(DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                                           profileName: "primary", source: .codexHome(base)))
            } else if action == "unrelated" {
                try AuthSwap$Codex.activate(columnID: "codex:next-selected", home: next)
            } else { try AuthSwap$Codex.restoreDefault() }
        } catch { refused = true }
        let retained = try AuthSwap$Codex.authData(home: base)
        Fixture.releaseRefresh()
        if !pending { try expect(await request.value == .renewed, "A fenced primary refresh lost its rotated grant") }
        try expect(refused == (action != "unrelated"), "An actual backup owner bypassed its mutation fence or blocked an unrelated switch")
        if action != "unrelated" { try expect(retained == before, "A refused operation changed the native selected owner") }
        else { try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "next-selected", "Unrelated selection did not reach Desktop/CLI storage") }
        if pending { try expect(await Renewal$Codex.shared.prepareForTermination(timeout: 2), "Pending accepted grant did not drain") }
        try AuthSwap$Codex.restoreDefault()
        let data = try AuthSwap$Codex.authData(home: base)!
        let tokens = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["tokens"] as? [String: Any]
        try expect(Provider$Codex.parseAuth(data)?.accountID == "primary"
                   && tokens?["refresh_token"] as? String == "synthetic-rotated" && Fixture.refreshCalls == 1,
                   "Primary restoration lost its rotated grant or repeated the refresh POST")
    }

    @MainActor
    private static func codexRetiredResponse(response: String = "temporary", remove: Bool = true,
                                              sameGrant: Bool = true) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("retry-after-readd")
        try Fixture.writeAuth(home, account: "original", refresh: "original-refresh", expired: true)
        let data = try Data(contentsOf: home.appendingPathComponent("auth.json"))
        let id = "codex:retry-after-readd"
        let account = DiscoveredAccount(id: id, provider: .codex, profileName: "retry-after-readd", source: .codexHome(home))
        Fixture.response = response == "temporary" ? .heldTemporary : response == "success" ? .heldRenewed : response == "lost" ? .heldLost : .heldRejected
        let old = Task { await Renewal$Codex.shared.renew(columnID: id, home: home, force: false) }
        try await waitForRefresh(1)
        if remove {
            try AccountRemoval.remove(account)
            try Fixture.writeAuth(home, account: "replacement", refresh: "replacement-refresh", expired: true)
            if sameGrant { try data.write(to: home.appendingPathComponent("auth.json")) }
        }
        Fixture.releaseRefresh()
        let oldResult = await old.value
        try expect(oldResult == (remove ? .skipped : .unavailable), "Retired response was published to the replacement owner")
        if remove { try expect(Provider$Codex.readAuth(codexHome: home)?.accountID == (sameGrant ? "original" : "replacement"), "Retired response replaced re-added credentials") }
        Fixture.response = .renewed
        let next = await Renewal$Codex.shared.renew(columnID: id, home: home, force: false)
        let again = await Renewal$Codex.shared.renew(columnID: id, home: home, force: false)
        let retryable = response == "temporary" || !sameGrant
        let expected: Renewal$Codex.Result = retryable ? .renewed : response == "rejected" ? .rejected : .uncertain
        try expect(next == expected && Fixture.refreshCalls == (retryable ? 2 : 1),
                   "Retired response either blocked a known retryable grant or allowed unsafe replay")
        try expect(again == (retryable ? .skipped : expected), "Repeated renewal changed the retired grant decision")
    }


    @MainActor
    private static func codexFirmlinkOwner(target: String = "selected", active: Bool = true,
                                            mode: String = "file") async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("firmlink-owner")
        let owner = target == "base" ? base : profile
        let alias = URL(fileURLWithPath: "/System/Volumes/Data" + owner.path)
        try Fixture.codexLogin(base, account: "primary", mode: "file", expired: target == "base")
        if target != "base" {
            try Fixture.codexLogin(profile, account: "selected", mode: mode, expired: true)
            if mode == "auto" {
                try Fixture.writeAuth(profile, account: "selected", refresh: "selected-file-grant")
                Fixture.codexKeychain[Fixture.codexKey(profile)] = nil
            }
        }
        var first = stat(), second = stat()
        try expect(owner.path.withCString { Darwin.lstat($0, &first) } == 0
                   && alias.path.withCString { Darwin.lstat($0, &second) } == 0
                   && first.st_dev == second.st_dev && first.st_ino == second.st_ino
                   && Fixture.codexKey(owner) != Fixture.codexKey(alias),
                   "Fixture did not expose distinct native keys for one physical directory")
        if mode == "keyring" {
            // A Data-volume spelling has its own native Keychain record.
            let independent = Fixture.root.appendingPathComponent("independent-payload")
            try Fixture.writeAuth(independent, account: "independent", refresh: "independent-refresh")
            Fixture.codexKeychain[Fixture.codexKey(alias)] = try Data(contentsOf: independent.appendingPathComponent("auth.json"))
        }
        if target != "base" && active { try AuthSwap$Codex.activate(columnID: "codex:firmlink-owner", home: profile) }
        let before = try AuthSwap$Codex.authData(home: base)
        let account = DiscoveredAccount(id: "codex:firmlink-alias", provider: .codex,
                                        profileName: "firmlink-alias", source: .codexHome(alias))
        _ = await Provider$Codex().fetch(account)
        let independent = !active || mode == "keyring"
        try expect(Fixture.refreshCalls == (independent ? 1 : 0),
                   "A physical file alias renewed native credentials or blocked an independent Keychain session")
        try expect(try AuthSwap$Codex.authData(home: base) == before, "Alias renewal changed the native login")
        if active && target == "selected" && mode != "keyring" {
            try expect(AuthSwap$Codex.liveHome(columnID: account.id, home: alias).path == base.path,
                       "Alias usage ignored the active native account")
            try writeNativeCodexGrant(base, grant: "native-after-alias-usage")
            let native = try AuthSwap$Codex.authData(home: base)
            var refused = false
            do { try AuthSwap$Codex.activate(columnID: account.id, home: alias) } catch { refused = true }
            try expect(refused && AuthSwap$Codex.authData(home: base) == native,
                       "Alias activation republished the selected profile's old grant")
        }
    }

    @MainActor
    private static func codexNativeGrantCopy(mode: String = "file", distinct: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("copied-native-grant")
        try Fixture.codexLogin(base, account: "same-account", mode: mode, expired: true)
        try Fixture.codexLogin(profile, account: "same-account", mode: mode, expired: true)
        if distinct { try writeNativeCodexGrant(profile, grant: "independent-session-refresh") }
        try AuthSwap$Codex.activate(columnID: "codex:copied-native-grant", home: profile)
        let native = try AuthSwap$Codex.authData(home: base)
        let primary = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                        profileName: "main", source: .codexHome(base))
        _ = await Provider$Codex().fetch(primary)
        try expect(Fixture.refreshCalls == (distinct ? 1 : 0),
                   "A copied grant renewed the active native session or blocked an independent same-account session")
        try expect(try AuthSwap$Codex.authData(home: base) == native, "Sleeping renewal changed native credentials")
        let backup = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)!
        let tokens = (try JSONSerialization.jsonObject(with: backup) as? [String: Any])?["tokens"] as? [String: Any]
        try expect(tokens?["refresh_token"] as? String == (distinct ? "synthetic-rotated" : "synthetic-refresh-same-account"),
                   "Native and sleeping owners disagreed about an accepted rotation")
    }

    @MainActor
    private static func codexFirmlinkUsageRemoval(remove: Bool = true) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("firmlink-usage")
        try Fixture.codexLogin(home, account: "original", mode: "file")
        let original = try Data(contentsOf: home.appendingPathComponent("auth.json"))
        let alias = URL(fileURLWithPath: "/System/Volumes/Data" + home.path)
        let account = DiscoveredAccount(id: "codex:firmlink-usage-alias", provider: .codex,
                                        profileName: "alias", source: .codexHome(alias))
        Fixture.holdFirstUsage = true; Fixture.firstUsageStatus = 401
        let provider = Provider$Codex()
        let old = Task { await provider.fetch(account) }
        for _ in 0..<300 {
            if Fixture.usageCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.usageCalls == 1, "Old usage did not reach its held response")
        if remove {
            try AccountRemoval.remove(DiscoveredAccount(id: "codex:firmlink-usage", provider: .codex,
                                                       profileName: "original", source: .codexHome(home)))
            try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            try original.write(to: home.appendingPathComponent("auth.json"))
        }
        Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        _ = await old.value
        try expect(Fixture.refreshCalls == (remove ? 0 : 1), "A retired firmlink usage response spent the re-added grant")
        if remove { try expect(try Data(contentsOf: home.appendingPathComponent("auth.json")) == original, "Retired usage replaced re-added credentials") }
    }

    @MainActor
    private static func codexRenewalDirectoryReplacement(replaceDirectory: Bool = true) async throws {
        let home = ProfileDirectories.codexRoot.appendingPathComponent("directory-generation")
        try Fixture.codexLogin(home, account: "original", mode: "file", expired: true)
        let original = try Data(contentsOf: home.appendingPathComponent("auth.json"))
        Fixture.response = .heldRenewed
        let request = Task { await Renewal$Codex.shared.renew(columnID: "codex:directory-generation", home: home, force: false) }
        try await waitForRefresh(1)
        if replaceDirectory {
            try Foundation.FileManager.default.moveItem(at: home, to: home.appendingPathExtension("previous-owner"))
            try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        }
        try original.write(to: home.appendingPathComponent("auth.json"), options: .atomic)
        Fixture.releaseRefresh()
        _ = await request.value
        let current = try Data(contentsOf: home.appendingPathComponent("auth.json"))
        try expect((current == original) == replaceDirectory && Fixture.refreshCalls == 1,
                   "Late rotation crossed a directory replacement or refused an ordinary atomic file replacement")
    }

    @MainActor
    private static func claudeMainFallbackLogin(mode: String) async throws {
        let shared = mode != "unshared"
        let removing = mode != "first"
        let owner = ProfileDirectories.claudeRoot.appendingPathComponent("retained-native-fallback")
        try Foundation.FileManager.default.createDirectory(at: owner, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: Fixture.storageDirectory, withDestinationURL: owner)
        let suffix = SHA256.hash(data: Data(owner.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let hashed = Fixture.service + "-" + suffix
        let original = Fixture.claudeLogin("old-primary", expired: false)
        let survivor = Fixture.claudeLogin("surviving-hashed", expired: false)
        Fixture.claudeEntries = shared ? [hashed: survivor] : [:]
        if removing { Fixture.claudeEntries?[Fixture.service] = original }
        let file = owner.appendingPathComponent(".credentials.json")
        let retained = try JSONSerialization.data(withJSONObject: shared ? survivor : original)
        try retained.write(to: file)
        let store = UsageStore(providers: [.claude: Provider$Claude()], discovery: Discovery$Real())
        let primaryID = "claude:" + Fixture.service
        if removing {
            store.rediscover(force: true)
            try expect(store.account(for: primaryID) != nil, "Original primary login was not discovered")
            try store.removeAccount(id: primaryID)
            try expect(store.account(for: primaryID) == nil, "Removal immediately resurrected the retained shared fallback as primary")
            if shared {
                try expect(try Data(contentsOf: file) == retained && Fixture.claudeEntries?[hashed] != nil,
                           "Primary removal changed the surviving owner's fallback or Keychain login")
            }
        }
        if mode == "unchanged" {
            store.rediscover(force: true)
            try expect(store.account(for: primaryID) == nil && store.account(for: "claude:" + hashed) != nil,
                       "An unchanged shared fallback resurrected primary or hid its surviving owner")
            return
        }
        let fresh = Fixture.claudeLogin("new-native-main", expired: false)
        if mode == "keychain" {
            Fixture.claudeEntries?[Fixture.service] = fresh
        } else {
            // A native login may rewrite the same grant. Atomic replacement
            // and discovery are real filesystem operations in this fixture.
            let replacement: Data
            if mode == "same-grant" { replacement = retained }
            else { replacement = try JSONSerialization.data(withJSONObject: fresh) }
            try replacement.write(to: file, options: .atomic)
        }
        store.rediscover(force: true)
        guard let primary = store.account(for: primaryID) else {
            throw Failure(description: "A native main login remained hidden behind a surviving hashed owner")
        }
        let expected = mode == "same-grant" ? "surviving-hashed" : "new-native-main"
        let credentials = AuthStorage$Claude.credentials(service: Fixture.service)
        try expect(credentials?.accessToken == "synthetic-" + expected,
                   "Discovery selected another owner's credentials for the new native main login")
        let outcome = await Provider$Claude().fetch(primary)
        if case .success(let snapshot) = outcome {
            try expect(snapshot.subtitle?.contains(Provider$Claude.humanized(expected)) == true,
                       "The rediscovered primary polled another owner's grant")
        } else { throw Failure(description: "The rediscovered native main login could not fetch usage") }
        try expect(Fixture.refreshCalls == 0 && Fixture.usageCalls == 1,
                   "A fresh native main login unnecessarily renewed credentials or skipped its usage request")
        if shared {
            guard let survivingEntry = Fixture.claudeEntries?[hashed] else {
                throw Failure(description: "Native main rediscovery removed the surviving hashed Keychain owner")
            }
            let actual = try JSONSerialization.data(withJSONObject: survivingEntry, options: .sortedKeys)
            let unchanged = try JSONSerialization.data(withJSONObject: survivor, options: .sortedKeys)
            try expect(actual == unchanged, "Native main rediscovery changed the surviving hashed Keychain owner")
        }
    }

    @MainActor
    private static func claudePreferredOwnerPolling(mode: String) async throws {
        let genuine = mode == "keychain-stub" || mode == "file-stub"
        let validFallback = mode == "valid-fallback"
        let stub: [String: Any] = ["trustedDeviceToken": "synthetic-stub"]
        Fixture.onlyClaudeService = Fixture.service
        Fixture.discoveredClaudeService = Fixture.service
        Fixture.claudeMetadataDate = Date(timeIntervalSince1970: 1)
        Fixture.keychain = genuine ? stub : Fixture.claudeLogin("unreadable-preferred", expired: false)
        Fixture.keychainExists = mode != "file-stub"
        Fixture.denyClaudeRead = mode == "denied" || validFallback
        Fixture.malformedClaudeRead = mode == "malformed"
        try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
        let fallback = validFallback ? Fixture.claudeLogin("readable-fallback", expired: false) : stub
        try JSONSerialization.data(withJSONObject: fallback)
            .write(to: Fixture.storageDirectory.appendingPathComponent(".credentials.json"))
        let probe = ClaudePollingProbe()
        let store = UsageStore(providers: [.claude: probe], discovery: Discovery$Real())
        Fixture.manualPollingTimer = true
        store.start()
        let primaryID = "claude:" + Fixture.service
        for _ in 0..<500 {
            if await probe.counts().completed == 1 { break }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        try expect(await probe.counts().completed == 1, "The initial preferred-owner poll did not finish")
        guard let tick = Fixture.pollingTick else { throw Failure(description: "UsageStore did not install its polling timer") }
        // Give the completed fetch time to reach UsageStore.finish, then drive
        // real scheduler ticks. An overdue retained owner starts another fetch.
        for _ in 0..<80 {
            tick()
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        let counts = await probe.counts()
        try expect(counts.started == 1 && counts.completed == 1,
                   "A retained preferred owner was polled again on the next scheduler tick after fallback-stub classification")
        if genuine {
            try expect(store.account(for: primaryID) == nil,
                       "A genuine native non-login stub remained visible")
        } else {
            try expect(store.account(for: primaryID) != nil,
                       "An unreadable preferred login was hidden by its fallback stub")
            guard let column = store.columns.first(where: { $0.id == primaryID }) else {
                throw Failure(description: "The retained preferred owner lost its column")
            }
            if !validFallback {
                if case .reauth = column.status {} else {
                    throw Failure(description: "An unreadable preferred owner was classified as a non-account")
                }
            }
        }
        try expect(Fixture.refreshCalls == 0 && Fixture.usageCalls == (validFallback ? 1 : 0),
                   "Preferred-owner classification refreshed a grant or requested usage through a non-login stub")
    }

    @MainActor
    private static func codexFirmlinkMixedAutoFileCleanup(selected: Bool = false, fileOwner: Bool = true) async throws {
        let base = AuthSwap$Codex.baseHome
        let owner = selected ? ProfileDirectories.codexRoot.appendingPathComponent("mixed-auto-selected") : base
        if selected { try Fixture.codexLogin(base, account: "primary", mode: "file", expired: false) }
        let alias = ProfileDirectories.codexRoot.appendingPathComponent("mixed-auto-keyring-alias")
        try Fixture.codexLogin(owner, account: "native-file-owner", mode: fileOwner ? "file" : "keyring", expired: false)
        try Fixture.codexMode(owner, "auto")
        if selected { try AuthSwap$Codex.activate(columnID: "codex:mixed-auto-selected", home: owner) }
        try Foundation.FileManager.default.createDirectory(at: alias.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(at: alias, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + owner.path))
        let source = Fixture.root.appendingPathComponent("independent-keyring-payload")
        try Fixture.writeAuth(source, account: "independent-keyring-owner", refresh: "independent-keyring-refresh", expired: true)
        Fixture.codexKeychain[Fixture.codexKey(alias)] = try Data(contentsOf: source.appendingPathComponent("auth.json"))
        let original = try AuthSwap$Codex.authData(home: owner)
        let account = DiscoveredAccount(id: "codex:mixed-auto-keyring-alias", provider: .codex,
                                        profileName: "mixed-auto-keyring-alias", source: .codexHome(alias))
        _ = await Provider$Codex().fetch(account)
        let after = try AuthSwap$Codex.authData(home: owner)
        try expect(after == original && Provider$Codex.readAuth(codexHome: base)?.accountID == "native-file-owner", "Independent alias Keychain refresh deleted the native owner's shared file fallback")
        try expect(Fixture.refreshCalls == (fileOwner ? 0 : 1), "Mixed auto ownership blocked an independent Keychain session or spent a grant before unsafe cleanup")
    }

    @MainActor
    private static func codexCopiedGrantNativeRotation(mode: String = "file", distinct: Bool = false, poll: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("copy-native-rotation")
        try Fixture.codexLogin(base, account: "same-account", mode: mode, expired: false)
        try Fixture.codexLogin(profile, account: "same-account", mode: mode, expired: false)
        let primaryGrant = Renewal$Codex.refreshToken(base.appendingPathComponent("auth.json"))
        if distinct { try writeNativeCodexGrant(profile, grant: "independent-profile-session") }
        try AuthSwap$Codex.activate(columnID: "codex:copy-native-rotation", home: profile)
        try writeNativeCodexGrant(base, grant: "native-current-rotated-grant")
        let native = try AuthSwap$Codex.authData(home: base)
        if poll {
            _ = await Renewal$Codex.shared.renew(columnID: AuthSwap$Codex.defaultColumnID, home: base, force: true)
            try expect(Fixture.refreshCalls == 0, "A copied primary spent the old grant after native rotation")
        }
        try AuthSwap$Codex.restoreDefault()
        let restored = Renewal$Codex.refreshToken(base.appendingPathComponent("auth.json"))
        let source = Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json"))
        let expected = distinct ? primaryGrant : "native-current-rotated-grant"
        try expect(restored == expected, "Restore republished a spent copied grant or replaced an independent same-account primary session")
        try expect(source == "native-current-rotated-grant", "Native rotation did not return to the selected profile")
        if !distinct { try expect(try AuthSwap$Codex.authData(home: base) == native, "Restoring the same native session changed its accepted credentials") }
        try expect(!AuthSwap$Codex.isSwapped && AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) == nil,
                   "Completed native restore retained an active selection or a duplicate backup")
        try expect(Fixture.refreshCalls == 0, "Restoring current native credentials issued an unnecessary refresh POST")
    }

    @MainActor
    private static func codexCopiedGrantRetry(distinct: Bool = false, replacement: String = "none", poll: Bool = false) async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("copy-partial-retry")
        try Fixture.codexLogin(base, account: "same-account", mode: "file")
        try Fixture.codexLogin(profile, account: "same-account", mode: "keyring")
        if distinct { try writeNativeCodexGrant(profile, grant: "independent-profile-session") }
        let primary = try AuthSwap$Codex.authData(home: base)
        try AuthSwap$Codex.activate(columnID: "codex:copy-partial-retry", home: profile)
        try writeNativeCodexGrant(base, grant: "native-rotation-two")
        let native = try AuthSwap$Codex.authData(home: base)
        Fixture.denyCodexWrite = true
        var refused = false
        do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
        Fixture.denyCodexWrite = false
        let afterFailure = try AuthSwap$Codex.authData(home: base)
        try expect(refused && afterFailure == native && AuthSwap$Codex.isSwapped,
                   "A refused selected-profile write completed the switch or changed native credentials")
        if replacement == "native-missing" {
            try Foundation.FileManager.default.removeItem(at: base.appendingPathComponent("auth.json"))
            refused = false
            do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
            let restored = try AuthSwap$Codex.authData(home: base)
            try expect(refused && restored == nil && AuthSwap$Codex.isSwapped,
                       "Pending copyback resurrected credentials after native logout")
            return
        }
        try writeNativeCodexGrant(base, grant: "native-rotation-three")
        if poll {
            _ = await Renewal$Codex.shared.renew(columnID: AuthSwap$Codex.defaultColumnID, home: base, force: true)
            try expect(Fixture.refreshCalls == 0, "Partial copyback spent a cloned grant after another native rotation")
        }
        let target = replacement == "backup" ? AuthSwap$Codex.stashHome : profile
        if replacement != "none" { try writeNativeCodexGrant(target, grant: "replacement-independent-session") }
        let fresh = try AuthSwap$Codex.authData(home: target)
        refused = false
        do { try AuthSwap$Codex.restoreDefault() } catch { refused = true }
        if replacement != "none" {
            let preserved = replacement == "backup" && !refused ? base : target
            let retained = try AuthSwap$Codex.authData(home: preserved)
            try expect(retained == fresh,
                       "Copyback recovery overwrote a new independent login")
            let active = Renewal$Codex.refreshToken(base.appendingPathComponent("auth.json"))
            try expect(active == "native-rotation-three" || active == "replacement-independent-session",
                       "Copyback recovery published an already spent grant after a replacement login")
        } else {
            try expect(!refused && !AuthSwap$Codex.isSwapped,
                       "Retry did not recover a partially completed copyback")
            if distinct {
                let restored = try AuthSwap$Codex.authData(home: base)
                try expect(restored == primary,
                           "Retry replaced an independent primary session of the same account")
            } else {
                try expect(Renewal$Codex.refreshToken(base.appendingPathComponent("auth.json")) == "native-rotation-three",
                           "Retry published an older clone after another native rotation")
            }
            try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "native-rotation-three",
                       "Retry lost the selected profile's latest native rotation")
        }
        try expect(Fixture.refreshCalls == 0, "Copyback recovery issued an unnecessary refresh POST")
    }

    @MainActor
    private static func codexMixedAutoActivation(fileOwner: Bool = true) throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "native-owner", mode: fileOwner ? "file" : "keyring")
        try Fixture.codexMode(base, "auto")
        let alias = URL(fileURLWithPath: "/System/Volumes/Data" + base.path)
        let incoming = Fixture.root.appendingPathComponent("mixed-activation-payload")
        try Fixture.writeAuth(incoming, account: "independent-owner", refresh: "independent-refresh", expired: false)
        Fixture.codexKeychain[Fixture.codexKey(alias)] = try Data(contentsOf: incoming.appendingPathComponent("auth.json"))
        let original = try AuthSwap$Codex.authData(home: base)
        var refused = false
        do { try AuthSwap$Codex.activate(columnID: "codex:mixed-activation", home: alias) } catch { refused = true }
        try expect(refused == fileOwner,
                   "Activation accepted a destructive mixed owner or blocked independent Keychain namespaces")
        if fileOwner {
            let retained = try AuthSwap$Codex.authData(home: base)
            try expect(retained == original && !AuthSwap$Codex.isSwapped,
                       "Refused mixed activation changed the native file owner")
        } else {
            try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "independent-owner",
                       "An independent Keychain selection did not reach native storage")
            try AuthSwap$Codex.restoreDefault()
            let restored = try AuthSwap$Codex.authData(home: base)
            try expect(restored == original, "Independent Keychain restoration lost primary")
        }
    }

    @MainActor
    private static func codexSharedFallback(action: String, physicalAlias: Bool = true) async throws {
        let base = AuthSwap$Codex.baseHome
        let owner = ProfileDirectories.codexRoot.appendingPathComponent("file-owner")
        let alias = ProfileDirectories.codexRoot.appendingPathComponent("keyring-owner")
        let other = ProfileDirectories.codexRoot.appendingPathComponent("third-owner")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(owner, account: "sleeping-file", mode: "file")
        try Fixture.codexMode(owner, "auto")
        let original = try AuthSwap$Codex.authData(home: owner)
        if physicalAlias {
            try Foundation.FileManager.default.createSymbolicLink(at: alias, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + owner.path))
            let source = Fixture.root.appendingPathComponent("independent-kc-payload")
            try Fixture.writeAuth(source, account: "independent-kc", refresh: "independent-kc-refresh", expired: action == "renew")
            Fixture.codexKeychain[Fixture.codexKey(alias)] = try Data(contentsOf: source.appendingPathComponent("auth.json"))
            try expect(Fixture.codexKey(owner) != Fixture.codexKey(alias), "The fixture did not establish independent native Keychain namespaces")
        } else { try Fixture.codexLogin(alias, account: "independent-kc", mode: "auto", expired: action == "renew") }
        let account = DiscoveredAccount(id: "codex:keyring-owner", provider: .codex, profileName: "keyring-owner", source: .codexHome(alias))
        if action == "remove" {
            try AccountRemoval.remove(account)
            try expect(Fixture.codexKeychain[Fixture.codexKey(alias)] == nil, "Removal retained the selected Keychain login")
        } else if action == "renew" {
            if case .success = await Provider$Codex().fetch(account) {} else {
                throw Failure(description: "An independent Keychain session could not renew")
            }
            try expect(Fixture.refreshCalls == 1 && Renewal$Codex.refreshToken(alias.appendingPathComponent("auth.json")) == "synthetic-rotated",
                       "Keychain renewal replayed or lost its accepted grant")
        } else {
            try AuthSwap$Codex.activate(columnID: "codex:file-owner", home: owner)
            // Keep auto's native file fallback during a temporary Keychain outage.
            Fixture.denyCodexWrite = true
            try AuthSwap$Codex.activate(columnID: account.id, home: alias)
            Fixture.denyCodexWrite = false
            try Fixture.codexLogin(other, account: "third", mode: "file")
            try AuthSwap$Codex.activate(columnID: "codex:third-owner", home: other)
            try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "third", "The final native selection did not commit")
        }
        let retained = try AuthSwap$Codex.authData(home: owner)
        try expect(retained == original, "An independent Keychain profile operation deleted the file owner's only login")
    }

    @MainActor
    private static func codexBackupRecovery(mode: String = "file", fails: Bool = true, action: String = "restore") async throws {
        let base = AuthSwap$Codex.baseHome
        let profile = ProfileDirectories.codexRoot.appendingPathComponent("refused-rollback")
        let id = "codex:refused-rollback"
        try Fixture.codexLogin(base, account: "primary", mode: mode, expired: action == "renew")
        let primary = try AuthSwap$Codex.authData(home: base)
        try Fixture.codexLogin(profile, account: "selected", mode: "keyring")
        try AuthSwap$Codex.activate(columnID: id, home: profile)
        let native = try AuthSwap$Codex.authData(home: base)
        let backupHome = AuthSwap$Codex.stashHome
        if fails {
            if mode == "file" { Fixture.denyCredentialChmodHome = AuthStorage$Codex.canonicalPath(backupHome) }
            else { Fixture.denyCodexWriteAccount = Fixture.codexKey(backupHome) }
        }
        Fixture.denyCodexDeleteAccount = Fixture.codexKey(profile)
        let account = DiscoveredAccount(id: id, provider: .codex, profileName: "refused-rollback", source: .codexHome(profile))
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        let after = try AuthSwap$Codex.authData(home: base)
        try expect(refused && after == native && AuthSwap$Codex.activeColumnID == id,
                   "A backup restoration failure skipped rollback of native credentials and selection markers")
        let recovered = try AuthSwap$Codex.authData(columnID: AuthSwap$Codex.defaultColumnID, home: base)
        try expect(recovered == primary && Discovery$Real().discover().contains { $0.id == AuthSwap$Codex.defaultColumnID },
                   "The refused removal lost the primary login or hid its recovery backup")
        if mode == "keyring" {
            try expect(!Foundation.FileManager.default.fileExists(atPath: AuthSwap$Codex.stashHome.appendingPathComponent("auth.json").path),
                       "Keychain recovery exported primary credentials to a file")
        }
        if action == "renew" {
            let primaryAccount = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex, profileName: "main", source: .codexHome(base))
            if case .success = await Provider$Codex().fetch(primaryAccount) {} else {
                throw Failure(description: "Recovered primary could not renew while its old backup remained unwritable")
            }
            try expect(Fixture.refreshCalls == 1 && Renewal$Codex.refreshToken(AuthSwap$Codex.stashHome.appendingPathComponent("auth.json")) == "synthetic-rotated",
                       "Recovered primary lost or replayed its rotation")
            let selected = try AuthSwap$Codex.authData(home: base)
            try expect(selected == native, "Recovered primary renewal changed the selected native login")
            return
        }
        Fixture.denyCredentialChmodHome = nil
        Fixture.denyCodexWriteAccount = nil
        Fixture.denyCodexDeleteAccount = nil
        if action == "readd" {
            try AccountRemoval.remove(account)
            try expect(!Foundation.FileManager.default.fileExists(atPath: profile.path), "Retry did not free the profile name")
            try Fixture.codexLogin(profile, account: "replacement", mode: "file")
            try AuthSwap$Codex.activate(columnID: id, home: profile)
            try expect(Provider$Codex.readAuth(codexHome: base)?.accountID == "replacement", "Same-name re-add reused the removed login")
        } else { try writeNativeCodexGrant(base, grant: "after-refusal-native-rotation") }
        try AuthSwap$Codex.restoreDefault()
        let restored = try AuthSwap$Codex.authData(home: base)
        try expect(restored == primary && !AuthSwap$Codex.isSwapped,
                   "Return to primary lost its recovery backup or retained the old selection")
        if action != "readd" {
            try expect(Renewal$Codex.refreshToken(profile.appendingPathComponent("auth.json")) == "after-refusal-native-rotation",
                       "Recovery broke later native copyback")
        }
    }

    @MainActor
    private static func usageLoginSnapshot(codex: Bool, backend: String = "file", change: String = "login", status: Int = 200) async throws {
        let account: DiscoveredAccount
        let home = ProfileDirectories.codexRoot.appendingPathComponent("usage-current")
        if codex {
            Fixture.keychainExists = false
            try Fixture.codexLogin(home, account: "old-login", mode: backend)
            account = DiscoveredAccount(id: "codex:usage-current", provider: .codex, profileName: "usage-current", source: .codexHome(home))
        } else if backend == "file" {
            let found = try claudeFileAccount(primary: true, expired: false)
            account = found.0
        } else {
            try Foundation.FileManager.default.createDirectory(at: Fixture.storageDirectory, withIntermediateDirectories: true)
            Fixture.keychain = Fixture.claudeLogin("old-login", expired: false)
            Fixture.onlyClaudeService = Fixture.service
            Fixture.discoveredClaudeService = Fixture.service
            account = DiscoveredAccount(id: "claude:" + Fixture.service, provider: .claude, profileName: "main", source: .claudeKeychain(service: Fixture.service, configDir: nil))
        }
        Fixture.holdFirstUsage = true
        Fixture.firstUsageStatus = status
        Fixture.manualPollingTimer = true
        defer { Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock() }
        let provider: any UsageProvider = codex ? Provider$Codex() : Provider$Claude()
        let probe = UsageCompletionProbe(provider)
        let store = UsageStore(providers: [codex ? .codex : .claude: probe], discovery: Discovery$Real())
        store.start()
        try expect(store.account(for: account.id) != nil, "Initial login was not discovered")
        for _ in 0..<400 {
            if Fixture.usageCalls == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(Fixture.usageCalls == 1, "Usage did not reach the held response boundary")
        if change == "login" {
            if codex { try Fixture.codexLogin(home, account: "new-login", mode: backend) }
            else if backend == "file" {
                let file = AuthStorage$Claude.credentialFile(service: Fixture.service)!
                try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("new-login", expired: false)).write(to: file, options: .atomic)
            } else { Fixture.tryNativeLogin(); try expect(!Fixture.nativeLoginPending, "A fresh login was blocked unexpectedly") }
        } else if change == "metadata" {
            if codex {
                var root = try JSONSerialization.jsonObject(with: AuthSwap$Codex.authData(home: home)!) as! [String: Any]
                root["last_refresh"] = "metadata-only"
                try AuthStorage$Codex(home: home).save(JSONSerialization.data(withJSONObject: root))
            } else { Fixture.keychain["unknown"] = "metadata-only" }
        } else if change == "unreadable" {
            if codex {
                try Fixture.writeAuth(home, account: "fallback-other", refresh: "fallback-other-grant", expired: false)
                Fixture.denyCodexRead = true
            } else {
                let file = Fixture.storageDirectory.appendingPathComponent(".credentials.json")
                try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("fallback-other", expired: false)).write(to: file)
                Fixture.denyClaudeRead = true
            }
        }
        store.rediscover(force: true)
        Fixture.lock.lock(); Fixture.releaseFirstUsage = true; Fixture.lock.unlock()
        for _ in 0..<400 {
            if await probe.completed == 1 { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(await probe.completed == 1, "The held usage request did not finish")
        try await Task.sleep(nanoseconds: 20_000_000)
        let accepted = change == "none" || change == "metadata"
        let columnHasOld = store.columns.first { $0.id == account.id }?.windows.first?.utilization == 12
        let cacheHasOld = UsageCache().load(id: account.id)?.windows.first?.utilization == 12
        try expect(columnHasOld == accepted && cacheHasOld == accepted,
                   "A stale successful response populated the replacement login's column or cache")
        guard let tick = Fixture.pollingTick else { throw Failure(description: "UsageStore did not install its scheduler") }
        if change == "login" {
            for _ in 0..<400 {
                tick()
                if await probe.completed == 2 && store.columns.first(where: { $0.id == account.id })?.windows.first?.utilization == 84 { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            try expect(await probe.completed == 2 && UsageCache().load(id: account.id)?.windows.first?.utilization == 84,
                       "The scheduler did not poll the replacement login after discarding old usage")
        } else {
            for _ in 0..<16 { tick(); try await Task.sleep(nanoseconds: 5_000_000) }
            try expect(await probe.completed == 1, "Metadata or an unavailable preferred owner caused rapid repeated polling")
        }
        try expect(Fixture.refreshCalls == 0, "A late response spent a fresh replacement login's refresh grant")
    }

    @MainActor
    private static func codexSharedDirectoryRemoval(peerBackend: String = "file", alias: Bool = true, selected: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let target = ProfileDirectories.codexRoot.appendingPathComponent("physical-owner")
        let peer = ProfileDirectories.codexRoot.appendingPathComponent("other-owner")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(target, account: "target", mode: "auto")
        if alias {
            try Foundation.FileManager.default.createSymbolicLink(at: peer, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + target.path))
            if peerBackend == "file" {
                try Fixture.writeAuth(target, account: "peer", refresh: "peer-refresh", expired: false)
            } else {
                let payload = Fixture.root.appendingPathComponent("peer-keyring-payload")
                try Fixture.writeAuth(payload, account: "peer", refresh: "peer-refresh", expired: false)
                Fixture.codexKeychain[Fixture.codexKey(peer)] = try Data(contentsOf: payload.appendingPathComponent("auth.json"))
            }
        } else { try Fixture.codexLogin(peer, account: "peer", mode: peerBackend) }
        let original = try AuthSwap$Codex.authData(home: peer)
        if selected { try AuthSwap$Codex.activate(columnID: "codex:physical-owner", home: target) }
        let account = DiscoveredAccount(id: "codex:physical-owner", provider: .codex, profileName: "physical-owner", source: .codexHome(target))
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        let retained = try AuthSwap$Codex.authData(home: peer)
        try expect(refused == alias && retained == original,
                   "Physical directory removal destroyed another native namespace's login or blocked a separate owner")
        if alias && selected {
            try expect(AuthSwap$Codex.activeColumnID == account.id && Provider$Codex.readAuth(codexHome: base)?.accountID == "target",
                       "Refusing shared-directory removal failed to restore the selected native account")
        }
    }

    @MainActor
    private static func claudeRootRetargetRemoval(identity: String, retarget: Bool = true) throws {
        let manager = Foundation.FileManager.default
        let first = Fixture.root.appendingPathComponent("owner-a")
        let second = Fixture.root.appendingPathComponent("owner-b")
        let original = first.appendingPathComponent("work")
        let replacement = second.appendingPathComponent("work")
        try manager.createDirectory(at: original, withIntermediateDirectories: true)
        try manager.createDirectory(at: replacement, withIntermediateDirectories: true)
        try manager.createSymbolicLink(at: ProfileDirectories.claudeRoot, withDestinationURL: first)
        let logical = ProfileDirectories.claudeRoot.appendingPathComponent("work")
        let configPath = identity == "physical" ? logical.resolvingSymlinksInPath().path + "/" : logical.path
        let service = Fixture.service + "-" + SHA256.hash(data: Data(configPath.utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(8)
        let originalData = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("original", expired: false))
        let originalFile = original.appendingPathComponent(".credentials.json")
        if identity == "file" {
            Fixture.claudeEntries = [:]
            try originalData.write(to: originalFile)
        } else {
            Fixture.claudeEntries = [service: Fixture.claudeLogin("original", expired: false)]
        }
        let replacementFile = replacement.appendingPathComponent(".credentials.json")
        let replacementData = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
        let settings = replacement.appendingPathComponent("settings.json")
        let settingsData = Data("replacement-settings".utf8)
        try replacementData.write(to: replacementFile)
        try settingsData.write(to: settings)
        guard let account = Discovery$Real().discover().first(where: { $0.id == "claude:" + service }) else {
            throw Failure(description: "Original Claude owner was not discovered")
        }
        try expect(AuthStorage$Claude.configPath(for: service) == configPath, "Fixture resolved a different native owner")
        if retarget {
            try manager.removeItem(at: ProfileDirectories.claudeRoot)
            try manager.createSymbolicLink(at: ProfileDirectories.claudeRoot, withDestinationURL: second)
        }
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        let preserved = (try? Data(contentsOf: replacementFile)) == replacementData
            && (try? Data(contentsOf: settings)) == settingsData
        print("Claude root identity=\(identity), retarget=\(retarget), refused=\(refused), replacement preserved=\(preserved)")
        try expect(preserved, "Stale Claude removal deleted the replacement credentials or settings")
        try expect(refused == retarget, "Claude removal did not distinguish a replaced owner from the original")
        if identity == "file" {
            try expect(manager.fileExists(atPath: originalFile.path) == retarget,
                       "Claude removal changed the original file owner's credentials unexpectedly")
        } else {
            try expect((Fixture.claudeEntries?[service] != nil) == retarget,
                       "Claude removal changed the original Keychain owner unexpectedly")
        }
        if retarget {
            // The refusal must release its leases so the original owner remains removable.
            try manager.removeItem(at: ProfileDirectories.claudeRoot)
            try manager.createSymbolicLink(at: ProfileDirectories.claudeRoot, withDestinationURL: first)
            try AccountRemoval.remove(account)
        }
        try expect(!manager.fileExists(atPath: original.path), "Original Claude profile could not be removed")
        try expect((try? Data(contentsOf: replacementFile)) == replacementData,
                   "Restoring the original root changed the replacement login")
    }

    @MainActor
    private static func codexUncertainOwner(mode: String = "file", response: String = "lost",
                                             change: String = "login") async throws {
        Fixture.keychainExists = false
        let home = ProfileDirectories.codexRoot.appendingPathComponent("renewal-owner")
        try Fixture.codexLogin(home, account: "old-login", mode: mode, expired: true)
        let original = try AuthSwap$Codex.authData(home: home)!
        let account = DiscoveredAccount(id: "codex:renewal-owner", provider: .codex,
                                        profileName: "renewal-owner", source: .codexHome(home))
        Fixture.response = response == "lost" ? .heldLost : response == "rejected" ? .heldRejected : .heldRenewed
        let request = Task { await Provider$Codex().fetch(account) }
        try await waitForRefresh(1)
        if change == "login" || change == "same-grant" {
            try Fixture.codexLogin(home, account: change == "login" ? "new-login" : "old-login",
                                   mode: mode, expired: false)
        } else if change == "metadata" {
            var root = try JSONSerialization.jsonObject(with: original) as! [String: Any]
            root["last_refresh"] = "2026-10-23T00:00:00Z"
            try JSONSerialization.data(withJSONObject: root).write(to: home.appendingPathComponent("auth.json"))
        } else if change == "denied" {
            try Fixture.writeAuth(home, account: "fallback", refresh: "fallback-grant", expired: false)
            Fixture.denyCodexRead = true
        }
        let replacement: Data?
        if change == "denied" { replacement = nil }
        else { replacement = try AuthSwap$Codex.authData(home: home) }
        Fixture.releaseRefresh()
        let result = await request.value
        if change == "login" || change == "same-grant" {
            guard case .success = result else {
                throw Failure(description: "A retired refresh response hid the fresh CLI login's usage: \(result)")
            }
            try expect(Fixture.usageCalls == 1, "The fresh CLI login's usage was not read exactly once")
        } else if change == "denied" {
            guard case .failure = result else {
                throw Failure(description: "An unavailable preferred owner inherited the old grant's reauth result: \(result)")
            }
        } else {
            guard case .reauth = result else {
                throw Failure(description: "The possibly spent unchanged grant was not fenced: \(result)")
            }
            try expect(Fixture.usageCalls == 0, "An uncertain unchanged grant reached the usage endpoint")
        }
        Fixture.denyCodexRead = false
        let current = try AuthSwap$Codex.authData(home: home)
        try expect(current == (change == "denied" ? original : replacement),
                   "A retired refresh response changed the current credentials")
        if response == "lost" {
            let copy = ProfileDirectories.codexRoot.appendingPathComponent("old-grant-copy")
            try Fixture.codexMode(copy, "file")
            try original.write(to: copy.appendingPathComponent("auth.json"))
            Fixture.response = .renewed
            let repeated = await Renewal$Codex.shared.renew(columnID: "codex:old-grant-copy", home: copy, force: true)
            try expect(repeated == .uncertain, "Replacing the login cleared the uncertain old grant's quarantine")
        }
        try expect(Fixture.refreshCalls == 1, "The potentially spent refresh grant was replayed")
    }

    @MainActor
    private static func codexDeniedOwnerInventory(action: String) throws {
        let base = AuthSwap$Codex.baseHome
        let target = ProfileDirectories.codexRoot.appendingPathComponent("inventory-owner")
        let peer = ProfileDirectories.codexRoot.appendingPathComponent("inventory-peer")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(target, account: "target", mode: "auto")
        try Foundation.FileManager.default.createSymbolicLink(
            at: peer, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + target.path))
        try Fixture.writeAuth(target, account: "peer", refresh: "peer-refresh", expired: false)
        let peerAuth = try AuthSwap$Codex.authData(home: peer)
        let targetAuth = Fixture.codexKeychain[Fixture.codexKey(target)]
        let payloadHome = Fixture.root.appendingPathComponent("inventory-payload")
        try Fixture.writeAuth(payloadHome, account: "updated", refresh: "updated-refresh", expired: false)
        let payload = try Data(contentsOf: payloadHome.appendingPathComponent("auth.json"))
        try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o300], ofItemAtPath: ProfileDirectories.codexRoot.path)
        defer { try? Foundation.FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ProfileDirectories.codexRoot.path) }
        do {
            _ = try Foundation.FileManager.default.contentsOfDirectory(atPath: ProfileDirectories.codexRoot.path)
            throw Failure(description: "Fixture did not deny managed-root enumeration")
        } catch let failure as Failure { throw failure } catch {}

        let storage = try AuthStorage$Codex(home: target)
        if action == "remove" {
            let account = DiscoveredAccount(id: "codex:inventory-owner", provider: .codex,
                                            profileName: "inventory-owner", source: .codexHome(target))
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(refused && Fixture.codexKeychain[Fixture.codexKey(target)] == targetAuth,
                       "Unavailable owner inventory authorized destructive profile removal")
        } else if action == "save" {
            try storage.save(payload)
            try expect(Fixture.codexKeychain[Fixture.codexKey(target)] == payload,
                       "Unavailable owner inventory blocked the separate Keychain update")
        } else {
            try storage.delete()
            try expect(Fixture.codexKeychain[Fixture.codexKey(target)] == nil,
                       "Unavailable owner inventory blocked deletion of the separate Keychain entry")
        }
        let retained = try AuthSwap$Codex.authData(home: peer)
        try expect(peerAuth != nil && retained == peerAuth,
                   "Unavailable owner inventory allowed cleanup of another native namespace's file login")
    }

    @MainActor
    private static func codexMissingOwnerInventoryControl() throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "primary", mode: "auto")
        let payload = try AuthSwap$Codex.authData(home: base)
        try Fixture.writeAuth(base, account: "stale-fallback", refresh: "stale-refresh", expired: false)
        try expect(!Foundation.FileManager.default.fileExists(atPath: ProfileDirectories.codexRoot.path),
                   "Missing-root control unexpectedly created a managed root")
        let storage = try AuthStorage$Codex(home: base)
        try storage.save(payload!)
        try expect(!Foundation.FileManager.default.fileExists(atPath: base.appendingPathComponent("auth.json").path),
                   "A genuinely absent profile root prevented stale fallback cleanup")
        try storage.delete()
        try expect(Fixture.codexKeychain[Fixture.codexKey(base)] == nil,
                   "A genuinely absent profile root prevented primary credential deletion")
    }

    @MainActor
    private static func codexPrimaryBackupAlias(action: String, mode: String = "file",
                                               recovery: Bool = false, separate: Bool = false,
                                               dataAlias: Bool = false, lostSelection: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let parent = separate ? Fixture.root.appendingPathComponent("external-default-profiles")
            : DesktopApp.supportDirectory.appendingPathComponent("codex-app")
        try Foundation.FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let destination = dataAlias ? URL(fileURLWithPath: "/System/Volumes/Data" + parent.path) : parent
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: destination)
        try Fixture.codexLogin(base, account: "primary", mode: mode)
        let primary = try AuthSwap$Codex.authData(home: base)
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        if recovery {
            let original = AuthSwap$Codex.stashHome
            Fixture.denyCredentialChmodHome = AuthStorage$Codex.canonicalPath(original)
            Fixture.denyCodexDeleteAccount = Fixture.codexKey(selected)
            defer { Fixture.denyCredentialChmodHome = nil; Fixture.denyCodexDeleteAccount = nil }
            let account = DiscoveredAccount(id: "codex:selected", provider: .codex,
                                            profileName: "selected", source: .codexHome(selected))
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(refused && AuthSwap$Codex.stashHome.path != original.path,
                       "Fixture did not move the refused rollback into a recovery backup")
            Fixture.denyCredentialChmodHome = nil
            Fixture.denyCodexDeleteAccount = nil
        }
        let name = separate ? "default" : AuthSwap$Codex.stashHome.lastPathComponent
        let alias = ProfileDirectories.codexRoot.appendingPathComponent(name)
        let id = AuthSwap$Codex.profileColumnID(name)
        if separate { try Fixture.codexLogin(alias, account: "separate-default", mode: "file") }
        if dataAlias {
            try expect(AuthStorage$Codex.canonicalPath(alias) != AuthStorage$Codex.canonicalPath(AuthSwap$Codex.stashHome),
                       "Fixture did not create distinct native namespaces for the same backup directory")
        }
        if lostSelection {
            for key in ["codexAppAccountID", "codexAppAccountHome", "codexAppAccountPhysicalHome"] {
                UserDefaults.standard.removeObject(forKey: key)
            }
            try expect(!AuthSwap$Codex.isSwapped, "Fixture retained the lost selection markers")
        }
        if action == "discovery" || separate {
            let accounts = Discovery$Real().discover()
            try expect(accounts.contains { $0.id == AuthSwap$Codex.defaultColumnID },
                       "Primary backup protection hid the primary column")
            let discovered = accounts.first { $0.id == id }
            try expect((discovered != nil) == separate,
                       "Discovery exposed the current primary backup as another removable profile")
            if let discovered {
                try expect(AccountRemoval.isExtraProfile(discovered), "A separate default profile lost its removal action")
                try AccountRemoval.remove(discovered)
            }
        } else {
            var refused = false
            do {
                if action == "direct" { try AuthSwap$Codex.removeAuth(home: alias) }
                else {
                    let stale = DiscoveredAccount(id: id, provider: .codex, profileName: name, source: .codexHome(alias))
                    try AccountRemoval.remove(stale)
                }
            } catch { refused = true }
            try expect(refused, "A stale or direct removal bypassed primary backup ownership")
        }
        let retained = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
        let expectedID = lostSelection ? AuthSwap$Codex.defaultColumnID : "codex:selected"
        try expect(retained == primary && AuthSwap$Codex.activeColumnID == expectedID
                   && Provider$Codex.readAuth(codexHome: base)?.accountID == "selected",
                   "Backup alias handling changed the primary login or the selected native account")
    }

    @MainActor
    private static func codexCachedRenewalOwner(mode: String = "file", afterResponse: Bool = false,
                                                 metadataOnly: Bool = false, rejected: Bool = false) async throws {
        Fixture.keychainExists = false
        let home = ProfileDirectories.codexRoot.appendingPathComponent("cached-renewal-owner")
        try Fixture.codexLogin(home, account: "owner", mode: mode, expired: true)
        let original = try AuthSwap$Codex.authData(home: home)!
        var login = try JSONSerialization.jsonObject(with: original) as! [String: Any]
        if metadataOnly {
            login["last_refresh"] = "2026-10-23T00:00:00Z"
        } else {
            var tokens = login["tokens"] as! [String: Any]
            tokens["access_token"] = Fixture.accessToken(expiresAt: Date().addingTimeInterval(86_400).timeIntervalSince1970)
            login["tokens"] = tokens
        }
        let replacement = try JSONSerialization.data(withJSONObject: login)
        func replaceLogin() throws {
            if mode == "file" { try replacement.write(to: home.appendingPathComponent("auth.json")) }
            else { Fixture.codexKeychain[Fixture.codexKey(home)] = replacement }
        }
        if !metadataOnly {
            guard let expiry = Provider$Codex.parseAuth(replacement)?.expiresAt else {
                throw Failure(description: "Replacement login is missing its access expiry")
            }
            try expect(expiry.timeIntervalSinceNow > 60 && expiry.timeIntervalSinceNow < Renewal$Codex.window,
                       "Replacement access token must be usable and inside the renewal window")
        }
        let account = DiscoveredAccount(id: "codex:cached-renewal-owner", provider: .codex,
                                        profileName: "cached-renewal-owner", source: .codexHome(home))
        Fixture.response = rejected ? .heldRejected : .heldLost
        let request = Task { await Provider$Codex().fetch(account) }
        try await waitForRefresh(1)
        if !afterResponse { try replaceLogin() }
        Fixture.releaseRefresh()
        let first = await request.value
        if afterResponse || metadataOnly {
            guard case .reauth = first else {
                throw Failure(description: "The original failed session was not fenced: \(first)")
            }
        } else {
            guard case .success = first else {
                throw Failure(description: "The old response hid a fresh near-window CLI access token: \(first)")
            }
        }
        if afterResponse { try replaceLogin() }
        for _ in 0..<2 {
            let result = await Provider$Codex().fetch(account)
            if metadataOnly {
                guard case .reauth = result else {
                    throw Failure(description: "Outer metadata cleared a failed session's result: \(result)")
                }
            } else {
                guard case .success = result else {
                    throw Failure(description: "Cached old grant status hid a fresh CLI access token: \(result)")
                }
            }
        }
        try expect(Fixture.usageCalls == (metadataOnly ? 0 : afterResponse ? 2 : 3),
                   "Repeated polls failed to read the fresh CLI session's usage")
        let current = try AuthSwap$Codex.authData(home: home)
        try expect(current == replacement, "Quarantined renewal changed the replacement credentials")
        let copy = ProfileDirectories.codexRoot.appendingPathComponent("cached-old-session-copy")
        try Fixture.codexMode(copy, "file")
        try original.write(to: copy.appendingPathComponent("auth.json"))
        let copied = await Renewal$Codex.shared.renew(columnID: "codex:cached-old-session-copy", home: copy, force: true)
        try expect(copied == (rejected ? .rejected : .uncertain),
                   "Moving the original session to another home cleared its failed result")
        try expect(Fixture.refreshCalls == 1, "Polling the new access token replayed its quarantined refresh grant")
    }

    @MainActor
    private static func codexBackupDirectoryGuard(ancestor: Bool = false, dataAlias: Bool = false,
                                                 keyringPeer: Bool = false, menu: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let parent = ancestor ? DesktopApp.supportDirectory
            : DesktopApp.supportDirectory.appendingPathComponent("codex-app")
        try Foundation.FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let destination = dataAlias ? URL(fileURLWithPath: "/System/Volumes/Data" + parent.path) : parent
        try Foundation.FileManager.default.createSymbolicLink(at: ProfileDirectories.codexRoot, withDestinationURL: destination)
        try Fixture.codexLogin(base, account: "primary", mode: keyringPeer ? "keyring" : "file")
        let primary = try AuthSwap$Codex.authData(home: base)
        let name = ancestor ? "codex-app" : "default"
        let target = ProfileDirectories.codexRoot.appendingPathComponent(name)
        let id = AuthSwap$Codex.profileColumnID(name)
        if ancestor && !menu { try Fixture.codexLogin(target, account: "ancestor", mode: "file") }
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        if keyringPeer {
            try expect(Fixture.codexKey(target) != Fixture.codexKey(AuthSwap$Codex.stashHome),
                       "Fixture did not create an independent native Keychain namespace")
            try Fixture.codexLogin(target, account: "independent-peer", mode: "keyring")
        }
        let targetAuth = try AuthSwap$Codex.authData(home: target)
        let settings = target.appendingPathComponent("settings-sentinel")
        let settingsData = Data("profile-configuration".utf8)
        try settingsData.write(to: settings)
        let accounts = Discovery$Real().discover()
        if menu {
            if !ancestor {
                try expect(!accounts.contains { $0.id == id }, "Discovery exposed the primary backup as an extra profile")
            }
            let unfinished = ProfileDirectories.codexRoot.appendingPathComponent("unfinished")
            try Foundation.FileManager.default.createDirectory(at: unfinished, withIntermediateDirectories: true)
            let store = UsageStore(providers: [:], discovery: Discovery$Real())
            store.rediscover(force: true)
            let entries = RegressionProfileMenu(store: store).profiles()
            try expect(!entries.contains { $0.url.path == target.path },
                       "The unfinished-profile menu offered removal of a primary backup or its ancestor")
            try expect(entries.contains { $0.url.path == unfinished.path },
                       "Primary backup protection hid an unrelated unfinished profile")
        } else {
            guard let account = accounts.first(where: { $0.id == id }) else {
                throw Failure(description: "Backup protection hid an independent account")
            }
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(refused, "Managed directory removal deleted an embedded primary backup")
            let retainedTarget = try AuthSwap$Codex.authData(home: target)
            try expect(retainedTarget == targetAuth, "Refused shared-directory removal changed the independent account")
            if keyringPeer {
                try expect(Provider$Codex.readAuth(codexHome: target)?.accountID == "independent-peer",
                           "Backup recognition merged independent Keychain namespaces")
            }
        }
        let retained = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
        try expect(retained == primary && (try? Data(contentsOf: settings)) == settingsData
                   && AuthSwap$Codex.activeColumnID == "codex:selected"
                   && Provider$Codex.readAuth(codexHome: base)?.accountID == "selected",
                   "Backup directory protection changed credentials, configuration or native selection")
    }

    @MainActor
    private static func codexBackupPrimaryAncestorControl(spoofed: Bool = false) throws {
        Fixture.codexHome = DesktopApp.supportDirectory.path
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        let primary = try AuthSwap$Codex.authData(home: base)
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
        try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        let projects = base.appendingPathComponent("projects-sentinel")
        let projectData = Data("native-projects".utf8)
        try projectData.write(to: projects)
        if spoofed {
            var refused = false
            do { try AuthSwap$Codex.removeAuth(home: AuthSwap$Codex.stashHome, columnID: AuthSwap$Codex.defaultColumnID) }
            catch { refused = true }
            let retained = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
            try expect(refused && retained == primary && AuthSwap$Codex.activeColumnID == "codex:selected",
                       "A forged primary ID authorized deletion of a different backup owner")
        } else {
            let account = DiscoveredAccount(id: AuthSwap$Codex.defaultColumnID, provider: .codex,
                                            profileName: "main", source: .codexHome(base))
            try AccountRemoval.remove(account)
            let removed = try AuthSwap$Codex.authData(home: base)
            try expect(removed == nil && !AuthSwap$Codex.isSwapped,
                       "Backup ancestor protection blocked the genuine primary credential transaction")
        }
        try expect((try? Data(contentsOf: projects)) == projectData
                   && Provider$Codex.readAuth(codexHome: selected)?.accountID == "selected",
                   "Primary ancestor handling removed native projects or the selected profile")
    }

    @MainActor
    private static func codexPrimaryRemovalInventory(state: String = "denied", mode: String = "auto",
                                                      selected: Bool = false, direct: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "primary", mode: mode)
        let primary = try AuthSwap$Codex.authData(home: base)
        if selected {
            let profile = ProfileDirectories.codexRoot.appendingPathComponent("selected")
            try Fixture.codexLogin(profile, account: "selected", mode: "keyring")
            try AuthSwap$Codex.activate(columnID: "codex:selected", home: profile)
        }
        guard let preferred = Fixture.codexKeychain[Fixture.codexKey(base)] else {
            throw Failure(description: "Fixture did not create the preferred native Keychain login")
        }
        let fallback = base.appendingPathComponent("auth.json")
        if mode == "auto" { try preferred.write(to: fallback) }
        let id = AuthSwap$Codex.defaultColumnID
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "Fixture did not discover the removable primary")
        store.setCustomName("Retained primary label", for: id)
        store.setHidden(id, hidden: true)
        if state != "missing" {
            try Foundation.FileManager.default.createDirectory(at: ProfileDirectories.codexRoot, withIntermediateDirectories: true)
        } else {
            try expect(!Foundation.FileManager.default.fileExists(atPath: ProfileDirectories.codexRoot.path),
                       "Missing-root control unexpectedly created a managed profile root")
        }
        if state == "denied" {
            try Foundation.FileManager.default.setAttributes([.posixPermissions: 0o300], ofItemAtPath: ProfileDirectories.codexRoot.path)
            do {
                _ = try Foundation.FileManager.default.contentsOfDirectory(atPath: ProfileDirectories.codexRoot.path)
                throw Failure(description: "Fixture did not deny managed-root enumeration")
            } catch let failure as Failure { throw failure } catch {}
        }
        defer {
            if state != "missing" {
                try? Foundation.FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ProfileDirectories.codexRoot.path)
            }
        }
        var refused = false
        do {
            if direct { try AuthSwap$Codex.removeAuth(home: base) }
            else { try store.removeAccount(id: id) }
        } catch { refused = true }
        if state == "denied" {
            try expect(refused && Fixture.codexKeychain[Fixture.codexKey(base)] == preferred,
                       "Unavailable inventory allowed a partial primary removal to report success")
            try expect(mode != "auto" || (try? Data(contentsOf: fallback)) == preferred,
                       "Refused primary removal changed the native file fallback")
            try expect(store.account(for: id) != nil && store.customNames[id] == "Retained primary label" && store.hidden.contains(id),
                       "Partial primary removal cleared column settings before rediscovering the retained fallback")
            if selected {
                let retained = try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome)
                try expect(retained == primary && AuthSwap$Codex.activeColumnID == "codex:selected",
                           "Inventory refusal occurred after changing native selection or primary backup")
            }
        } else {
            try expect(!refused && Fixture.codexKeychain[Fixture.codexKey(base)] == nil
                       && !Foundation.FileManager.default.fileExists(atPath: fallback.path),
                       "A readable or absent profile root blocked complete primary removal")
            try expect(store.account(for: id) == nil && !Discovery$Real().discover().contains { $0.id == id }
                       && store.customNames[id] == nil && !store.hidden.contains(id),
                       "Successful primary removal resurrected the account or retained its column settings")
        }
    }

    @MainActor
    private static func codexCompleteRemovalPeer(peerState: String = "denied", mode: String = "auto",
                                                 fallback: Bool = true, backup: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        try Fixture.codexLogin(base, account: "primary", mode: mode)
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("selected")
        if backup {
            try Fixture.codexLogin(selected, account: "selected", mode: "keyring")
            try AuthSwap$Codex.activate(columnID: "codex:selected", home: selected)
        }
        let target = backup ? AuthSwap$Codex.stashHome : base
        let id = backup ? "codex:selected" : AuthSwap$Codex.defaultColumnID
        guard let preferred = Fixture.codexKeychain[Fixture.codexKey(target)] else {
            throw Failure(description: "Fixture did not create preferred credentials")
        }
        let native = try AuthSwap$Codex.authData(home: base)
        let peer = ProfileDirectories.codexRoot.appendingPathComponent("peer")
        try Foundation.FileManager.default.createDirectory(at: ProfileDirectories.codexRoot, withIntermediateDirectories: true)
        try Foundation.FileManager.default.createSymbolicLink(
            at: peer, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + target.path))
        try expect(Fixture.codexKey(peer) != Fixture.codexKey(target),
                   "Fixture did not create separate native namespaces")
        if peerState != "file" {
            let payload = Fixture.root.appendingPathComponent("peer-payload")
            try Fixture.writeAuth(payload, account: "peer", refresh: "peer-refresh", expired: false)
            Fixture.codexKeychain[Fixture.codexKey(peer)] = try Data(contentsOf: payload.appendingPathComponent("auth.json"))
        }
        let peerPreferred = Fixture.codexKeychain[Fixture.codexKey(peer)]
        let file = target.appendingPathComponent("auth.json")
        if fallback { try preferred.write(to: file) }
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "Fixture did not discover the account before removal")
        store.setCustomName("Retained owner", for: id)
        store.setHidden(id, hidden: true)
        _ = try Foundation.FileManager.default.contentsOfDirectory(atPath: ProfileDirectories.codexRoot.path)
        Fixture.denyCodexRead = peerState == "denied"
        defer { Fixture.denyCodexRead = false }
        var refused = false
        do { try store.removeAccount(id: id) } catch { refused = true }
        Fixture.denyCodexRead = false
        let mustRefuse = mode == "auto" && fallback && peerState != "keyring"
        try expect(refused == mustRefuse,
                   "Complete removal ignored a retained auto fallback or blocked an independent Keychain owner")
        if mustRefuse {
            try expect(Fixture.codexKeychain[Fixture.codexKey(target)] == preferred
                       && (try? Data(contentsOf: file)) == preferred,
                       "Refused complete removal changed preferred credentials or their fallback")
            try expect(store.account(for: id) != nil && store.customNames[id] == "Retained owner" && store.hidden.contains(id),
                       "Partial removal cleared metadata before rediscovering the retained login")
            let retainedNative = try AuthSwap$Codex.authData(home: base)
            try expect(retainedNative == native
                       && AuthSwap$Codex.activeColumnID == (backup ? "codex:selected" : AuthSwap$Codex.defaultColumnID),
                       "Shared-backup refusal occurred after native copyback or selection changed")
        } else {
            try expect(Fixture.codexKeychain[Fixture.codexKey(target)] == nil
                       && !Foundation.FileManager.default.fileExists(atPath: file.path),
                       "Successful complete removal retained the owner's credentials")
            try expect(store.account(for: id) == nil && store.customNames[id] == nil && !store.hidden.contains(id)
                       && !Discovery$Real().discover().contains { $0.id == id },
                       "Successful complete removal resurrected the account or retained its metadata")
        }
        try expect(Fixture.codexKeychain[Fixture.codexKey(peer)] == peerPreferred,
                   "Complete removal changed a separate native Keychain namespace")
    }

    @MainActor
    private static func codexSharedAutoLinkRemoval(direct: Bool = false) throws {
        let base = AuthSwap$Codex.baseHome
        let alias = ProfileDirectories.codexRoot.appendingPathComponent("linked-owner")
        let physical = ProfileDirectories.codexRoot.appendingPathComponent("physical-owner")
        try Fixture.codexLogin(base, account: "primary", mode: "file")
        try Fixture.codexLogin(alias, account: "alias-owner", mode: "auto")
        guard let account = Discovery$Real().discover().first(where: { $0.id == "codex:linked-owner" }),
              let preferred = Fixture.codexKeychain[Fixture.codexKey(alias)] else {
            throw Failure(description: "Fixture did not discover the original managed account")
        }
        // Preserve a discovered account while its managed path is migrated to a
        // child symlink. The native login moves to that alias's new namespace.
        Fixture.codexKeychain[Fixture.codexKey(alias)] = nil
        try Foundation.FileManager.default.removeItem(at: alias)
        try Fixture.codexMode(physical, "auto")
        try Fixture.writeAuth(physical, account: "file-peer", refresh: "peer-refresh", expired: false)
        try Foundation.FileManager.default.createSymbolicLink(
            at: alias, withDestinationURL: URL(fileURLWithPath: "/System/Volumes/Data" + physical.path))
        Fixture.codexKeychain[Fixture.codexKey(alias)] = preferred
        let peer = try Data(contentsOf: physical.appendingPathComponent("auth.json"))
        let settings = physical.appendingPathComponent("settings-sentinel")
        let settingsData = Data("physical-profile-settings".utf8)
        try settingsData.write(to: settings)
        var refused = false
        do {
            if direct { try AuthSwap$Codex.removeAuth(home: alias, columnID: account.id) }
            else { try AccountRemoval.remove(account) }
        } catch { refused = true }
        try expect(refused == direct,
                   "Removal confused unlinking a managed alias with credential-only deletion")
        try expect((try? Data(contentsOf: physical.appendingPathComponent("auth.json"))) == peer
                   && (try? Data(contentsOf: settings)) == settingsData,
                   "Removing an auto alias changed its independent physical file owner")
        if direct {
            try expect(Foundation.FileManager.default.fileExists(atPath: alias.path)
                       && Fixture.codexKeychain[Fixture.codexKey(alias)] == preferred,
                       "Credential-only removal resurrected a still-linked alias through its shared fallback")
        } else {
            let nativeAlias = URL(fileURLWithPath: "/System/Volumes/Data" + physical.path)
            try expect(!Foundation.FileManager.default.fileExists(atPath: alias.path)
                       && Fixture.codexKeychain[Fixture.codexKey(nativeAlias)] == nil,
                       "Safe managed-alias removal left its link or preferred credentials behind")
        }
    }

}
