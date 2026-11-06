import Foundation
import Security
import CryptoKit
import Darwin
import TOMLDecoder

/// The native Codex auth payload, stored under the selected CODEX_HOME.
struct AuthStorage$Codex {
    private static let recoveryConfiguration = "cli_auth_credentials_store = \"keyring\"\n"
    enum Mode: String { case file, keyring, auto, ephemeral }
    enum Backend { case file, keyring }
    struct Record { let data: Data; let backend: Backend }
    struct RemovalKeyring {
        let original: AuthStorage$Codex
        let originalFile: Data?
        let storage: AuthStorage$Codex
        let owner: DirectoryIdentity
        let record: Record?
        let verifiesRecord: Bool

        func validate(removed: Bool = false) throws {
            guard try storage.loadFile() == nil else { throw Failure.settings }
            if removed {
                guard storage.keyringStatus() == errSecItemNotFound else { throw Failure.settings }
            } else if verifiesRecord {
                guard AuthStorage$Codex.sameCredentials(try storage.loadKeyring()?.data, record?.data) else {
                    throw Failure.settings
                }
            }
            guard owner.matches(storage.home) else { throw Failure.settings }
        }

        func finish() {
            let config = storage.home.appendingPathComponent("config.toml")
            do {
                guard (try? String(contentsOf: config, encoding: .utf8)) == AuthStorage$Codex.recoveryConfiguration,
                      try storage.loadFile() == nil,
                      storage.keyringStatus() == errSecItemNotFound,
                      owner.matches(storage.home) else { return }
                // Remove only our configuration and an empty directory. A new
                // file login must survive even if it appears during cleanup.
                guard unlink(config.path) == 0 else { return }
                _ = rmdir(storage.home.path)
            } catch { return }
        }

        /// Moving an item back must not overwrite a login created during removal.
        /// A refused restoration remains a normal, discoverable Keychain profile.
        mutating func restore(retainsOriginalFile: Bool) -> Bool {
            // No item was reserved for an auto file fallback. A later Keychain
            // login in recovery is independent and must never be moved back.
            if verifiesRecord && record == nil {
                do { try validate() } catch { return false }
                finish()
                return true
            }
            do { self = try preservingSnapshot() } catch { return false }
            guard owner.matches(storage.home) else { return false }
            // Keep the snapshot discoverable before any rollback refusal. The
            // native add is exclusive and preserves a later reserved login too.
            if storage.keyringStatus() != errSecSuccess, let record {
                var item = storage.query
                item[kSecValueData as String] = record.data
                let status = AuthStorage$Claude.access(interactive: false) { SecItemAdd(item as CFDictionary, nil) }
                guard status == errSecSuccess || status == errSecDuplicateItem else { return false }
            }
            var info = stat()
            if lstat(original.file.path, &info) == 0 {
                guard retainsOriginalFile, let current = try? Data(contentsOf: original.file),
                      current == originalFile else { return false }
            } else if errno != ENOENT { return false }
            // File admission can block while the reserved namespace receives
            // another login. Keep that login and restore our own snapshot.
            do { self = try preservingSnapshot() } catch { return false }
            let status = AuthStorage$Claude.access(interactive: false) {
                guard owner.matches(storage.home) else { return errSecInteractionNotAllowed }
                return SecItemUpdate(storage.query as CFDictionary,
                                     [kSecAttrAccount as String: original.account] as CFDictionary)
            }
            guard status == errSecSuccess || status == errSecItemNotFound else { return false }
            finish()
            return true
        }

        /// A replacement owns its recovery namespace. Keep the captured login
        /// separately before a rollback can refuse or move any Keychain item.
        private func preservingSnapshot() throws -> Self {
            guard verifiesRecord, let record else { return self }
            do {
                if try storage.loadFile() == nil {
                    if let current = try storage.loadKeyring(),
                       AuthStorage$Codex.sameCredentials(current.data, record.data),
                       owner.matches(storage.home) { return self }
                    if storage.keyringStatus() == errSecItemNotFound, owner.matches(storage.home) { return self }
                }
            } catch { /* An unavailable owner does not authorize moving its item. */ }
            // A public recovery can be claimed by CLI during preparation.
            // Retry a fresh namespace without changing that login's config.
            for _ in 0..<3 {
                let home = ProfileDirectories.codexRoot
                    .appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                let destination = try AuthStorage$Codex(home: home, mode: .keyring)
                guard let destinationOwner = DirectoryIdentity.capture(destination.home) else { throw Failure.settings }
                guard try FileManager.default.contentsOfDirectory(atPath: destination.home.path).isEmpty,
                      destinationOwner.matches(destination.home) else { continue }
                do {
                    try Data(AuthStorage$Codex.recoveryConfiguration.utf8)
                        .write(to: destination.home.appendingPathComponent("config.toml"), options: .withoutOverwriting)
                } catch let error as CocoaError where error.code == .fileWriteFileExists { continue }
                var item = destination.query
                item[kSecValueData as String] = record.data
                let status = AuthStorage$Claude.access(interactive: false) {
                    guard destinationOwner.matches(destination.home),
                          AuthStorage$Codex.canonicalPath(home) == destination.home.path else { return errSecInteractionNotAllowed }
                    return SecItemAdd(item as CFDictionary, nil)
                }
                if status == errSecDuplicateItem { continue }
                guard status == errSecSuccess else { throw Failure.keychain(status) }
                return Self(original: original, originalFile: originalFile, storage: destination,
                            owner: destinationOwner, record: record, verifiesRecord: true)
            }
            throw Failure.settings
        }
    }

    /// Admission follows the physical profile through staging, not its freed name.
    struct Removal {
        let original: AuthStorage$Codex
        let owner: DirectoryIdentity
        let file: Data?
        let keyring: RemovalKeyring?

        private enum Phase { case staged, fileRemoved, removed }

        func delete(fileHome: URL?) throws {
            let location = fileHome ?? original.home
            func validate(_ phase: Phase) throws {
                if let keyring {
                    try keyring.validate(removed: phase == .removed)
                    if original.keyringStatus() != errSecItemNotFound {
                        // A re-addition owns a new directory. A login completed
                        // in the staged owner still needs its original name back.
                        guard let replacement = DirectoryIdentity.capture(original.home),
                              !replacement.isSameDirectory(as: owner) else { throw Failure.settings }
                    }
                }
                let shared = original.mode != .file
                    && AuthSwap$Codex.fileIsShared(home: original.home, fileHome: location)
                let current = try AuthStorage$Codex(home: location)
                let data = shared ? nil : try current.loadFile()?.data
                guard current.mode == original.mode,
                      shared || AuthStorage$Codex.sameCredentials(data, phase == .staged ? file : nil),
                      DirectoryIdentity.capture(location)?.isSameDirectory(as: owner) == true,
                      AuthStorage$Codex.canonicalPath(location) == current.home.path else { throw Failure.settings }
            }
            var removedFile = false
            do {
                try original.validatingMutation(nil).delete(fileHome: location, keyring: keyring?.storage,
                    validating: { try validate(.staged) }, afterFileRemoval: {
                        removedFile = true
                        try validate(.fileRemoved)
                    })
                // An unreadable secret cannot be reconstructed. All admission
                // checks precede its deletion; successful deletion commits it.
                if keyring?.verifiesRecord != false { try validate(.removed) }
            } catch {
                if removedFile, let file, DirectoryIdentity.capture(location)?.isSameDirectory(as: owner) == true {
                    try original.restoreFile(file, at: location.appendingPathComponent("auth.json"))
                }
                throw error
            }
        }
    }
    enum Failure: LocalizedError {
        case settings, ephemeral, keychain(OSStatus)
        var errorDescription: String? {
            switch self {
            case .settings: return L.t("error.codexStorage")
            case .ephemeral: return L.t("error.codexEphemeral")
            case .keychain(let status): return SecCopyErrorMessageString(status, nil) as String?
            }
        }
    }

    let home: URL
    let mode: Mode
    private var mutationValidation: (() throws -> Void)?
    private var file: URL { home.appendingPathComponent("auth.json") }
    private let account: String
    private var query: [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "Codex Auth",
                kSecAttrAccount as String: account]
    }

    /// Carry a removal's proof through its callback to the first mutation.
    func validatingMutation(_ validation: (() throws -> Void)?) -> Self {
        var copy = self
        copy.mutationValidation = validation
        return copy
    }

    init(home: URL, mode: Mode? = nil) throws {
        let path = Self.canonicalPath(home)
        // Pin file operations to the same physical owner as the native Keychain
        // key. A later symlink retarget must not redirect a pending rotation.
        self.home = URL(fileURLWithPath: path, isDirectory: true)
        self.mode = try mode ?? Self.configuredMode(home: self.home)
        // Configuration reads can block. Do not return a snapshot of a former
        // namespace after the caller's logical home has been redirected.
        guard Self.canonicalPath(home) == path else { throw Failure.settings }
        let hash = SHA256.hash(data: Data(path.utf8))
            .map { String(format: "%02x", $0) }.joined()
        account = "cli|" + hash.prefix(16)
    }

    /// Match Rust Path::canonicalize, including its fallback for missing homes.
    /// Foundation also rewrites /private/tmp to /tmp, producing a different key.
    static func canonicalPath(_ home: URL) -> String {
        guard let path = home.path.withCString({ realpath($0, nil) }) else { return home.path }
        defer { free(path) }
        return String(cString: path)
    }

    func load(backend: Backend? = nil, verifyingOwner: Bool = false) throws -> Record? {
        if let backend {
            return try backend == .keyring ? loadKeyring() : loadFile()
        }
        switch mode {
        case .ephemeral: return nil // Another process's memory is not an auth cache.
        case .file: return try loadFile()
        case .keyring: return try loadKeyring()
        case .auto:
            // Native reads may fall back on errors. A switch must distinguish
            // an unavailable owner from a confirmed missing or different login.
            if verifyingOwner { return try loadKeyring() ?? loadFile() }
            if let record = try? loadKeyring() { return record }
            return try loadFile()
        }
    }

    func contains() -> Bool {
        switch mode {
        case .ephemeral: return false
        case .file: return FileManager.default.fileExists(atPath: file.path)
        case .keyring: return keyringStatus() == errSecSuccess
        case .auto:
            return keyringStatus() == errSecSuccess || FileManager.default.fileExists(atPath: file.path)
        }
    }

    /// Renewal persists back to the backend that supplied its current grant.
    /// A denied Keychain update must not hide rotated tokens behind a stale entry.
    func save(_ data: Data, backend: Backend? = nil, validating: (() throws -> Void)? = nil) throws {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        let validate = {
            try mutationValidation?()
            try validating?()
        }
        if backend == .file || backend == nil && mode == .file {
            try saveFile(data, validating: validate)
            return
        }
        // Cleanup may remove only the fallback observed before publication.
        let fallbackOwner = DirectoryIdentity.capture(home)
        let fallback = try? loadFile()
        do {
            try validate()
            var status = AuthStorage$Claude.access(interactive: false) {
                SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            }
            if status == errSecItemNotFound {
                var item = query
                item[kSecValueData as String] = data
                try validate()
                status = AuthStorage$Claude.access(interactive: false) { SecItemAdd(item as CFDictionary, nil) }
            }
            guard status == errSecSuccess else { throw Failure.keychain(status) }
            if let fallback, let fallbackOwner,
               !AuthSwap$Codex.fileIsShared(home: home, fileHome: home) {
                try? removeFile(validating: {
                    let inventory = try Self.profileRevision()
                    guard !AuthSwap$Codex.fileIsShared(home: home, fileHome: home) else { throw Failure.settings }
                    let published = try loadKeyring()
                    let current = try Self.configuredMode(home: home)
                    let file = try loadFile()
                    guard current == .keyring || current == .auto,
                          Self.sameCredentials(published?.data, data),
                          Self.sameCredentials(file?.data, fallback.data),
                          fallbackOwner.matches(home),
                          try inventory == Self.profileRevision() else { throw Failure.settings }
                })
            }
        } catch {
            guard backend == nil, mode == .auto, keyringStatus() == errSecItemNotFound else { throw error }
            try saveFile(data, validating: validate)
        }
    }

    /// A switch can promote an auto file fallback into Keychain. Restore the
    /// owner through the preferred backend instead of leaving that item above
    /// a restored file. Never export an original Keychain record to a fallback.
    func restore(_ record: Record?, validating: (() throws -> Void)? = nil) throws {
        guard let record else { try delete(validating: validating); return }
        let backend: Backend? = mode == .auto && record.backend == .file ? nil : record.backend
        try save(record.data, backend: backend, validating: validating)
    }

    /// Reserve the old Keychain item before its profile name becomes available.
    /// Later deletion addresses only this unique namespace, never a re-added login.
    func beginRemoval() throws -> Removal {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        guard let profileOwner = DirectoryIdentity.capture(home) else { throw Failure.settings }
        let originalFile = try loadFile()?.data
        if mode == .file {
            try mutationValidation?()
            return Removal(original: self, owner: profileOwner, file: originalFile, keyring: nil)
        }
        var record: Record?
        var verifiesRecord = false
        do { record = try loadKeyring(); verifiesRecord = true }
        catch { /* Explicit namespace removal does not require secret-read access. */ }
        let recovery = ProfileDirectories.codexRoot
            .appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let storage = try AuthStorage$Codex(home: recovery, mode: .keyring)
        guard let owner = DirectoryIdentity.capture(storage.home) else { throw Failure.settings }
        let keyring = RemovalKeyring(original: self, originalFile: originalFile, storage: storage, owner: owner,
                                     record: record, verifiesRecord: verifiesRecord)
        do {
            // A CLI login may claim the public directory during preparation.
            // Never replace its configuration, even when reservation refuses.
            guard try FileManager.default.contentsOfDirectory(atPath: storage.home.path).isEmpty,
                  owner.matches(storage.home), Self.canonicalPath(recovery) == storage.home.path else {
                throw Failure.settings
            }
            let config = storage.home.appendingPathComponent("config.toml")
            try Data(Self.recoveryConfiguration.utf8).write(to: config, options: .withoutOverwriting)
            // Recovery preparation can block while CLI replaces the login.
            // Reserve only the credentials authorized by the removal caller.
            try mutationValidation?()
            let status = AuthStorage$Claude.access(interactive: false) {
                // The interaction gate can block after preparation. Native
                // rename is exclusive for Keychain; also preserve file logins.
                guard (try? String(contentsOf: config, encoding: .utf8)) == Self.recoveryConfiguration,
                      (try? storage.loadFile() == nil) == true,
                      owner.matches(storage.home), Self.canonicalPath(recovery) == storage.home.path else {
                    return errSecInteractionNotAllowed
                }
                return SecItemUpdate(query as CFDictionary,
                                     [kSecAttrAccount as String: storage.account] as CFDictionary)
            }
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
            // An auto file owner has no item to move. A missing source must
            // not authorize adopting a new login in the reserved namespace.
            if status == errSecItemNotFound {
                guard storage.keyringStatus() == errSecItemNotFound else { throw Failure.settings }
            }
            return Removal(original: self, owner: profileOwner, file: originalFile, keyring: keyring)
        } catch {
            keyring.finish()
            throw error
        }
    }

    func delete(fileHome: URL? = nil, keyring: AuthStorage$Codex? = nil,
                validating: (() throws -> Void)? = nil,
                afterFileRemoval: (() throws -> Void)? = nil) throws {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        let validate = {
            try mutationValidation?()
            try validating?()
        }
        let file = (fileHome ?? home).appendingPathComponent("auth.json")
        if mode == .file {
            try removeFile(at: file, validating: validate)
            try afterFileRemoval?()
            return
        }
        let destination = keyring ?? self
        var record: Record?
        var verifiesRecord = false
        do { record = try destination.loadKeyring(); verifiesRecord = true }
        catch { /* Preserve explicit removal of an unreadable namespace. */ }
        let shared = AuthSwap$Codex.fileIsShared(home: home, fileHome: file.deletingLastPathComponent())
        let backup = !shared && FileManager.default.fileExists(atPath: file.path) ? try Data(contentsOf: file) : nil
        if !shared {
            try removeFile(at: file, validating: {
                guard !AuthSwap$Codex.fileIsShared(home: home, fileHome: file.deletingLastPathComponent()) else {
                    throw Failure.settings
                }
                try validate()
            })
        }
        do {
            if backup == nil { try validate() }
            else {
                try afterFileRemoval?()
                // The file unlink can block while another client logs in.
                if verifiesRecord,
                   !Self.sameCredentials(try destination.loadKeyring()?.data, record?.data) { throw Failure.settings }
            }
            let status = AuthStorage$Claude.access(interactive: false) {
                SecItemDelete((keyring?.query ?? query) as CFDictionary)
            }
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
        } catch {
            if let backup { try restoreFile(backup, at: file) }
            throw error
        }
    }

    /// Detect aliases added or retargeted during the final credential reads.
    private static func profileRevision() throws -> [Int64] {
        let root = canonicalPath(ProfileDirectories.codexRoot)
        var info = stat()
        guard lstat(root, &info) == 0 else {
            guard errno == ENOENT else { throw Failure.settings }
            return []
        }
        return [Int64(info.st_dev), Int64(info.st_ino), Int64(info.st_mtimespec.tv_sec),
                Int64(info.st_mtimespec.tv_nsec), Int64(info.st_ctimespec.tv_sec), Int64(info.st_ctimespec.tv_nsec)]
    }

    private static func sameCredentials(_ first: Data?, _ second: Data?) -> Bool {
        if let first, let second, let identity = AuthSwap$Codex.authIdentity(first) {
            return identity == AuthSwap$Codex.authIdentity(second)
        }
        return first == second
    }

    private func restoreFile(_ data: Data, at file: URL) throws {
        var template = Array(file.deletingLastPathComponent()
            .appendingPathComponent(".auth-restore-XXXXXX").path.utf8CString)
        let descriptor = mkstemp(&template)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let prepared = String(cString: template)
        defer { _ = unlink(prepared) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.close()
        // Publish only a complete private backup. A CLI login that appeared
        // during Keychain deletion owns the path and must remain untouched.
        if renameatx_np(AT_FDCWD, prepared, AT_FDCWD, file.path, UInt32(RENAME_EXCL)) == 0 { return }
        guard errno == EEXIST else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private func loadFile() throws -> Record? {
        if !FileManager.default.fileExists(atPath: file.path) {
            let descriptor = open(file.path, O_RDONLY | O_CLOEXEC)
            guard descriptor >= 0 else {
                let code = errno
                guard code == ENOENT else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
                return nil
            }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            return Record(data: try handle.readToEnd() ?? Data(), backend: .file)
        }
        return Record(data: try Data(contentsOf: file), backend: .file)
    }

    private func loadKeyring() throws -> Record? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = AuthStorage$Claude.access(interactive: false) { SecItemCopyMatching(request as CFDictionary, &result) }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
        guard let data = result as? Data,
              (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { throw Failure.settings }
        return Record(data: data, backend: .keyring)
    }

    private func keyringStatus() -> OSStatus {
        var request = query
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        return AuthStorage$Claude.access(interactive: false) { SecItemCopyMatching(request as CFDictionary, nil) }
    }

    private func saveFile(_ data: Data, validating: (() throws -> Void)? = nil) throws {
        let prepared = home.appendingPathComponent(".auth-" + UUID().uuidString + ".json")
        guard FileManager.default.createFile(atPath: prepared.path, contents: nil,
                                              attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? FileManager.default.removeItem(at: prepared) }
        // Finish every fallible preparation before publishing credentials. A
        // chmod failure must not change the login while its owner marker stays old.
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: prepared.path)
        try data.write(to: prepared)
        try validating?()
        guard rename(prepared.path, file.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private func removeFile(at destination: URL? = nil, validating: (() throws -> Void)? = nil) throws {
        let file = destination ?? self.file
        if FileManager.default.fileExists(atPath: file.path) {
            try validating?()
            try FileManager.default.removeItem(at: file)
        }
    }

    private static func configuredMode(home: URL) throws -> Mode {
        var values: [String: String] = [:]
        for path in ["/etc/codex/config.toml", home.appendingPathComponent("config.toml").path,
                     "/etc/codex/managed_config.toml"] {
            try mergeFile(path, into: &values)
        }
        if let text = try managed("config_toml_base64") { values.merge(try settings(text)) { _, new in new } }
        try mergeFile("/etc/codex/requirements.toml", into: &values)
        if let text = try managed("requirements_toml_base64") { values.merge(try settings(text)) { _, new in new } }
        // The opt-in encrypted secrets backend has a different on-disk format.
        // Never mistake its absence in the direct Keychain backend for a file login.
        guard let mode = Mode(rawValue: values["cli_auth_credentials_store"] ?? "file"),
              mode == .file || mode == .ephemeral || values["features.secret_auth_storage"] != "true" else { throw Failure.settings }
        return mode
    }

    private static func mergeFile(_ path: String, into values: inout [String: String]) throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8) else {
            throw Failure.settings
        }
        values.merge(try settings(text)) { _, new in new }
    }

    private static func managed(_ name: String) throws -> String? {
        let key = name as CFString, domain = "com.openai.codex" as CFString
        guard CFPreferencesAppValueIsForced(key, domain) else { return nil }
        let value = CFPreferencesCopyAppValue(key, domain)
        guard CFPreferencesAppValueIsForced(key, domain), let encoded = value as? String,
              let data = Data(base64Encoded: encoded), let text = String(data: data, encoding: .utf8) else {
            throw Failure.settings
        }
        return text
    }

    /// Decode native TOML syntax, including quoted/dotted keys and inline tables.
    /// Only root auth settings participate; model profiles cannot override them.
    private static func settings(_ text: String) throws -> [String: String] {
        struct Settings: Decodable {
            struct Features: Decodable { let secret_auth_storage: Bool? }
            let cli_auth_credentials_store: String?
            let features: Features?
        }
        do {
            let settings = try TOMLDecoder(isLenient: false).decode(Settings.self, from: text)
            var values: [String: String] = [:]
            values["cli_auth_credentials_store"] = settings.cli_auth_credentials_store
            values["features.secret_auth_storage"] = settings.features?.secret_auth_storage.map(String.init)
            return values
        } catch {
            throw Failure.settings
        }
    }
}
