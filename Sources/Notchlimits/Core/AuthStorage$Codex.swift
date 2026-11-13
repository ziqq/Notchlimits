import Foundation
import Security
import CryptoKit
import Darwin
import TOMLDecoder

/// The native Codex auth payload, stored under the selected CODEX_HOME.
struct AuthStorage$Codex {
    private static let recoveryConfiguration = "cli_auth_credentials_store = \"keyring\"\n"
    enum Mode: String {
        case file, keyring, auto, ephemeral
        var usesKeyring: Bool { self == .keyring || self == .auto }
    }
    enum Backend { case file, keyring }
    struct Record { let data: Data; let backend: Backend }

    /// Classic Keychain item dates have only second precision. The owning
    /// database changes even when a native write leaves item metadata equal.
    fileprivate struct KeyringDatabaseRevision: Equatable {
        let path: String
        private let generation: [Int64]
        private let handle: FileHandle

        init(path: String) throws {
            let descriptor = open(path, O_EVTONLY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw Failure.settings }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            var info = stat()
            guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { throw Failure.settings }
            self.path = path
            self.generation = Self.generation(info)
            self.handle = handle
            guard isCurrent else { throw Failure.settings }
        }

        fileprivate static func generation(_ info: stat) -> [Int64] {
            [Int64(info.st_dev), Int64(bitPattern: UInt64(info.st_ino)), Int64(info.st_size),
             Int64(info.st_mtimespec.tv_sec), Int64(info.st_mtimespec.tv_nsec),
             Int64(info.st_ctimespec.tv_sec), Int64(info.st_ctimespec.tv_nsec)]
        }

        var isCurrent: Bool {
            // Retaining the descriptor prevents reuse of the captured inode.
            withExtendedLifetime(handle) {
                var info = stat()
                return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFREG
                    && Self.generation(info) == generation
            }
        }

        static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.path == rhs.path && lhs.generation == rhs.generation
        }
    }

    /// File and configuration reads can block too. Keep a metadata proof of
    /// the paths those reads admitted and recheck it at the mutation boundary.
    private struct CredentialFilesRevision {
        private let entries: [(path: String, tracksContents: Bool, revision: [Int64])]

        init(_ homes: [URL], tracksDirectoryContents: Bool = true) throws {
            let paths = homes.flatMap { home in
                [(home.path, tracksDirectoryContents), (home.appendingPathComponent("config.toml").path, true),
                 (home.appendingPathComponent("auth.json").path, true)]
            }
            entries = try paths.map { path, tracksContents in
                (path, tracksContents, try Self.revision(path, tracksContents: tracksContents))
            }
        }

        private static func revision(_ path: String, tracksContents: Bool) throws -> [Int64] {
            func generation(_ info: stat) -> [Int64] {
                if tracksContents { return KeyringDatabaseRevision.generation(info) }
                return [Int64(info.st_dev), Int64(bitPattern: UInt64(info.st_ino)), Int64(info.st_mode & S_IFMT)]
            }
            var info = stat()
            guard lstat(path, &info) == 0 else {
                guard errno == ENOENT else { throw Failure.settings }
                return []
            }
            let entry = generation(info)
            guard info.st_mode & S_IFMT == S_IFLNK else { return entry }
            guard stat(path, &info) == 0 else {
                guard errno == ENOENT else { throw Failure.settings }
                return entry
            }
            return entry + generation(info)
        }

        func validate() throws {
            for entry in entries {
                guard try Self.revision(entry.path, tracksContents: entry.tracksContents) == entry.revision else {
                    throw Failure.settings
                }
            }
        }
    }

    private struct KeyringSearchRevision {
        let keychains: [SecKeychain]
        private let paths: [String]
        private let databases: [KeyringDatabaseRevision]

        init() throws {
            keychains = try AuthStorage$Codex.classicKeyringSearchList()
            paths = try keychains.map(AuthStorage$Codex.keyringPath)
            databases = try paths.map(KeyringDatabaseRevision.init(path:))
        }

        private func matchesSearchList() throws -> Bool {
            try AuthStorage$Codex.classicKeyringSearchList().map(AuthStorage$Codex.keyringPath) == paths
        }

        func isCurrent(checkingFiles: () -> Bool) -> Bool {
            // Security can block while the fallback file is replaced. Check
            // file metadata after that call and the databases after both.
            (try? matchesSearchList()) == true && checkingFiles() && databases.allSatisfy(\.isCurrent)
        }

        func validate(files: CredentialFilesRevision) throws {
            guard try matchesSearchList() else {
                throw Failure.settings
            }
            try files.validate()
            guard databases.allSatisfy(\.isCurrent) else { throw Failure.settings }
        }
    }

    static func captureClassicKeychainRevision() -> ((() -> Bool) -> Bool)? {
        guard let revision = try? KeyringSearchRevision() else { return nil }
        return { checkingFiles in revision.isCurrent(checkingFiles: checkingFiles) }
    }

    /// A later credential or configuration read can invalidate an earlier one.
    /// Verify both stores after all reads and immediately before publication.
    static func validateMutation(homes: [URL], includesKeyring: Bool, tracksDirectoryContents: Bool = true,
                                 checking: () throws -> Void) throws {
        let keyring = includesKeyring ? try KeyringSearchRevision() : nil
        let files = try CredentialFilesRevision(homes, tracksDirectoryContents: tracksDirectoryContents)
        try checking()
        if let keyring { try keyring.validate(files: files) }
        else { try files.validate() }
    }

    fileprivate struct KeyringRevision: Equatable {
        let reference: Data
        let modified: Date
        let database: KeyringDatabaseRevision
    }

    fileprivate enum KeyringProof {
        case readable(Record?)
        case opaque(KeyringRevision)

        var isOpaque: Bool {
            if case .opaque = self { return true }
            return false
        }

        func validate(_ storage: AuthStorage$Codex) throws {
            switch self {
            case .readable(let record):
                guard AuthStorage$Codex.sameCredentials(try storage.loadKeyring()?.data, record?.data) else {
                    throw Failure.settings
                }
            case .opaque(let revision):
                guard revision.database.isCurrent, try storage.keyringRevision() == revision,
                      revision.database.isCurrent else { throw Failure.settings }
            }
        }

        func validateDatabase() throws {
            if case .opaque(let revision) = self, !revision.database.isCurrent { throw Failure.settings }
        }

        func afterMove(to storage: AuthStorage$Codex) throws -> Self {
            guard case .opaque(let originalRevision) = self else { return self }
            // Capture the generation committed by the move before resolving
            // the new reference. A later write cannot rebase this proof.
            let database = try KeyringDatabaseRevision(path: originalRevision.database.path)
            guard let revision = try storage.keyringRevision(), revision.database == database,
                  database.isCurrent else { throw Failure.settings }
            return .opaque(revision)
        }
    }

    struct RemovalKeyring {
        let original: AuthStorage$Codex
        let originalFile: Data?
        let storage: AuthStorage$Codex
        let owner: DirectoryIdentity
        fileprivate var proof: KeyringProof

        func validate(removed: Bool = false) throws {
            if removed {
                guard storage.keyringStatus() == errSecItemNotFound else { throw Failure.settings }
            } else {
                try proof.validate(storage)
            }
            try validateFiles()
            if !removed { try proof.validateDatabase() }
        }

        func validateFiles() throws {
            guard try storage.loadFile() == nil,
                  try AuthStorage$Codex.configuredMode(home: storage.home).usesKeyring,
                  owner.matches(storage.home) else { throw Failure.settings }
        }

        func finish() {
            let config = storage.home.appendingPathComponent("config.toml")
            func ownsEmptyRecovery() throws -> Bool {
                guard (try? String(contentsOf: config, encoding: .utf8)) == AuthStorage$Codex.recoveryConfiguration,
                      try storage.loadFile() == nil else { return false }
                return owner.matches(storage.home)
            }
            do {
                try AuthStorage$Codex.withKeychainAccess {
                    guard try ownsEmptyRecovery(), storage.keyringStatus() == errSecItemNotFound else { return }
                    let files = try CredentialFilesRevision([storage.home])
                    guard try ownsEmptyRecovery() else { return }
                    let keyring = try KeyringSearchRevision()
                    guard storage.keyringStatus(in: keyring.keychains) == errSecItemNotFound else { return }
                    try keyring.validate(files: files)
                    // Remove only our configuration and an empty directory.
                    guard unlink(config.path) == 0 else { return }
                    _ = rmdir(storage.home.path)
                }
            } catch { return }
        }

        /// Restore into the original namespace only while it still uses the
        /// captured storage mode. Otherwise keep a discoverable recovery.
        mutating func restore(retainsOriginalFile: Bool) -> Bool {
            // No item was reserved for an auto file fallback. A later Keychain
            // login in recovery is independent and must never be moved back.
            if case .readable(nil) = proof {
                do { try validate() } catch { return false }
                finish()
                return true
            }
            do { self = try preservingSnapshot() } catch { return false }
            func validateOriginalFile(_ original: AuthStorage$Codex, _ originalFile: Data?) throws {
                var info = stat()
                if lstat(original.file.path, &info) == 0 {
                    guard retainsOriginalFile, try Data(contentsOf: original.file) == originalFile else {
                        throw Failure.settings
                    }
                } else if errno != ENOENT { throw Failure.settings }
            }
            let status: OSStatus
            do {
                try validateOriginalFile(original, originalFile)
                self = try preservingSnapshot()
                status = try AuthStorage$Codex.withKeychainAccess {
                    // Keep our original snapshot if another login claimed recovery
                    // while waiting for the Keychain gate.
                    self = try preservingSnapshot()
                    try AuthStorage$Codex.validateMutation(homes: [original.home, storage.home], includesKeyring: true) {
                        try validate()
                        try validateOriginalFile(original, originalFile)
                        guard try AuthStorage$Codex.configuredMode(home: original.home) == original.mode,
                              AuthStorage$Codex.canonicalPath(original.home) == original.home.path else { throw Failure.settings }
                    }
                    return SecItemUpdate(storage.query as CFDictionary,
                                         [kSecAttrAccount as String: original.account] as CFDictionary)
                }
            } catch {
                // A readable snapshot remains recoverable after a refused move.
                if let retained = try? preservingSnapshot() { self = retained }
                return false
            }
            guard status == errSecSuccess || status == errSecItemNotFound else { return false }
            finish()
            return true
        }

        /// A replacement owns its recovery namespace. Keep the captured login
        /// separately before a rollback can refuse or move any Keychain item.
        private func preservingSnapshot() throws -> Self {
            if case .readable(nil) = proof { try validate(); return self }
            do {
                let files = try CredentialFilesRevision([storage.home])
                try validate()
                try files.validate()
                return self
            } catch {
                if proof.isOpaque {
                    // A file login or storage-mode change can hide the item.
                    // Salvage only the verified original Keychain item.
                    try proof.validate(storage)
                    guard owner.matches(storage.home) else { throw Failure.settings }
                }
            }
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
                var destinationProof = proof
                let status = try AuthStorage$Codex.withKeychainAccess {
                    do {
                        try AuthStorage$Codex.validateMutation(homes: [home, storage.home], includesKeyring: true) {
                            if proof.isOpaque {
                                try proof.validate(storage)
                                guard owner.matches(storage.home) else { throw Failure.settings }
                            }
                            guard try destination.loadFile() == nil,
                                  try AuthStorage$Codex.configuredMode(home: destination.home).usesKeyring,
                                  (try? String(contentsOf: destination.home.appendingPathComponent("config.toml"), encoding: .utf8))
                                    == AuthStorage$Codex.recoveryConfiguration,
                                  destinationOwner.matches(destination.home),
                                  AuthStorage$Codex.canonicalPath(home) == destination.home.path,
                                  destination.keyringStatus() == errSecItemNotFound else { throw Failure.settings }
                        }
                    } catch Failure.settings { return errSecDuplicateItem }
                    switch proof {
                    case .readable(let record?):
                        var item = destination.query
                        item[kSecValueData as String] = record.data
                        return SecItemAdd(item as CFDictionary, nil)
                    case .opaque:
                        let status = SecItemUpdate(storage.query as CFDictionary,
                                                   [kSecAttrAccount as String: destination.account] as CFDictionary)
                        if status == errSecSuccess { destinationProof = try proof.afterMove(to: destination) }
                        return status
                    case .readable(nil): throw Failure.settings
                    }
                }
                if status == errSecDuplicateItem { continue }
                guard status == errSecSuccess else { throw Failure.keychain(status) }
                return Self(original: original, originalFile: originalFile, storage: destination,
                            owner: destinationOwner, proof: destinationProof)
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
            var filesAtAdmission: CredentialFilesRevision?
            var inventoryAtAdmission: [Int64]?
            func validateFiles(_ phase: Phase, shared: Bool) throws {
                try keyring?.validateFiles()
                let current = try AuthStorage$Codex(home: location)
                let data = shared ? nil : try current.loadFile()?.data
                guard current.mode == original.mode,
                      shared || AuthStorage$Codex.sameCredentials(data, phase == .staged ? file : nil),
                      DirectoryIdentity.capture(location)?.isSameDirectory(as: owner) == true,
                      AuthStorage$Codex.canonicalPath(location) == current.home.path else { throw Failure.settings }
            }
            func validate(_ phase: Phase) throws {
                let inventory = try AuthStorage$Codex.profileRevision()
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
                let files = try CredentialFilesRevision([location] + (keyring.map { [$0.storage.home] } ?? []))
                try validateFiles(phase, shared: shared)
                try files.validate()
                guard try AuthStorage$Codex.profileRevision() == inventory else { throw Failure.settings }
                if phase != .removed { try keyring?.proof.validateDatabase() }
                filesAtAdmission = files
                inventoryAtAdmission = inventory
            }
            var removedFile = false
            do {
                try original.validatingMutation(nil).delete(fileHome: location, keyring: keyring?.storage,
                    validating: { try validate(.staged) }, afterFileRemoval: {
                        removedFile = true
                        try validate(.fileRemoved)
                    }, beforeKeyringMutation: {
                        // The final secret read can block while a file login
                        // or a shared alias claims one of these directories.
                        guard let filesAtAdmission else { throw Failure.settings }
                        try filesAtAdmission.validate()
                        guard try AuthStorage$Codex.profileRevision() == inventoryAtAdmission else { throw Failure.settings }
                        try keyring?.proof.validateDatabase()
                    })
                // An unreadable secret cannot be reconstructed. All admission
                // checks precede its deletion; successful deletion commits it.
                if keyring?.proof.isOpaque != true { try validate(.removed) }
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

    func containsKeyringItem() -> Bool {
        keyringStatus() == errSecSuccess
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
            let status = try Self.withKeychainAccess {
                try validate()
                let updated = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
                guard updated == errSecItemNotFound else { return updated }
                var item = query
                item[kSecValueData as String] = data
                try validate()
                return SecItemAdd(item as CFDictionary, nil)
            }
            guard status == errSecSuccess else { throw Failure.keychain(status) }
            if let fallback, let fallbackOwner,
               !AuthSwap$Codex.fileIsShared(home: home, fileHome: home) {
                try? removeFile(validating: {
                    let inventory = try Self.profileRevision()
                    try Self.validateMutation(homes: [home], includesKeyring: true) {
                        guard !AuthSwap$Codex.fileIsShared(home: home, fileHome: home) else { throw Failure.settings }
                        let published = try loadKeyring()
                        let current = try Self.configuredMode(home: home)
                        let file = try loadFile()
                        guard current.usesKeyring,
                              Self.sameCredentials(published?.data, data),
                              Self.sameCredentials(file?.data, fallback.data),
                              fallbackOwner.matches(home),
                              try inventory == Self.profileRevision() else { throw Failure.settings }
                    }
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
        let sourceProof = try captureKeyringProof()
        let recovery = ProfileDirectories.codexRoot
            .appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let storage = try AuthStorage$Codex(home: recovery, mode: .keyring)
        guard let owner = DirectoryIdentity.capture(storage.home) else { throw Failure.settings }
        var keyring = RemovalKeyring(original: self, originalFile: originalFile, storage: storage, owner: owner,
                                     proof: sourceProof)
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
            try Self.withKeychainAccess {
                // The interaction gate can block after preparation. Native
                // rename is exclusive for Keychain; also preserve file logins.
                try Self.validateMutation(homes: [home, recovery], includesKeyring: true) {
                    try mutationValidation?()
                    try sourceProof.validate(self)
                    guard (try? String(contentsOf: config, encoding: .utf8)) == Self.recoveryConfiguration,
                          try storage.loadFile() == nil, profileOwner.matches(home),
                          owner.matches(storage.home), Self.canonicalPath(recovery) == storage.home.path,
                          storage.keyringStatus() == errSecItemNotFound else { throw Failure.settings }
                }
                // An auto file login with no Keychain item has nothing to move.
                if case .readable(nil) = sourceProof { return }
                let status = SecItemUpdate(query as CFDictionary,
                                           [kSecAttrAccount as String: storage.account] as CFDictionary)
                guard status == errSecSuccess else { throw Failure.keychain(status) }
                keyring.proof = try sourceProof.afterMove(to: storage)
            }
            return Removal(original: self, owner: profileOwner, file: originalFile, keyring: keyring)
        } catch {
            keyring.finish()
            throw error
        }
    }

    func delete(fileHome: URL? = nil, keyring: AuthStorage$Codex? = nil,
                validating: (() throws -> Void)? = nil,
                afterFileRemoval: (() throws -> Void)? = nil,
                beforeKeyringMutation: (() throws -> Void)? = nil) throws {
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
        let proof = try destination.captureKeyringProof()
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
            let status = try Self.withKeychainAccess {
                if backup == nil { try validate() }
                else { try afterFileRemoval?() }
                try proof.validate(destination)
                try beforeKeyringMutation?()
                if !shared {
                    var info = stat()
                    guard lstat(file.path, &info) != 0, errno == ENOENT else { throw Failure.settings }
                }
                try proof.validateDatabase()
                return SecItemDelete(destination.query as CFDictionary)
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

    static func sameCredentials(_ first: Data?, _ second: Data?) -> Bool {
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

    private func keyringStatus(in keychains: [SecKeychain]? = nil) -> OSStatus {
        var request = query
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        if let keychains { request[kSecMatchSearchList as String] = keychains }
        return AuthStorage$Claude.access(interactive: false) { SecItemCopyMatching(request as CFDictionary, nil) }
    }

    private static func withKeychainAccess<T>(_ operation: () throws -> T) throws -> T {
        try AuthStorage$Claude.access(interactive: false, unavailable: {
            throw Failure.keychain(errSecInteractionNotAllowed)
        }, operation)
    }

    private func captureKeyringProof() throws -> KeyringProof {
        do { return .readable(try loadKeyring()) }
        catch {
            // Legacy ACLs can deny the payload while exposing item metadata.
            guard let revision = try keyringRevision() else { return .readable(nil) }
            return .opaque(revision)
        }
    }

    private func keyringRevision() throws -> KeyringRevision? {
        var request = query
        request[kSecReturnAttributes as String] = true
        request[kSecReturnPersistentRef as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        return try Self.withKeychainAccess {
            var result: CFTypeRef?
            let status = SecItemCopyMatching(request as CFDictionary, &result)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw Failure.keychain(status) }
            guard let attributes = result as? [String: Any],
                  let reference = attributes[kSecValuePersistentRef as String] as? Data,
                  let modified = attributes[kSecAttrModificationDate as String] as? Date else { throw Failure.settings }
            return KeyringRevision(reference: reference, modified: modified,
                                   database: try Self.keyringDatabaseRevision(reference: reference))
        }
    }

    private static func keyringDatabaseRevision(reference: Data) throws -> KeyringDatabaseRevision {
        var item: SecKeychainItem?
        var keychain: SecKeychain?
        // Resolve the item itself: a custom classic Keychain can own it.
        guard SecKeychainItemCopyFromPersistentReference(reference as CFData, &item) == errSecSuccess,
              let item, SecKeychainItemCopyKeychain(item, &keychain) == errSecSuccess,
              let keychain else { throw Failure.settings }
        return try KeyringDatabaseRevision(path: keyringPath(keychain))
    }

    private static func classicKeyringSearchList() throws -> [SecKeychain] {
        var result: CFArray?
        guard SecKeychainCopySearchList(&result) == errSecSuccess,
              let keychains = result as? [SecKeychain] else { throw Failure.settings }
        return keychains
    }

    private static func keyringPath(_ keychain: SecKeychain) throws -> String {
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        var length = UInt32(path.count)
        guard SecKeychainGetPath(keychain, &length, &path) == errSecSuccess,
              length > 0, length < path.count else { throw Failure.settings }
        path[Int(length)] = 0
        return canonicalPath(URL(fileURLWithPath: String(cString: path)))
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
