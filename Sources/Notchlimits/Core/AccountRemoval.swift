import Foundation
import Security
import Darwin

/// Remove credentials and managed profile directories; preserve the main CLI config.
enum AccountRemoval {

    struct ClaudeRemoval {
        let service: String
        let retainedFile: DirectoryIdentity?
    }

    enum Failure: LocalizedError {
        case keychain(OSStatus), busy

        var errorDescription: String? {
            switch self {
            case .keychain(let status): return SecCopyErrorMessageString(status, nil) as String?
            case .busy: return L.t("remove.busy")
            }
        }
    }

    /// An extra profile directory belongs to Notchlimits.
    static func isExtraProfile(_ account: DiscoveredAccount) -> Bool {
        switch account.source {
        case .claudeKeychain(_, let configDir):
            return configDir.map { !ProfileDirectories.containsNativeHome($0) } ?? false
        case .codexHome(let url):
            return !ProfileDirectories.containsNativeHome(url) && url.path.hasPrefix(ProfileDirectories.codexRoot.path + "/")
        case .mock:
            return false
        }
    }

    /// Serialize Codex removal with Desktop switching, including its exit barrier.
    @MainActor
    static func remove(_ account: DiscoveredAccount, requireIncomplete: Bool = false,
                       claudeRemoval: ((ClaudeRemoval) -> Void)? = nil,
                       completion: @escaping (Result<Void, Error>) -> Void) {
        guard account.provider == .codex else {
            completion(Result { try remove(account, requireIncomplete: requireIncomplete, claudeRemoval: claudeRemoval) })
            return
        }
        guard !AppSwitchState.inProgress.contains(.codex) else {
            completion(.failure(Failure.busy))
            return
        }
        AppSwitchState.inProgress.insert(.codex)
        let finish: (Result<Void, Error>) -> Void = { result in
            defer { AppSwitchState.inProgress.remove(.codex) }
            completion(result.flatMap { Result { try remove(account, requireIncomplete: requireIncomplete) } })
        }
        if touchesCodexDesktop(account) {
            let app = AppSwitcher$Codex()
            DesktopApp.stop(bundleID: app.bundleID, appName: app.appName, completion: finish)
        } else {
            finish(.success(()))
        }
    }

    private static func touchesCodexDesktop(_ account: DiscoveredAccount) -> Bool {
        [AuthSwap$Codex.defaultColumnID, AuthSwap$Codex.activeColumnID].contains(account.id)
    }

    /// A stale unfinished-profile menu must not delete a newly completed login.
    static func removeIncompleteClaudeProfile(at directory: URL) throws {
        guard directory.path.hasPrefix(ProfileDirectories.claudeRoot.path + "/"),
              !ProfileDirectories.containsNativeHome(directory) else { throw Failure.busy }
        do {
            try AuthStorage$Claude.withRemovalLock(directory: directory) { move in
                guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent(".credentials.json").path) else {
                    throw Failure.busy
                }
                guard let services = AuthStorage$Claude.keychainServices(in: directory) else { throw Failure.busy }
                // Native CLI also writes non-login stubs. Remove those only
                // after proving that no OAuth login is present or unreadable.
                guard services.allSatisfy({ AuthStorage$Claude.hasNoLogin(service: $0, interactive: false) }) else {
                    throw Failure.busy
                }
                // Logout removes Keychain metadata but leaves the profile and
                // its Desktop session. Retire every supported path spelling.
                let desktopServices = Set(services + AuthStorage$Claude.profileServices(in: directory))
                try withProfileDirectory(directory, root: ProfileDirectories.claudeRoot, move: move) { _ in
                    for service in services { try deleteKeychainEntry(service: service) }
                }
                for service in desktopServices {
                    AppSwitcher$Claude.accountRemoved(columnID: "claude:" + service)
                }
            }
        } catch is StorageLock$Claude.Failure {
            throw Failure.busy
        }
    }

    static func remove(_ account: DiscoveredAccount, requireIncomplete: Bool = false,
                       claudeRemoval: ((ClaudeRemoval) -> Void)? = nil) throws {
        switch account.source {
        case .claudeKeychain(let service, let configDir):
            let directory = configDir ?? AuthStorage$Claude.configDirectory(for: service)
            let owner = directory ?? (service == AuthStorage$Claude.baseService
                ? ProfileDirectories.home.appendingPathComponent(".claude") : nil)
            do {
                try AuthStorage$Claude.withRemovalLock(service: service, configDir: directory) { move in
                    // A stale logical path must not authorize the replacement
                    // directory after the managed root has been redirected.
                    let current = service == AuthStorage$Claude.baseService
                        ? ProfileDirectories.home.appendingPathComponent(".claude")
                        : AuthStorage$Claude.configDirectory(for: service)
                    guard let owner, let current,
                          current.resolvingSymlinksInPath().path == owner.resolvingSymlinksInPath().path,
                          (service == AuthStorage$Claude.baseService && configDir == nil
                            ? AuthStorage$Claude.matchesPrimaryOwner(account)
                            : account.claudeConfigOwner?.matches(owner) == true),
                          let owners = AuthStorage$Claude.keychainServices(in: owner) else { throw Failure.busy }
                    let shared = owners.contains { $0 != service }
                        || service != AuthStorage$Claude.baseService && ProfileDirectories.isClaudeBase(owner)
                    // A file-only login cannot claim the common fallback after
                    // another Keychain owner has appeared, including native main.
                    guard !shared || owners.contains(service) else { throw Failure.busy }
                    var retainedFile: DirectoryIdentity?
                    if shared {
                        // Other owners retain their shared configuration and fallback.
                        if FileManager.default.fileExists(atPath: owner.appendingPathComponent(".credentials.json").path) {
                            guard let identity = DirectoryIdentity.capture(owner) else { throw Failure.busy }
                            retainedFile = identity
                        }
                        try deleteKeychainEntry(service: service)
                        if service == AuthStorage$Claude.baseService {
                            AuthStorage$Claude.recordSharedPrimaryRemoval()
                        }
                    } else {
                        try withProfileDirectory(directory, root: ProfileDirectories.claudeRoot, move: move) { moved in
                            try deleteClaudeCredentials(service: service, configDir: moved)
                        }
                    }
                    AppSwitcher$Claude.accountRemoved(columnID: account.id)
                    claudeRemoval?(ClaudeRemoval(service: service, retainedFile: retainedFile))
                }
            } catch is StorageLock$Claude.Failure {
                throw Failure.busy
            }

        case .codexHome(let url):
            // Discovery presents a canonical base home only as primary. Reject
            // stale duplicate columns rather than deleting another logical owner.
            let isBase = AuthSwap$Codex.isBaseHome(url)
            guard !isBase || account.id == AuthSwap$Codex.defaultColumnID else { throw Failure.busy }
            guard isBase || !ProfileDirectories.containsNativeHome(url) else { throw Failure.busy }
            // Synchronous callers must also fail safely under a running Desktop.
            if touchesCodexDesktop(account) {
                guard !DesktopApp.isRunning(bundleID: AppSwitcher$Codex().bundleID) else { throw Failure.busy }
            }
            // Unlinking a managed alias removes its login without deleting the
            // independent owner's shared fallback or physical directory.
            var link = stat()
            let removesLink = !isBase && url.deletingLastPathComponent().path == ProfileDirectories.codexRoot.path
                && url.path.withCString({ Darwin.lstat($0, &link) }) == 0 && link.st_mode & S_IFMT == S_IFLNK
            try AuthSwap$Codex.removeAuth(home: url, columnID: account.id, removingProfileLink: removesLink,
                                        requireIncomplete: requireIncomplete, expectedAccount: account) { storage in
                if isBase {
                    try storage.delete()
                } else {
                    var info = stat()
                    if url.path.withCString({ Darwin.lstat($0, &info) }) == 0,
                       info.st_mode & S_IFMT == S_IFDIR,
                       AuthSwap$Codex.directoryIsShared(home: storage.home, directory: url) {
                        // Moving the physical directory would also move another
                        // native namespace's file/configuration. A symlink can
                        // be removed independently without moving that owner.
                        throw Failure.busy
                    }
                    let keyring = try storage.beginRemoval()
                    var retainsOriginalFile = true
                    do {
                        try withProfileDirectory(url, root: ProfileDirectories.codexRoot,
                                                 rollbackFile: { retainsOriginalFile = $0 },
                                                 restoredFileOwner: AuthSwap$Codex.recordRestoredFileOwner) { directory in
                            try storage.delete(fileHome: directory, keyring: keyring?.storage)
                        }
                        keyring?.finish()
                    } catch {
                        if let keyring, !keyring.restore(retainsOriginalFile: retainsOriginalFile) {
                            AuthSwap$Codex.retainRemovalRecovery(keyring)
                        }
                        throw error
                    }
                }
            }

        case .mock:
            break
        }
    }

    /// Free the profile name before deleting credentials. A refused move leaves
    /// the login intact; a refused credential deletion restores the directory.
    /// Cleanup of a hidden, logged-out directory cannot block same-name re-addition.
    private static func withProfileDirectory(_ directory: URL?, root: URL,
                                             move: (URL, URL) throws -> Void = { try FileManager.default.moveItem(at: $0, to: $1) },
                                             rollbackFile: ((Bool) -> Void)? = nil,
                                             restoredFileOwner: ((Int32, Int32) -> Void)? = nil,
                                             operation: (URL?) throws -> Void) throws {
        let manager = FileManager.default
        guard let directory, directory.path.hasPrefix(root.path + "/"),
              manager.fileExists(atPath: directory.path) else { try operation(directory); return }
        guard !ProfileDirectories.containsNativeHome(directory) else { throw Failure.busy }
        let removed = directory.deletingLastPathComponent()
            .appendingPathComponent(".removed-" + UUID().uuidString, isDirectory: true)
        try move(directory, removed)
        do { try operation(removed) } catch {
            rollbackFile?(false)
            do {
                try move(removed, directory)
                rollbackFile?(true)
            } catch let rollback as NSError {
                guard rollback.domain == NSCocoaErrorDomain,
                      rollback.code == CocoaError.fileWriteFileExists.rawValue else { throw rollback }
                // A client may bootstrap the original directory while waiting
                // for OAuth locks. Restore missing entries atomically, keeping
                // replacement credentials and all native lock owners untouched.
                try restoreContents(from: removed, to: directory,
                                    authFileRestored: {
                                        rollbackFile?(true)
                                        restoredFileOwner?($0, $1)
                                    })
            }
            throw error
        }
        try? manager.removeItem(at: removed)
    }

    private static func restoreContents(from source: URL, to destination: URL,
                                        isProfileRoot: Bool = true,
                                        authFileRestored: ((Int32, Int32) -> Void)? = nil) throws {
        let sourceFD = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard sourceFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { _ = close(sourceFD) }
        let destinationFD = open(destination.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard destinationFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { _ = close(destinationFD) }
        var auth = stat()
        let replacementAuth = isProfileRoot
            && fstatat(destinationFD, "auth.json", &auth, AT_SYMLINK_NOFOLLOW) == 0
        if isProfileRoot && !replacementAuth && errno != ENOENT {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        // Recover access before unrelated profile metadata can fail to merge.
        let authFiles: Set<String> = ["auth.json", ".credentials.json", "config.toml"]
        let names = try FileManager.default.contentsOfDirectory(atPath: source.path).sorted {
            if authFiles.contains($0) != authFiles.contains($1) { return authFiles.contains($0) }
            return $0 < $1
        }
        for name in names {
            // A new CLI file login uses implicit file storage when it has no
            // config. Keep the old settings staged instead of hiding that login
            // behind its previous owner's Keychain record.
            if replacementAuth && name == "config.toml" { continue }
            // Borrowed renewal leases still own these in the staged directory;
            // the adjacent legacy OAuth lock continues to fence native writers.
            if name.hasPrefix(".oauth_refresh.lock") || name.hasPrefix(".storage-write.lock") { continue }
            if renameatx_np(sourceFD, name, destinationFD, name, UInt32(RENAME_EXCL)) == 0 {
                if isProfileRoot && name == "auth.json" { authFileRestored?(sourceFD, destinationFD) }
                if isProfileRoot && name == ".credentials.json" {
                    AuthStorage$Claude.recordRestoredFileOwner(from: source, to: destination)
                }
                continue
            }
            guard errno == EEXIST else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let original = source.appendingPathComponent(name), current = destination.appendingPathComponent(name)
            let old = try original.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            let new = try current.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if old.isDirectory == true, old.isSymbolicLink != true,
               new.isDirectory == true, new.isSymbolicLink != true {
                try restoreContents(from: original, to: current, isProfileRoot: false)
            }
            // Existing files belong to the concurrent client. Retain conflicting
            // backups in the hidden directory instead of overwriting either login.
        }
    }

    private static func deleteClaudeCredentials(service: String, configDir: URL?) throws {
        let file = configDir?.appendingPathComponent(".credentials.json") ?? AuthStorage$Claude.credentialFile(service: service)
        let backup = try file.flatMap { FileManager.default.fileExists(atPath: $0.path) ? try Data(contentsOf: $0) : nil }
        // An unlink failure must leave Keychain and pending grants untouched.
        if let file, backup != nil { try FileManager.default.removeItem(at: file) }
        do {
            try deleteKeychainEntry(service: service)
        } catch {
            if let file, let backup,
               !FileManager.default.createFile(atPath: file.path, contents: backup, attributes: [.posixPermissions: 0o600]) {
                throw CocoaError(.fileWriteUnknown)
            }
            throw error
        }
    }

    private static func deleteKeychainEntry(service: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let status = AuthStorage$Claude.access { SecItemDelete(query as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.keychain(status)
        }
    }
}
