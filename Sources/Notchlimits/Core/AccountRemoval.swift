import Foundation
import Security
import Darwin

/// Remove credentials and managed profile directories; preserve the main CLI config.
enum AccountRemoval {

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
    static func remove(_ account: DiscoveredAccount,
                       completion: @escaping (Result<Void, Error>) -> Void) {
        guard account.provider == .codex else {
            completion(Result { try remove(account) })
            return
        }
        guard !AppSwitchState.inProgress.contains(.codex) else {
            completion(.failure(Failure.busy))
            return
        }
        AppSwitchState.inProgress.insert(.codex)
        let finish: (Result<Void, Error>) -> Void = { result in
            defer { AppSwitchState.inProgress.remove(.codex) }
            completion(result.flatMap { Result { try remove(account) } })
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
                try withProfileDirectory(directory, root: ProfileDirectories.claudeRoot, move: move) { _ in
                    for service in services { try deleteKeychainEntry(service: service) }
                }
            }
        } catch is StorageLock$Claude.Failure {
            throw Failure.busy
        }
    }

    static func remove(_ account: DiscoveredAccount) throws {
        switch account.source {
        case .claudeKeychain(let service, let configDir):
            let directory = configDir ?? AuthStorage$Claude.configDirectory(for: service)
            do {
                try AuthStorage$Claude.withRemovalLock(service: service, configDir: directory) { move in
                    let shared: Bool
                    if let directory, !ProfileDirectories.isClaudeBase(directory) {
                        guard let owners = AuthStorage$Claude.keychainServices(in: directory) else { throw Failure.busy }
                        shared = owners.contains { $0 != service }
                        // A file-only login cannot claim the common fallback
                        // after another Keychain owner has appeared.
                        guard !shared || owners.contains(service) else { throw Failure.busy }
                    } else {
                        shared = service != AuthStorage$Claude.baseService && directory.map(ProfileDirectories.isClaudeBase) == true
                    }
                    if shared {
                        // Other owners retain their shared configuration and fallback.
                        try deleteKeychainEntry(service: service)
                    } else {
                        try withProfileDirectory(directory, root: ProfileDirectories.claudeRoot, move: move) { moved in
                            try deleteClaudeCredentials(service: service, configDir: moved)
                        }
                    }
                    AppSwitcher$Claude.accountRemoved(columnID: account.id)
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
            try AuthSwap$Codex.removeAuth(home: url, columnID: account.id) { storage in
                if isBase {
                    try storage.delete()
                } else {
                    try withProfileDirectory(url, root: ProfileDirectories.codexRoot) { directory in
                        try storage.delete(fileHome: directory)
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
                                             operation: (URL?) throws -> Void) throws {
        let manager = FileManager.default
        guard let directory, directory.path.hasPrefix(root.path + "/"),
              manager.fileExists(atPath: directory.path) else { try operation(directory); return }
        guard !ProfileDirectories.containsNativeHome(directory) else { throw Failure.busy }
        let removed = directory.deletingLastPathComponent()
            .appendingPathComponent(".removed-" + UUID().uuidString, isDirectory: true)
        try move(directory, removed)
        do { try operation(removed) } catch {
            do { try move(removed, directory) } catch let rollback as NSError {
                guard rollback.domain == NSCocoaErrorDomain,
                      rollback.code == CocoaError.fileWriteFileExists.rawValue else { throw rollback }
                // A client may bootstrap the original directory while waiting
                // for OAuth locks. Restore missing entries atomically, keeping
                // replacement credentials and all native lock owners untouched.
                try restoreContents(from: removed, to: directory)
            }
            throw error
        }
        try? manager.removeItem(at: removed)
    }

    private static func restoreContents(from source: URL, to destination: URL) throws {
        let sourceFD = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard sourceFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { _ = close(sourceFD) }
        let destinationFD = open(destination.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard destinationFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { _ = close(destinationFD) }
        // Recover access before unrelated profile metadata can fail to merge.
        let authFiles: Set<String> = ["auth.json", ".credentials.json", "config.toml"]
        let names = try FileManager.default.contentsOfDirectory(atPath: source.path).sorted {
            if authFiles.contains($0) != authFiles.contains($1) { return authFiles.contains($0) }
            return $0 < $1
        }
        for name in names {
            // Borrowed renewal leases still own these in the staged directory;
            // the adjacent legacy OAuth lock continues to fence native writers.
            if name.hasPrefix(".oauth_refresh.lock") || name.hasPrefix(".storage-write.lock") { continue }
            if renameatx_np(sourceFD, name, destinationFD, name, UInt32(RENAME_EXCL)) == 0 { continue }
            guard errno == EEXIST else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let original = source.appendingPathComponent(name), current = destination.appendingPathComponent(name)
            let old = try original.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            let new = try current.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if old.isDirectory == true, old.isSymbolicLink != true,
               new.isDirectory == true, new.isSymbolicLink != true {
                try restoreContents(from: original, to: current)
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
