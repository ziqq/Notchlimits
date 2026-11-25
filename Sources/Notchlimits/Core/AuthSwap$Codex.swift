import Foundation
import CryptoKit
import Darwin

/// Keep Desktop and CLI on the base CODEX_HOME while swapping only credentials.
/// Projects and threads stay in place. The primary account waits in an internal
/// backup using its original backend; native token changes return to the selected
/// profile's backend before the next switch. liveHome keeps column identities stable.
enum AuthSwap$Codex {

    enum Failure: LocalizedError {
        case missingAuth, busy

        var errorDescription: String? {
            L.t(self == .busy ? "appswitch.error.inProgress" : "appswitch.error.noAuth")
        }
    }

    static let defaultColumnID = "codex:default"

    /// Preserve main's existing ID and escape the reserved prefix so imported
    /// `profile:default` cannot collide with `default`.
    static func profileColumnID(_ name: String) -> String {
        name == "default" || name.hasPrefix("profile:")
            ? "codex:profile:\(name)" : "codex:\(name)"
    }

    private static let activeIDKey = "codexAppAccountID"
    private static let activeHomeKey = "codexAppAccountHome"
    private static let activePhysicalHomeKey = "codexAppAccountPhysicalHome"
    private static let stashStoreKey = "codexAppStashStore"
    private static let stashHomeKey = "codexAppStashHome"
    private static let primaryReturnKey = "codexAppPrimaryReturn"
    private static let recoveredBackupKey = "codexAppRecoveredBackups"
    private static let recoveredBackupIDPrefix = "codex-recovery:"
    private static let duplicateRecoverySettings = Data("cli_auth_credentials_store = \"keyring\"\n".utf8)
    private static let sourceAuthKey = "codexAppSourceAuth"
    private static let primarySessionKey = "codexAppPrimarySession"
    private static let nativeGrantKey = "codexNativeGrant"
    private static let retiredNativeGrantsKey = "codexRetiredNativeGrants"

    /// Перестановка входов и запись продлённых токенов не должны пересечься:
    /// иначе в `~/.codex` уедет уже потраченный refresh-токен.
    private static let lock = NSLock()
    struct SessionCopy {
        let storage: AuthStorage$Codex
        let record: AuthStorage$Codex.Record
        let owner: DirectoryIdentity
        let sourceKey: String
        let generation: UUID?
    }
    struct Renewal {
        let id = UUID()
        let columnID: String
        let key: String
        let generation: UUID?
        let columnGeneration: UUID?
        let sourceKey: String
        let sourceGeneration: UUID?
        let storage: AuthStorage$Codex
        let record: AuthStorage$Codex.Record
        let copies: [SessionCopy]
        let nativeStorage: AuthStorage$Codex
        let nativeOwner: DirectoryIdentity?
    }
    struct AuthSnapshot {
        let data: Data
        let key: String
        let generation: UUID?
        let columnGeneration: UUID?
        let sourceKey: String
        let sourceGeneration: UUID?
    }
    private struct RenewalRecovery {
        let removal: AuthStorage$Codex.RemovalKeyring
        let generation: UUID?
    }
    private static var generations: [String: UUID] = [:]
    private static var columnGenerations: [String: UUID] = [:]
    private static var renewals: [String: Renewal] = [:]
    private static var renewalRecoveries: [UUID: RenewalRecovery] = [:]
    /// Forward only an observed credential identity, never another login that
    /// happens to use the same profile name. No credentials are stored in defaults.
    private static var rotations: [String: Data] = [:]
    private static var usageLogins: [String: UUID] =
        (UserDefaults.standard.dictionary(forKey: "codexUsageLogins") as? [String: String] ?? [:])
            .compactMapValues { UUID(uuidString: $0) }
    private static var knownCopies: [String: SessionCopy] = [:]
    private static var copyDebt: [String: SessionCopy] = [:]
    private static var primarySession: (data: Data, owner: DirectoryIdentity, generation: UUID?)?
    private static var nativeGrantsDirty = false

    /// Базовый CODEX_HOME: его берут голая `codex` и приложение.
    static var baseHome: URL {
        ProcessInfo.processInfo.environment["CODEX_HOME"].map { URL(fileURLWithPath: $0) }
            ?? ProfileDirectories.home.appendingPathComponent(".codex")
    }

    /// Куда убран вход основного аккаунта, пока в `~/.codex` чужой.
    private static var defaultStashHome: URL {
        DesktopApp.supportDirectory.appendingPathComponent("codex-app/default", isDirectory: true)
    }

    static var stashHome: URL {
        if let path = UserDefaults.standard.string(forKey: stashHomeKey) {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        if let path = recoveredBackupState["stashHome"] as? String {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        return defaultStashHome
    }

    private static var recoveredBackupState: [String: Any] {
        UserDefaults.standard.dictionary(forKey: recoveredBackupKey) ?? [:]
    }

    private static var recoveredBackups: [String: [String: String]] {
        recoveredBackupState["profiles"] as? [String: [String: String]] ?? [:]
    }

    private struct PrimaryReturn: Codable {
        struct Route: Codable {
            let id: String?
            let home: String?
            let physicalHome: String?

            init() {
                let defaults = UserDefaults.standard
                id = defaults.string(forKey: activeIDKey)
                home = defaults.string(forKey: activeHomeKey)
                physicalHome = defaults.string(forKey: activePhysicalHomeKey)
            }

            func restore() {
                let defaults = UserDefaults.standard
                defaults.set(id, forKey: activeIDKey)
                defaults.set(home, forKey: activeHomeKey)
                defaults.set(physicalHome, forKey: activePhysicalHomeKey)
            }
        }

        let nativePath: String
        let nativeOwner: String
        let nativeMode: AuthStorage$Codex.Mode?
        let previousLogin: String?
        let previousAccountOwner: String?
        let previousGrant: String?
        let primaryLogin: String?
        let primaryAccountOwner: String?
        let primaryGrant: String?
        let backupPath: String
        let backupOwner: String?
        let backupMode: AuthStorage$Codex.Mode
        let backupBackend: AuthStorage$Codex.Backend?
        let previousRoute: Route?
        var published = false
        var rollingBack: Bool?
    }

    private static func savePrimaryReturn(_ operation: PrimaryReturn) throws {
        UserDefaults.standard.set(try PropertyListEncoder().encode(operation), forKey: primaryReturnKey)
        guard UserDefaults.standard.synchronize() else { throw Failure.busy }
    }

    private static func finishPrimaryReturn() {
        guard UserDefaults.standard.object(forKey: primaryReturnKey) != nil,
              UserDefaults.standard.synchronize() else { return }
        UserDefaults.standard.removeObject(forKey: primaryReturnKey)
        _ = UserDefaults.standard.synchronize()
    }

    private static func startPrimaryRollback() throws {
        guard let data = UserDefaults.standard.data(forKey: primaryReturnKey) else { return }
        var operation = try PropertyListDecoder().decode(PrimaryReturn.self, from: data)
        operation.rollingBack = true
        try savePrimaryReturn(operation)
    }

    static func recoverPrimaryReturnForDiscovery() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        do {
            try recoverPrimaryReturnLocked()
            return true
        } catch { return false }
    }

    /// Recover routing from the durable publication intent. Cleanup may only
    /// resume for the exact backup login and directory named by that intent.
    private static func recoverPrimaryReturnLocked() throws {
        guard let data = UserDefaults.standard.data(forKey: primaryReturnKey) else { return }
        let operation = try PropertyListDecoder().decode(PrimaryReturn.self, from: data)
        let native = try storage(at: baseHome)
        guard native.mode != .ephemeral else { throw AuthStorage$Codex.Failure.ephemeral }
        let owner = DirectoryIdentity.capture(native.home)
        try requireNative(native, owner: owner)
        let record = try native.load(verifyingOwner: true)
        try requireNative(native, owner: owner)
        let identity = record.flatMap { authIdentity($0.data) }
        let sameNative = try native.home.path == operation.nativePath
            && availableFileOwnerKey(native.home) == operation.nativeOwner
        if sameNative, record == nil, let mode = operation.nativeMode, native.mode != mode {
            throw Failure.busy
        }
        let currentGrant = record.flatMap { grantIdentity($0.data) }
        let currentAccountOwner = record.flatMap { primaryAccountOwner($0.data) }
        let rollingBack = operation.rollingBack == true
        let previousContinued = operation.previousGrant != nil && currentGrant != nil
            && operation.previousAccountOwner != nil && currentAccountOwner == operation.previousAccountOwner
            && operation.previousAccountOwner != operation.primaryAccountOwner
        if sameNative, rollingBack || !operation.published, identity == operation.previousLogin || previousContinued {
            try requirePublication(record?.data, storage: native, owner: owner)
            if rollingBack { operation.previousRoute?.restore() }
            if previousContinued, let grant = operation.previousGrant, currentGrant != grant {
                try retireNativeGrant(grant)
            }
            if rollingBack || previousContinued {
                rememberNativeGrant(record?.data, home: native.home.path)
                try flushNativeGrants()
            }
            finishPrimaryReturn()
            return
        }

        let replacedGrant = operation.primaryGrant
        let nativeContinued = sameNative && replacedGrant != nil && currentGrant != nil && identity != operation.primaryLogin
            && operation.primaryAccountOwner != nil
            && currentAccountOwner == operation.primaryAccountOwner
            && (operation.published && !rollingBack || operation.primaryAccountOwner != operation.previousAccountOwner)
        let nativeRotated = nativeContinued && currentGrant != replacedGrant
        if nativeRotated, let replacedGrant {
            try requirePublication(record?.data, storage: native, owner: owner)
            try retireNativeGrant(replacedGrant)
            try flushNativeGrants()
        }
        let path = URL(fileURLWithPath: operation.backupPath, isDirectory: true)
        if homeKey(stashHome) == path.path {
            if let key = operation.backupOwner,
               try availableRecoveredBackupHome(["home": path.path, "owner": key]) != nil {
                guard let backupOwner = DirectoryIdentity.capture(path), homeKey(path) == path.path else {
                    throw Failure.busy
                }
                let backup = try AuthStorage$Codex(home: path, mode: operation.backupMode)
                var deferredCleanup: [String: String] = [:]
                if sameNative, identity == operation.primaryLogin || nativeContinued,
                   let backend = operation.backupBackend, let login = operation.primaryLogin {
                    do {
                        try cleanupReturnedCopies(in: backup, owner: backupOwner, backend: backend, login: login,
                                                  retainedRoute: baseHome, retainedUsesKeyring: native.mode.usesKeyring) {
                            try requirePublication(record?.data, storage: native, owner: owner)
                        }
                    } catch {
                        try requirePublication(record?.data, storage: native, owner: owner)
                        deferredCleanup = ["returnedLogin": login, "returnedBackend": backend.rawValue]
                        deferredCleanup["returnedOwner"] = operation.primaryAccountOwner
                        deferredCleanup["returnedGrant"] = operation.primaryGrant
                    }
                }
                // The write may have completed before the old process died.
                // Either backend, including an unreadable one, can still own a login.
                if !deferredCleanup.isEmpty || (try? backup.load(backend: .file) == nil) != true
                    || (try? backup.load(backend: .keyring) == nil) != true {
                    try requireNativeLocation(native, owner: owner)
                    _ = try retainUnreadableBackup(backup, owner: backupOwner, details: deferredCleanup)
                }
            } else {
                // A path that no longer names the captured owner must not be reused.
                var state = recoveredBackupState
                state["stashHome"] = nextStashHome().path
                UserDefaults.standard.set(state, forKey: recoveredBackupKey)
            }
        }
        try requirePublication(record?.data, storage: native, owner: owner)
        clearActiveRouting()
        UserDefaults.standard.removeObject(forKey: stashStoreKey)
        UserDefaults.standard.removeObject(forKey: stashHomeKey)
        if nativeRotated, let record, let replacedGrant {
            // Keep the original grant as the lookup key until known copies
            // have caught up with the native rotation.
            rememberPrimarySession(record.data, grant: replacedGrant, accountOwner: operation.primaryAccountOwner)
        } else if let record, let owner {
            primarySession = (record.data, owner, generations[native.home.path])
            rememberPrimarySession(record.data)
        }
        rememberNativeGrant(record?.data, home: native.home.path)
        finishPrimaryReturn()
    }

    /// The alternate backend can own a separate login. Remove only copies
    /// that still match the recorded credentials.
    private static func cleanupReturnedCopies(in backup: AuthStorage$Codex, owner: DirectoryIdentity,
                                              backend: AuthStorage$Codex.Backend, login: String,
                                              retainedRoute: URL, retainedUsesKeyring: Bool,
                                              validating: @escaping () throws -> Void) throws {
        let path = backup.home
        guard homeKey(retainedRoute) != path.path else { throw Failure.busy }
        let candidates: [AuthStorage$Codex.Backend] = backend == .keyring ? [.file, .keyring] : [.file]
        var sharedCopyRemains = false
        for candidate in candidates {
            guard let current = try backup.load(backend: candidate), authIdentity(current.data) == login else { continue }
            let isFile = candidate == .file
            if isFile, fileIsShared(home: path, fileHome: path) {
                sharedCopyRemains = true
                continue
            }
            let exact = try AuthStorage$Codex(home: path, mode: isFile ? .file : .keyring)
            try requireIdle(exact)
            try requireIdleGrant(current.data)
            try exact.delete(preservingFile: true, validating: {
                try AuthStorage$Codex.validateMutation(homes: [retainedRoute, path],
                                                       includesKeyring: retainedUsesKeyring || !isFile,
                                                       tracksDirectoryContents: false) {
                    try validating()
                    if isFile, fileIsShared(home: path, fileHome: path) { throw Failure.busy }
                    let found = try exact.load(backend: candidate)
                    guard AuthStorage$Codex.sameCredentials(found?.data, current.data),
                          try matchesLocation(exact, home: path, owner: owner) else { throw Failure.busy }
                }
            })
        }
        if sharedCopyRemains { throw Failure.busy }
    }

    static func recoveredBackupHomes() -> [(id: String, home: URL)] {
        recoveredBackups.sorted { $0.key < $1.key }.compactMap { id, entry in
            guard let home = recoveredBackupHome(entry) else { return nil }
            return (recoveredBackupIDPrefix + id, home)
        }
    }

    private static func recoveredBackupHome(_ entry: [String: String]) -> URL? {
        try? availableRecoveredBackupHome(entry)
    }

    private static func availableRecoveredBackupHome(_ entry: [String: String]) throws -> URL? {
        guard let path = entry["home"], let owner = entry["owner"] else { return nil }
        let home = URL(fileURLWithPath: path, isDirectory: true)
        do {
            guard try availableFileOwnerKey(home) == owner, homeKey(home) == path else { return nil }
        } catch let error as POSIXError where error.code == .ENOTDIR {
            return nil
        }
        return home
    }

    static func recoveredBackupDiscovery(managedDirectories: [URL], resumeCleanup: Bool = true)
        -> (profiles: [(id: String, home: URL)], reservedPaths: Set<String>) {
        lock.lock()
        defer { lock.unlock() }
        discoverPreviouslySavedNativeLogins()
        let replay = resumeCleanup ? resolveRecoveredBackups(managedDirectories: managedDirectories) : CleanupReplay()
        let backups = recoveredBackupHomes()
        let entries = recoveredBackups
        let profiles = backups.filter { profile in
            let id = String(profile.id.dropFirst(recoveredBackupIDPrefix.count))
            return entries[id]?["pendingOn"] == nil && (resumeCleanup || entries[id]?["cleanupSource"] == nil)
                && !replay.hidden.contains(id)
                && exposesRetainedBackup(entries[id], at: profile.home, id: profile.id)
        }
        // Managed discovery can reach a private backup through a root alias.
        return (profiles + replay.visible, Set((backups + replay.visible).map { $0.home.path }))
    }

    private static func retainUnreadableBackup(_ backup: AuthStorage$Codex, owner: DirectoryIdentity?,
                                               details: [String: String] = [:]) throws -> String {
        guard let owner, homeKey(backup.home) == backup.home.path,
              let key = try availableFileOwnerKey(backup.home), owner.matches(backup.home) else { throw Failure.busy }
        var state = recoveredBackupState
        var entries = state["profiles"] as? [String: [String: String]] ?? [:]
        let id = entries.first(where: { $0.value["home"] == backup.home.path && $0.value["owner"] == key })?.key
            ?? UUID().uuidString
        entries[id] = details.merging(["home": backup.home.path, "owner": key]) { _, location in location }
        // CLI can keep using this CODEX_HOME. A future swap needs another stash.
        if homeKey(stashHome) == backup.home.path {
            state["stashHome"] = nextStashHome().path
        }
        state["profiles"] = entries
        UserDefaults.standard.set(state, forKey: recoveredBackupKey)
        UserDefaults.standard.removeObject(forKey: stashStoreKey)
        UserDefaults.standard.removeObject(forKey: stashHomeKey)
        return id
    }

    private static func nextStashHome() -> URL {
        defaultStashHome.deletingLastPathComponent().appendingPathComponent("backup-" + UUID().uuidString, isDirectory: true)
    }

    private static func exposesRetainedBackup(_ entry: [String: String]?, at home: URL, id: String) -> Bool {
        if let returned = entry?["returnedLogin"] {
            guard let active = try? storage(at: home).load(verifyingOwner: true) else { return false }
            return authIdentity(active.data) != returned
        }
        if let saved = entry?["nativeLogin"], id != activeColumnID,
           let active = try? storage(at: home).load(verifyingOwner: true), authIdentity(active.data) == saved,
           let native = try? storage(at: baseHome).load(verifyingOwner: true) {
            return authIdentity(native.data) != saved
        }
        return true
    }

    /// Cleanup of a retired stash can retry without blocking active routing.
    private static func reconcileReturnedCopy(_ entry: [String: String]) throws {
        guard let path = try availableRecoveredBackupHome(entry),
              let owner = DirectoryIdentity.capture(path), !isRoutedRecoveryHome(path),
              let login = entry["returnedLogin"], let name = entry["returnedBackend"],
              let backend = AuthStorage$Codex.Backend(rawValue: name) else { return }
        let retainedRoute = liveHome(columnID: defaultColumnID, home: baseHome)
        let retained = try storage(at: retainedRoute)
        guard retained.mode != .ephemeral else { throw Failure.busy }
        let retainedOwner = DirectoryIdentity.capture(retained.home)
        guard let record = try retained.load(verifyingOwner: true) else { throw Failure.busy }
        func validate() throws {
            guard liveHome(columnID: defaultColumnID, home: baseHome) == retainedRoute,
                  !isRoutedRecoveryHome(path),
                  try checkedRecord(record, storage: retained, home: retainedRoute, owner: retainedOwner).matches else {
                throw Failure.busy
            }
        }
        try validate()
        let rotated: Bool
        if let account = entry["returnedOwner"], primaryAccountOwner(record.data) == account,
           let grant = entry["returnedGrant"] {
            rotated = try retiredNativeGrants().contains(grant)
        } else { rotated = false }
        if authIdentity(record.data) == login || rotated {
            let backup = try AuthStorage$Codex(home: path, mode: backend == .file ? .file : .keyring)
            try cleanupReturnedCopies(in: backup, owner: owner, backend: backend, login: login,
                                      retainedRoute: retainedRoute, retainedUsesKeyring: retained.mode.usesKeyring,
                                      validating: validate)
        }
    }

    /// Keep a saved login private until the original namespace can be checked.
    @discardableResult
    private static func resolveRecoveredBackups(managedDirectories: [URL]) -> CleanupReplay {
        var state = recoveredBackupState
        let previous = recoveredBackups
        var entries = previous
        let replay = resumeDuplicateCleanups(in: &entries, managedDirectories: managedDirectories)
        let pending = entries
        for (id, entry) in pending where !replay.resumed.contains(id) {
            if entry["returnedLogin"] != nil {
                do {
                    try reconcileReturnedCopy(entry)
                    for key in ["returnedLogin", "returnedBackend", "returnedOwner", "returnedGrant"] {
                        entries[id]?[key] = nil
                    }
                } catch {
                    // The old copy stays private while its owner cannot be checked.
                }
                continue
            }
            guard let originalID = entry["pendingOn"], let snapshot = recoveredBackupHome(entry),
                  let original = matchedPrimaryRecovery(entry) ?? pending[originalID],
                  let originalPath = original["home"], let originalOwner = original["owner"] else { continue }
            let originalURL = URL(fileURLWithPath: originalPath, isDirectory: true)
            let canonical = URL(fileURLWithPath: homeKey(originalURL), isDirectory: true)
            var info = stat()
            if fstatat(AT_FDCWD, canonical.path, &info, 0) != 0 {
                guard errno == ENOENT || errno == ENOTDIR else { continue }
                entries[id]?["pendingOn"] = nil
                continue
            }
            guard let currentOwner = fileOwnerKey(info) else {
                entries[id]?["pendingOn"] = nil
                continue
            }
            var retained = original
            var retainedID = originalID
            let isPrimaryRoute = homeKey(liveHome(columnID: defaultColumnID, home: baseHome)) == canonical.path
            if canonical.path != originalPath || currentOwner != originalOwner {
                let known = entries.first { id, record in
                    id != originalID && record["pendingOn"] == nil
                        && record["home"] == canonical.path && record["owner"] == currentOwner
                }
                // Resolve duplicates only against a route discovery can actually show.
                let isManaged = managedDirectories.contains { homeKey($0) == canonical.path }
                let isExtraRoute = !isBaseHome(canonical) && !isPrimaryBackup(canonical) && (known != nil || isManaged)
                guard isPrimaryRoute || isExtraRoute else {
                    entries[id]?["pendingOn"] = nil
                    continue
                }
                retainedID = known?.key ?? originalID
                retained["home"] = canonical.path
                retained["owner"] = currentOwner
            }
            guard let originalHome = recoveredBackupHome(retained) else { continue }
            let retainedRouteIsCurrent = {
                let route = isPrimaryRoute ? liveHome(columnID: defaultColumnID, home: baseHome) : originalURL
                return homeKey(route) == originalHome.path
            }
            let stageID = UUID().uuidString
            do {
                if try discardDuplicateRecovery(at: snapshot, matching: entry, retainedAt: originalHome, matching: retained,
                                                retainedRouteIsCurrent: retainedRouteIsCurrent,
                                                onDuplicate: {
                    if isPrimaryRoute {
                        // A later retry must still find the primary after the old alias is removed.
                        entries[id]?["matchedPrimaryHome"] = canonical.path
                        entries[id]?["matchedPrimaryOwner"] = currentOwner
                    } else {
                        entries[retainedID] = retained
                        entries[id]?["pendingOn"] = retainedID
                    }
                }, onDetachedRetainedLogin: { retry in
                    entries[retainedID] = retained
                    if retry {
                        entries[id]?["pendingOn"] = retainedID
                        entries[id]?["matchedPrimaryHome"] = nil
                        entries[id]?["matchedPrimaryOwner"] = nil
                    }
                }, recordStage: { home in
                    if let home {
                        guard let owner = try availableFileOwnerKey(home) else { throw Failure.busy }
                        var stage = entries[id] ?? entry
                        stage["home"] = home.path
                        stage["owner"] = owner
                        stage["cleanupSource"] = id
                        stage["cleanupRetainedHome"] = retained["home"]
                        stage["cleanupRetainedOwner"] = retained["owner"]
                        stage["cleanupRetainedID"] = UUID().uuidString
                        entries[stageID] = stage
                        state["profiles"] = entries
                        UserDefaults.standard.set(state, forKey: recoveredBackupKey)
                        guard UserDefaults.standard.synchronize() else { throw Failure.busy }
                    } else {
                        // Keep the checkpoint on disk until the outer decision
                        // has committed, even if the empty stage is removed.
                        entries[stageID] = nil
                    }
                }) {
                    entries[id] = nil
                } else {
                    entries[id]?["pendingOn"] = nil
                }
            } catch {
                // Unavailable credentials and changed ownership can be retried.
                continue
            }
        }
        if entries != recoveredBackups {
            state["profiles"] = entries
            UserDefaults.standard.set(state, forKey: recoveredBackupKey)
        }
        return replay
    }

    private struct CleanupReplay {
        var resumed: Set<String> = []
        var hidden: Set<String> = []
        var visible: [(id: String, home: URL)] = []
    }

    private typealias CleanupCredentials = (active: Data?, hasInactiveLogin: Bool)

    /// An interrupted cleanup still owns one decision across its source,
    /// staged copy and the namespace that was supposed to retain the login.
    private static func resumeDuplicateCleanups(in entries: inout [String: [String: String]],
                                                managedDirectories: [URL]) -> CleanupReplay {
        var replay = CleanupReplay()
        for (stageID, stage) in entries {
            guard let sourceID = stage["cleanupSource"], let retainedID = stage["cleanupRetainedID"],
                  let retainedPath = stage["cleanupRetainedHome"], let retainedOwner = stage["cleanupRetainedOwner"]
            else { continue }
            replay.resumed.formUnion([sourceID, stageID])
            let retained = ["home": retainedPath, "owner": retainedOwner]
            let source = entries[sourceID]
            let registeredRetained = entries.first {
                $0.key != sourceID && $0.key != stageID && $0.value["pendingOn"] == nil
                    && $0.value["home"] == retainedPath && $0.value["owner"] == retainedOwner
            }?.key
            let retainedTargetID = registeredRetained ?? retainedID
            let participants = [source, stage, retained]
            let homes: [URL?]
            var credentials: [CleanupCredentials?] = []
            let primaryHome = liveHome(columnID: defaultColumnID, home: baseHome)
            let primaryPath = homeKey(primaryHome)
            var primaryData: Data?
            do {
                if let stageHome = try availableRecoveredBackupHome(stage),
                   !managedDirectories.contains(where: { homeKey($0) == stageHome.path }) {
                    _ = try retireEmptyDuplicateStage(at: stageHome, matching: stage)
                }
                homes = try participants.map { try $0.flatMap(availableRecoveredBackupHome) }
                try AuthStorage$Codex.validateMutation(homes: homes.compactMap { $0 }, includesKeyring: true,
                                                       tracksDirectoryContents: false) {
                    let stores = try homes.map { try $0.map(storage(at:)) }
                    credentials = try stores.map { try $0.map(duplicateRecoveryCredentials) }
                    if credentials.contains(where: { $0?.hasInactiveLogin == true }) {
                        if let index = homes.firstIndex(where: { $0?.path == primaryPath }) {
                            primaryData = credentials[index]?.active
                        } else {
                            let primary = URL(fileURLWithPath: primaryPath, isDirectory: true)
                            try AuthStorage$Codex.validateMutation(homes: [primary], includesKeyring: false) {
                                primaryData = try storage(at: primary).load(verifyingOwner: true)?.data
                            }
                        }
                    }
                    for (entry, store) in zip(participants, stores) {
                        guard try entry.flatMap(availableRecoveredBackupHome) == store?.home else { throw Failure.busy }
                        if let store, try storage(at: store.home).mode != store.mode { throw Failure.busy }
                    }
                    guard homeKey(liveHome(columnID: defaultColumnID, home: baseHome)) == primaryPath else {
                        throw Failure.busy
                    }
                }
            } catch {
                continue
            }
            let (sourceData, stageData, retainedData) = (credentials[0]?.active, credentials[1]?.active, credentials[2]?.active)
            let retainedIsPrimary = primaryPath == retainedPath
            let retainedIsManaged = managedDirectories.contains { homeKey($0) == retainedPath }
            if credentials.contains(where: { $0?.hasInactiveLogin == true }) {
                // Keep the checkpoint for inactive stores. Discovery can still show
                // each currently selected login, once, without retiring its owner.
                replay.hidden.formUnion([sourceID, stageID, retainedTargetID])
                let retainedIsDiscovered = retainedIsManaged && registeredRetained == nil
                var shown = [primaryData, retainedIsDiscovered ? retainedData : nil].compactMap { $0 }
                let profiles = [(sourceID, homes[0], sourceData),
                                (retainedTargetID, retainedIsDiscovered ? nil : homes[2], retainedData),
                                (stageID, homes[1], stageData)]
                for (id, home, data) in profiles {
                    guard let home, let data, !isRoutedRecoveryHome(home),
                          !replay.visible.contains(where: { $0.home == home }),
                          !shown.contains(where: { AuthStorage$Codex.sameCredentials($0, data) }) else { continue }
                    replay.visible.append((recoveredBackupIDPrefix + id, home))
                    shown.append(data)
                }
                continue
            }
            let isRetainedVisible = retainedIsPrimary || retainedIsManaged
            let hasRetainedCopy = retainedData != nil && [sourceData, stageData].contains {
                AuthStorage$Codex.sameCredentials($0, retainedData)
            }
            let primaryCopy = [(sourceID, source, sourceData), (stageID, stage, stageData)]
                .first { $0.1?["home"] == primaryPath && $0.2 != nil }
            if retainedData != nil, !isRetainedVisible, !hasRetainedCopy, registeredRetained == nil {
                entries[retainedTargetID] = retained
            }
            func reconciled(_ entry: [String: String]?, data: Data?, matchingSource: Bool = false) -> [String: String]? {
                guard let entry, let data, let path = entry["home"], let owner = entry["owner"] else { return nil }
                var result = ["home": path, "owner": owner]
                if isRoutedRecoveryHome(URL(fileURLWithPath: path)) { return result }
                if let (primaryID, primary, primaryData) = primaryCopy,
                   AuthStorage$Codex.sameCredentials(data, primaryData) {
                    result["pendingOn"] = primaryID
                    result["matchedPrimaryHome"] = primary?["home"]
                    result["matchedPrimaryOwner"] = primary?["owner"]
                } else if (isRetainedVisible || registeredRetained != nil),
                   AuthStorage$Codex.sameCredentials(data, retainedData) {
                    result["pendingOn"] = retainedTargetID
                    if retainedIsPrimary {
                        result["matchedPrimaryHome"] = retainedPath
                        result["matchedPrimaryOwner"] = retainedOwner
                    }
                } else if matchingSource, AuthStorage$Codex.sameCredentials(data, sourceData) {
                    result["pendingOn"] = sourceID
                }
                return result
            }
            if retainedIsManaged, !retainedIsPrimary, hasRetainedCopy, registeredRetained == nil {
                entries[retainedTargetID] = retained
            }
            entries[sourceID] = reconciled(source, data: sourceData)
            entries[stageID] = reconciled(stage, data: stageData, matchingSource: true)
        }
        return replay
    }

    private static func duplicateRecoveryCredentials(_ storage: AuthStorage$Codex) throws -> CleanupCredentials {
        // A failed probe of an inactive store still requires the checkpoint.
        func mayHaveLogin(_ backend: AuthStorage$Codex.Backend) -> Bool {
            (try? storage.load(backend: backend) == nil) != true
        }
        switch storage.mode {
        case .file:
            return (try storage.load(backend: .file)?.data, mayHaveLogin(.keyring))
        case .keyring:
            return (try storage.load(backend: .keyring)?.data, mayHaveLogin(.file))
        case .auto:
            if let keyring = try storage.load(backend: .keyring) { return (keyring.data, mayHaveLogin(.file)) }
            return (try storage.load(backend: .file)?.data, false)
        case .ephemeral: throw Failure.busy
        }
    }

    /// Retire only the stage directory and configuration created by this cleanup.
    private static func retireEmptyDuplicateStage(at home: URL, matching entry: [String: String]) throws -> Bool {
        guard !isRoutedRecoveryHome(home) else { return false }
        let descriptor = open(home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.busy }
        defer { close(descriptor) }
        guard let owner = DirectoryIdentity.capture(descriptor: descriptor) else { throw Failure.busy }
        let staged = try AuthStorage$Codex(home: home, mode: .keyring)
        let config = home.appendingPathComponent("config.toml")
        var empty = false
        var hasConfig = false
        try AuthStorage$Codex.validateMutation(homes: [home], includesKeyring: true) {
            guard try staged.load(backend: .keyring) == nil, try staged.load(backend: .file) == nil else { return }
            let names = try FileManager.default.contentsOfDirectory(atPath: home.path)
            if names == ["config.toml"] {
                var info = stat()
                guard fstatat(descriptor, "config.toml", &info, AT_SYMLINK_NOFOLLOW) == 0,
                      info.st_mode & S_IFMT == S_IFREG,
                      try Data(contentsOf: config) == duplicateRecoverySettings else { return }
                hasConfig = true
            } else if !names.isEmpty {
                return
            }
            empty = true
        }
        guard empty, !isRoutedRecoveryHome(home) else { return false }
        guard owner.matches(home), try availableRecoveredBackupHome(entry) == home else { throw Failure.busy }
        if hasConfig, unlinkat(descriptor, "config.toml", 0) != 0 { throw Failure.busy }
        guard owner.matches(home), rmdir(home.path) == 0 else { throw Failure.busy }
        return true
    }

    private static func isRoutedRecoveryHome(_ home: URL) -> Bool {
        let native = baseHome
        return home.path == homeKey(native) || home.path == homeKey(liveHome(columnID: defaultColumnID, home: native))
    }

    private static func matchedPrimaryRecovery(_ entry: [String: String]) -> [String: String]? {
        guard entry["matchedPrimaryHome"] != nil, let owner = entry["matchedPrimaryOwner"] else { return nil }
        // A switch moves the primary credentials between the native home and stash.
        // The previous owner is only a hint. Reconciliation verifies the current
        // namespace and compares credentials again before discarding a copy.
        let path = homeKey(liveHome(columnID: defaultColumnID, home: baseHome))
        return ["home": path, "owner": owner]
    }

    private static func hasPendingRecovery(for home: URL) -> Bool {
        let entries = recoveredBackups
        return entries.values.contains { entry in
            if entry["returnedLogin"] != nil {
                return homeKey(liveHome(columnID: defaultColumnID, home: baseHome)) == home.path
            }
            guard let original = entry["pendingOn"] else { return false }
            if let primary = matchedPrimaryRecovery(entry) {
                return primary["home"] == home.path
            }
            guard let path = entries[original]?["home"] else { return false }
            return path == home.path || homeKey(URL(fileURLWithPath: path)) == home.path
        }
    }

    private static func discardDuplicateRecovery(at snapshot: URL, matching savedEntry: [String: String],
                                                 retainedAt original: URL, matching retainedEntry: [String: String],
                                                 retainedRouteIsCurrent: @escaping () -> Bool,
                                                 onDuplicate: () -> Void,
                                                 onDetachedRetainedLogin: (Bool) -> Void,
                                                 recordStage: (URL?) throws -> Void) throws -> Bool {
        guard let savedOwner = DirectoryIdentity.capture(snapshot),
              let retainedOwner = DirectoryIdentity.capture(original),
              recoveredBackupHome(savedEntry) == snapshot, recoveredBackupHome(retainedEntry) == original else {
            throw Failure.busy
        }
        let saved = try storage(at: snapshot)
        let retained = try storage(at: original)
        // Discovery can route the primary directly to the recovery copy.
        // That route already owns the credentials, so there is nothing to delete.
        guard saved.home.path != retained.home.path, !isRoutedRecoveryHome(saved.home) else { return false }
        guard saved.mode != .ephemeral else { throw Failure.busy }
        try requireIdle(saved)
        try requireIdle(retained)
        let includesKeyring = saved.mode.usesKeyring || retained.mode.usesKeyring
        var savedRecord: AuthStorage$Codex.Record?
        var retainedRecord: AuthStorage$Codex.Record?
        try AuthStorage$Codex.validateMutation(homes: [snapshot, original], includesKeyring: includesKeyring,
                                               tracksDirectoryContents: false) {
            savedRecord = try saved.load(verifyingOwner: true)
            retainedRecord = try retained.load(verifyingOwner: true)
            try requireStorage(saved, home: snapshot, owner: savedOwner)
            try requireStorage(retained, home: original, owner: retainedOwner)
        }
        guard retainedRouteIsCurrent() else { throw Failure.busy }
        guard let savedRecord else { return true }
        guard let retainedRecord, AuthStorage$Codex.sameCredentials(savedRecord.data, retainedRecord.data) else {
            return false
        }
        guard savedRecord.backend != .file || retainedRecord.backend != .file
                || !savedOwner.isSameDirectory(as: retainedOwner) else { return false }
        // An exact match keeps the existing route and its removal guard, even
        // if Keychain refuses to clear the private copy this time.
        onDuplicate()
        try requireIdleGrant(savedRecord.data)
        func validateRetainedRoute() throws {
            guard retainedRouteIsCurrent() else { throw Failure.busy }
        }
        func validateDuplicate(_ candidate: AuthStorage$Codex, owner: DirectoryIdentity) throws {
            try AuthStorage$Codex.validateMutation(homes: [candidate.home, original], includesKeyring: includesKeyring,
                                                   tracksDirectoryContents: false) {
                if candidate.mode.usesKeyring, try candidate.load(backend: .file) != nil { throw Failure.busy }
                guard try checkedRecord(savedRecord, storage: candidate, home: candidate.home, owner: owner).matches,
                      try checkedRecord(retainedRecord, storage: retained, home: original, owner: retainedOwner).matches else {
                    throw Failure.busy
                }
            }
            try validateRetainedRoute()
            guard !isRoutedRecoveryHome(candidate.home) else { throw Failure.busy }
        }
        if savedRecord.backend == .keyring {
            let staging = snapshot.deletingLastPathComponent()
                .appendingPathComponent(".duplicate-" + UUID().uuidString, isDirectory: true)
            guard mkdir(staging.path, 0o700) == 0 else { throw Failure.busy }
            let staged = try AuthStorage$Codex(home: staging, mode: .keyring)
            let config = staged.home.appendingPathComponent("config.toml")
            guard let stageOwner = DirectoryIdentity.capture(staged.home),
                  let stageOwnerKey = try availableFileOwnerKey(staged.home) else { throw Failure.busy }
            let stageEntry = ["home": staged.home.path, "owner": stageOwnerKey]
            var stageHasItem = false
            defer {
                if !stageHasItem, stageOwner.matches(staged.home),
                   (try? retireEmptyDuplicateStage(at: staged.home, matching: stageEntry)) == true {
                    try? recordStage(nil)
                }
            }
            try duplicateRecoverySettings.write(to: config, options: .withoutOverwriting)
            // Register before moving the item so discovery can resume a cut transaction.
            try recordStage(staged.home)
            guard try saved.moveRecoveryKeychainItem(to: staged, validating: {
                try validateDuplicate(saved, owner: savedOwner)
            }) else { throw Failure.busy }
            stageHasItem = true
            do {
                // Updating the account name retains a concurrent secret update.
                // Delete only after reading the item in the private namespace.
                try staged.delete(validating: {
                    try validateDuplicate(staged, owner: stageOwner)
                }, beforeKeyringMutation: {
                    try validateRetainedRoute()
                    guard !isRoutedRecoveryHome(staged.home) else { throw Failure.busy }
                })
                stageHasItem = false
            } catch {
                if (try? staged.moveRecoveryKeychainItem(to: saved, validating: {
                    try requireStorage(staged, home: staged.home, owner: stageOwner)
                    try requireStorage(saved, home: snapshot, owner: savedOwner)
                    guard try saved.load(backend: .file) == nil else { throw Failure.busy }
                })) == true { stageHasItem = false }
                throw error
            }
        } else {
            try saved.delete(validating: { try validateDuplicate(saved, owner: savedOwner) })
        }
        if retainedRouteIsCurrent(), retainedOwner.matches(original) {
            let loaded = Result { try saved.load(verifyingOwner: true) }
            if retainedRouteIsCurrent(), retainedOwner.matches(original) {
                guard let current = try loaded.get() else { return true }
                if AuthStorage$Codex.sameCredentials(current.data, savedRecord.data) { throw Failure.busy }
                return false
            }
        }

        // The route can change while the deletion is in flight. Restore the
        // copy exclusively, then let discovery reconcile the new route.
        let restored = try? saved.restoreRecoveryRecordIfAbsent(savedRecord) {
            try requireStorage(saved, home: snapshot, owner: savedOwner)
            if saved.mode.usesKeyring, try saved.load(backend: .file) != nil { throw Failure.busy }
        }
        if restored == true { throw Failure.busy }
        if (try? checkedRecord(savedRecord, storage: saved, home: snapshot, owner: savedOwner).matches) == true {
            // Another writer already restored the same login.
            if retainedRouteIsCurrent() { throw Failure.busy }
            return false
        }
        let retainedMatches: Bool
        do {
            retainedMatches = try checkedRecord(retainedRecord, storage: retained, home: original, owner: retainedOwner).matches
        } catch {
            // A temporary Keychain denial still leaves the detached namespace.
            try requireStorage(retained, home: original, owner: retainedOwner)
            onDetachedRetainedLogin(true)
            throw Failure.busy
        }
        if retainedMatches {
            onDetachedRetainedLogin(false)
        } else {
            let mode: AuthStorage$Codex.Mode = savedRecord.backend == .file ? .file : .keyring
            let recovery = ProfileDirectories.codexRoot.appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
            try saveRecoveredBackup(savedRecord, mode: mode, at: recovery)
        }
        return false
    }

    /// Колонка, чей вход сейчас в `~/.codex`.
    static var activeColumnID: String {
        guard let id = UserDefaults.standard.string(forKey: activeIDKey) else { return defaultColumnID }
        // The saved path identifies the owner even when its legacy ID collided.
        if let path = UserDefaults.standard.string(forKey: activeHomeKey) {
            // Older versions could select a duplicate of the physical base home.
            // Its backup is the same grant, so it must never become a sleeping login.
            if let owner = activeOwnerPath, isBaseHome(URL(fileURLWithPath: owner)) { return defaultColumnID }
            let name = URL(fileURLWithPath: path).lastPathComponent
            if name.hasPrefix("profile:"), id == "codex:\(name)" {
                return profileColumnID(name)
            }
        }
        return id
    }

    static var isSwapped: Bool { activeColumnID != defaultColumnID }

    private static var activeOwnerPath: String? {
        UserDefaults.standard.string(forKey: activePhysicalHomeKey)
            ?? UserDefaults.standard.string(forKey: activeHomeKey).map { homeKey(URL(fileURLWithPath: $0)) }
    }

    /// Папка, где сейчас лежит `auth.json` колонки (`home` — её собственная).
    static func liveHome(columnID: String, home: URL) -> URL {
        guard isSwapped else { return home }
        if columnID == defaultColumnID { return stashHome }
        if columnID == activeColumnID { return baseHome }
        if let owner = activeOwnerPath,
           (try? sameOwner(home, URL(fileURLWithPath: owner))) == true { return baseHome }
        return home
    }

    struct UsageOwner: Equatable {
        let path: String
        let directory: DirectoryIdentity?
    }

    struct LoginOwner: Equatable {
        let location: UsageOwner
        let authIdentity: String?
    }

    enum ActionLogin {
        case readable(LoginOwner)
        case opaque(UsageOwner, () throws -> Bool)
        case unavailable
    }

    /// Polling follows the routed credentials; removal owns the profile itself.
    /// Capture routing and physical identity together, including backup recovery.
    static func usageOwner(columnID: String, home: URL) -> UsageOwner {
        lock.lock()
        defer { lock.unlock() }
        let path = homeKey(liveHome(columnID: columnID, home: home))
        return UsageOwner(path: path, directory: DirectoryIdentity.capture(URL(fileURLWithPath: path)))
    }

    static func discoveredLogin(columnID: String, home: URL) -> AuthStorage$Codex.LoginSelection? {
        lock.lock()
        defer { lock.unlock() }
        let live = liveHome(columnID: columnID, home: home)
        guard let source = try? storage(at: live) else { return nil }
        let login = source.loginSelection()
        return homeKey(live) == source.home.path ? login : nil
    }

    static func actionLogin(for account: DiscoveredAccount) -> ActionLogin? {
        guard let selection = account.codexLogin, case .codexHome(let home) = account.source else { return nil }
        lock.lock()
        defer { lock.unlock() }
        do { try recoverPrimaryReturnLocked() } catch { return .unavailable }
        let live = liveHome(columnID: account.id, home: home)
        guard let source = try? storage(at: live) else { return .unavailable }
        let location = UsageOwner(path: source.home.path, directory: DirectoryIdentity.capture(source.home))
        if let current = try? source.load(verifyingOwner: true), selection.matches(current),
           let identity = authIdentity(current.data), homeKey(live) == source.home.path {
            return .readable(LoginOwner(location: location, authIdentity: identity))
        }
        if selection == .keyring, let check = source.opaqueLoginCheck(), homeKey(live) == source.home.path {
            return .opaque(location, check)
        }
        return .unavailable
    }

    private static func requireActionLogin(_ account: DiscoveredAccount?, owner: ActionLogin?) throws {
        guard let account, let selection = account.codexLogin,
              case .codexHome(let home) = account.source else { return }
        let live = liveHome(columnID: account.id, home: home)
        let source = try storage(at: live)
        guard source.loginSelection() == selection else { throw Failure.busy }
        switch owner {
        case .readable(let owner):
            let record = try source.load(verifyingOwner: true)
            guard let record, selection.matches(record), authIdentity(record.data) == owner.authIdentity,
                  owner.location == UsageOwner(path: source.home.path, directory: DirectoryIdentity.capture(source.home))
            else { throw Failure.busy }
        case .opaque(let owner, let current):
            guard try current(), owner == UsageOwner(path: source.home.path, directory: DirectoryIdentity.capture(source.home))
            else { throw Failure.busy }
        case .unavailable: throw Failure.busy
        case nil: break
        }
        guard homeKey(live) == source.home.path else { throw Failure.busy }
    }

    private static func requireSelectedRecord(_ record: AuthStorage$Codex.Record?, account: DiscoveredAccount?,
                                              owner: ActionLogin?) throws {
        guard let selection = account?.codexLogin else { return }
        guard let record, selection.matches(record) else { throw Failure.busy }
        switch owner {
        case .readable(let owner):
            guard owner.authIdentity == authIdentity(record.data) else { throw Failure.busy }
        case .opaque(_, let current):
            guard try current() else { throw Failure.busy }
        case .unavailable: throw Failure.busy
        case nil: break
        }
    }

    /// Provider outcomes retain a login proof without making discovery read secrets.
    static func loginOwner(columnID: String, home: URL) -> LoginOwner {
        lock.lock()
        defer { lock.unlock() }
        let live = liveHome(columnID: columnID, home: home)
        let path = homeKey(live)
        let record = try? storage(at: live).load()
        let location = UsageOwner(path: path, directory: DirectoryIdentity.capture(URL(fileURLWithPath: path)))
        return LoginOwner(location: location, authIdentity: record.flatMap { authIdentity($0.data) })
    }

    static func isCurrent(_ owner: LoginOwner, columnID: String, home: URL) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let live = liveHome(columnID: columnID, home: home)
        let path = homeKey(live)
        let source = try storage(at: live)
        let record = try source.load(verifyingOwner: true)
        guard path == source.home.path, homeKey(live) == path else { throw Failure.busy }
        let location = UsageOwner(path: path, directory: DirectoryIdentity.capture(source.home))
        return owner == LoginOwner(location: location, authIdentity: record.flatMap { authIdentity($0.data) })
    }

    static func isBaseHome(_ url: URL) -> Bool {
        (try? sameOwner(url, baseHome)) == true
    }

    /// A duplicate primary owner is not another account. Native Keychain
    /// namespaces remain distinct even when their directories share an inode.
    static func isPrimaryBackup(_ url: URL) -> Bool {
        (try? sameOwner(url, stashHome)) == true
    }

    /// Removing a directory also removes every backup below it. Match physical
    /// ancestors so Data-volume aliases cannot bypass the reserved owner.
    static func containsPrimaryBackup(_ url: URL, excludingRecoveryID: String? = nil) -> Bool {
        let candidate = URL(fileURLWithPath: homeKey(url))
        let prefix = candidate.path.hasSuffix("/") ? candidate.path : candidate.path + "/"
        let owner = fileOwnerKey(candidate)
        let retained = recoveredBackupHomes().filter {
            $0.id != excludingRecoveryID || $0.home.path != candidate.path
        }.map(\.home)
        for home in [stashHome] + retained {
            var backup = URL(fileURLWithPath: homeKey(home))
            if backup.path == candidate.path || backup.path.hasPrefix(prefix) { return true }
            guard let owner else { continue }
            while backup.path != "/" {
                if owner == fileOwnerKey(backup) { return true }
                backup.deleteLastPathComponent()
            }
        }
        return false
    }

    private static func homeKey(_ home: URL) -> String { AuthStorage$Codex.canonicalPath(home) }

    /// Keychain keeps native realpath keys. Only file grants share an owner
    /// across Data-volume firmlink spellings of the same physical directory.
    private static func fileOwnerKey(_ home: URL) -> String? {
        try? availableFileOwnerKey(home)
    }

    private static func availableFileOwnerKey(_ home: URL) throws -> String? {
        var info = stat()
        guard home.path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
            let code = errno
            guard code == ENOENT else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
            return nil
        }
        return fileOwnerKey(info)
    }

    private static func fileOwnerKey(_ info: stat) -> String? {
        guard info.st_mode & S_IFMT == S_IFDIR else { return nil }
        return "file:\(info.st_dev):\(info.st_ino)"
    }

    private static func usesFile(_ storage: AuthStorage$Codex) throws -> Bool {
        switch storage.mode {
        case .file: return true
        case .auto: return try storage.load(verifyingOwner: true)?.backend == .file
        case .keyring, .ephemeral: return false
        }
    }

    /// Keychain cleanup must preserve a file used through another native key.
    /// Callers already hold the swap lock; do not acquire it recursively here.
    static func fileIsShared(home: URL, fileHome: URL) -> Bool {
        guard let homes = try? otherHomes(home: home, directory: fileHome) else { return true }
        for candidate in homes {
            do {
                if try usesFile(storage(at: candidate)) { return true }
            } catch {
                // Unavailable ownership is not permission to remove its file.
                return true
            }
        }
        return false
    }

    static func directoryIsShared(home: URL, directory: URL) -> Bool {
        guard let homes = try? otherHomes(home: home, directory: directory) else { return true }
        for candidate in homes {
            do {
                if try storage(at: candidate).load(verifyingOwner: true) != nil { return true }
            } catch { return true }
        }
        return false
    }

    private static func otherHomes(home: URL, directory: URL) throws -> [URL] {
        let physical = URL(fileURLWithPath: homeKey(directory))
        let root = ProfileDirectories.codexRoot
        // Directory metadata excludes child symlinks. Ownership checks must
        // include those native namespaces before moving their shared target.
        let entries: [URL]
        do {
            entries = try FileManager.default.contentsOfDirectory(
                at: root.resolvingSymlinksInPath(), includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            entries = []
        }
        guard let owner = fileOwnerKey(physical) else { return [] }
        var homes = [baseHome, stashHome] + recoveredBackupHomes().map(\.home) + entries.map {
            root.appendingPathComponent($0.lastPathComponent, isDirectory: true)
        }
        if let active = activeOwnerPath { homes.append(URL(fileURLWithPath: active)) }
        return homes.filter {
            let canonical = URL(fileURLWithPath: homeKey($0))
            return canonical.path != home.path && fileOwnerKey(canonical) == owner
        }
    }

    /// Raw Keychain cleanup may retain a shared file. Complete auto-account
    /// removal cannot: that file would become the account's live fallback.
    private static func requireRemovalOwners(_ target: AuthStorage$Codex, removingProfileLink: Bool = false) throws {
        let homes = try otherHomes(home: target.home, directory: target.home)
        guard !removingProfileLink, target.mode == .auto else { return }
        var file = stat()
        guard lstat(target.home.appendingPathComponent("auth.json").path, &file) == 0 else {
            guard errno == ENOENT else { throw Failure.busy }
            return
        }
        for home in homes {
            guard try !usesFile(storage(at: home)) else { throw Failure.busy }
        }
    }

    private static func sameOwner(_ first: URL, _ second: URL) throws -> Bool {
        if homeKey(first) == homeKey(second) { return true }
        return try sameOwner(storage(at: first), storage(at: second))
    }

    private static func sameOwner(_ first: AuthStorage$Codex, _ second: AuthStorage$Codex) throws -> Bool {
        if first.home.path == second.home.path { return true }
        guard let owner = fileOwnerKey(first.home), owner == fileOwnerKey(second.home) else { return false }
        return try usesFile(first) && usesFile(second)
    }

    private static func sourceKey(_ storage: AuthStorage$Codex, backend: AuthStorage$Codex.Backend) -> String {
        backend == .file ? fileOwnerKey(storage.home) ?? storage.home.path : storage.home.path
    }

    private static func removesFile(_ storage: AuthStorage$Codex, backend: AuthStorage$Codex.Backend,
                                    ownedBy other: AuthStorage$Codex) throws -> Bool {
        guard backend == .keyring, let owner = fileOwnerKey(storage.home),
              owner == fileOwnerKey(other.home) else { return false }
        return try usesFile(other)
    }

    private static func refreshToken(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (root["auth_mode"] as? String).map({ $0 == "chatgpt" }) ?? true,
              let tokens = root["tokens"] as? [String: Any],
              let token = tokens["refresh_token"] as? String, !token.isEmpty else { return nil }
        return token
    }

    private struct SourceProof {
        let selected: String
        let backup: String?
        let intended: String?

        var isPending: Bool { intended != nil }
        var identities: [String] { [selected, backup, intended].compactMap { $0 } }

        func ownsSelected(_ identity: String) -> Bool { identity == selected || identity == intended }
        func ownsBackup(_ identity: String) -> Bool { identity == backup || identity == intended }
    }

    /// A normal selection stores one digest. During cloned-session copyback,
    /// three digests fence both atomic writes so a failed save can be retried.
    private static func sourceProof() throws -> SourceProof? {
        guard let value = UserDefaults.standard.object(forKey: sourceAuthKey) else { return nil }
        if let identity = value as? String { return SourceProof(selected: identity, backup: nil, intended: nil) }
        guard let journal = value as? [String], journal.count == 3 else { throw Failure.busy }
        return SourceProof(selected: journal[0], backup: journal[1], intended: journal[2])
    }

    /// Положить в `~/.codex` вход колонки. Приложение должно быть закрыто.
    static func activate(columnID: String, home: URL, expectedAccount: DiscoveredAccount? = nil,
                         expectedPrimaryRoute: UsageOwner? = nil, expectedLogin: ActionLogin? = nil) throws {
        lock.lock()
        defer { lock.unlock() }
        try recoverPrimaryReturnLocked()
        _ = try activateLocked(columnID: columnID, home: home, expectedAccount: expectedAccount,
                               expectedPrimaryRoute: expectedPrimaryRoute, expectedLogin: expectedLogin)
    }

    private static func activateLocked(columnID: String, home: URL,
                                       keepBackup: Bool = false, expectedAccount: DiscoveredAccount? = nil,
                                       expectedPrimaryRoute: UsageOwner? = nil, expectedLogin: ActionLogin? = nil) throws
        -> (previous: AuthStorage$Codex.Record?, published: AuthStorage$Codex.Record?) {
        let base = try storage(at: baseHome)
        var baseOwner = DirectoryIdentity.capture(base.home)
        guard base.mode != .ephemeral else { throw AuthStorage$Codex.Failure.ephemeral }
        guard columnID == defaultColumnID || !isBaseHome(home) else { throw Failure.busy }
        try requireActionLogin(expectedAccount, owner: expectedLogin)
        func validateSelectionOwner(_ owner: DirectoryIdentity?, at location: URL) throws {
            guard let expectedAccount else { return }
            let missingPrimary = columnID == defaultColumnID && owner == nil
                && expectedAccount.codexHomeMissingPath != nil
                && expectedAccount.codexHomeMissingPath == DirectoryIdentity.missingPath(home)
            guard expectedAccount.id == columnID, homeKey(home) == location.path,
                  (owner != nil && owner == expectedAccount.codexHomeOwner || missingPrimary) else { throw Failure.busy }
        }
        if columnID == activeColumnID {
            try validateSelectionOwner(DirectoryIdentity.capture(home), at: URL(fileURLWithPath: homeKey(home)))
            return (nil, nil)
        }
        guard !renewals.values.contains(where: {
            renewalRecoveries[$0.id] == nil
                && ($0.key == homeKey(home) || $0.columnID == columnID || $0.columnID == activeColumnID)
        }) else {
            throw Failure.busy
        }
        let incoming = columnID == defaultColumnID ? stashHome : home
        let source = try storage(at: incoming)
        let sourceOwner = DirectoryIdentity.capture(source.home)
        if columnID == defaultColumnID {
            try validateSelectionOwner(baseOwner, at: base.home)
            if let expectedPrimaryRoute {
                guard expectedPrimaryRoute == UsageOwner(path: source.home.path, directory: sourceOwner),
                      try matchesLocation(source, home: incoming, owner: sourceOwner) else { throw Failure.busy }
            }
        } else {
            try validateSelectionOwner(sourceOwner, at: source.home)
        }
        try requireIdle(base)
        try requireIdle(source)
        var incomingRecord = try source.load(verifyingOwner: true)
        try requireSelectedRecord(incomingRecord, account: expectedAccount, owner: expectedLogin)
        if let record = incomingRecord {
            try requireIdleGrant(record.data)
            incomingRecord = try reconcile(source, record: record)
        }
        if columnID != defaultColumnID, let record = incomingRecord { trackCopies(of: record.data) }
        var payload = incomingRecord?.data
        guard homeKey(incoming) == source.home.path else { throw Failure.busy }
        // An alias of the selected owner must not publish its old profile copy
        // over the newer native grant before copyback completes.
        if columnID != defaultColumnID, try sameOwner(source, base) { throw Failure.busy }
        if columnID != defaultColumnID, let incomingRecord,
           try removesFile(source, backend: incomingRecord.backend, ownedBy: base) { throw Failure.busy }
        if columnID != defaultColumnID, isSwapped, let active = activeOwnerPath,
           try sameOwner(source, storage(at: URL(fileURLWithPath: active))) {
            throw Failure.busy
        }
        // Internal restoration can intentionally restore a signed-out primary.
        // A Desktop selection represents an account that was discovered signed in.
        let requiresLogin = columnID != defaultColumnID || expectedAccount != nil
        guard !requiresLogin || payload != nil else { throw Failure.missingAuth }
        try requireNative(base, owner: baseOwner)
        try FileManager.default.createDirectory(at: base.home, withIntermediateDirectories: true)
        if baseOwner == nil { baseOwner = DirectoryIdentity.capture(base.home) }
        try requireNative(base, owner: baseOwner)
        let previous = try giveBackCurrent(base)
        // Copyback can advance a primary backup that shared the selected grant.
        // Publish that updated record instead of its pre-copyback token snapshot.
        incomingRecord = try source.load(verifyingOwner: true)
        if let record = incomingRecord {
            try requireIdleGrant(record.data)
            incomingRecord = try reconcile(source, record: record)
        }
        guard homeKey(incoming) == source.home.path else { throw Failure.busy }
        payload = incomingRecord?.data
        // Copyback may have retired this grant or advanced a known copy. Check
        // the final payload before handing credentials to native clients.
        if let payload, let grant = grantIdentity(payload),
           try retiredNativeGrants().contains(grant) { throw Failure.busy }
        try requireNative(base, owner: baseOwner)
        let checked = try checkedRecord(incomingRecord, storage: source, home: incoming, owner: sourceOwner)
        guard checked.matches else { throw Failure.busy }
        payload = checked.record?.data
        guard !requiresLogin || payload != nil else { throw Failure.missingAuth }
        try requireNativeLocation(base, owner: baseOwner)
        let backup = columnID == defaultColumnID ? source : try storage(at: stashHome)
        let backupOwner = columnID == defaultColumnID ? sourceOwner : DirectoryIdentity.capture(backup.home)
        let validatePublication = {
            let includesKeyring = source.mode.usesKeyring || base.mode.usesKeyring
            try AuthStorage$Codex.validateMutation(homes: [incoming, baseHome], includesKeyring: includesKeyring) {
                guard try checkedRecord(incomingRecord, storage: source, home: incoming, owner: sourceOwner).matches,
                      try checkedRecord(previous, storage: base, home: baseHome, owner: baseOwner).matches else {
                    throw Failure.busy
                }
            }
        }
        var primaryReturn: PrimaryReturn?
        if columnID == defaultColumnID {
            guard let nativeKey = try availableFileOwnerKey(base.home),
                  try matchesLocation(backup, home: stashHome, owner: backupOwner) else { throw Failure.busy }
            let operation = PrimaryReturn(nativePath: base.home.path, nativeOwner: nativeKey, nativeMode: base.mode,
                                          previousLogin: previous.flatMap { authIdentity($0.data) },
                                          previousAccountOwner: previous.flatMap { primaryAccountOwner($0.data) },
                                          previousGrant: previous.flatMap { grantIdentity($0.data) },
                                          primaryLogin: payload.flatMap(authIdentity),
                                          primaryAccountOwner: payload.flatMap(primaryAccountOwner),
                                          primaryGrant: payload.flatMap(grantIdentity), backupPath: backup.home.path,
                                          backupOwner: try availableFileOwnerKey(backup.home), backupMode: backup.mode,
                                          backupBackend: checked.record?.backend, previousRoute: PrimaryReturn.Route())
            try savePrimaryReturn(operation)
            primaryReturn = operation
        }
        if let payload { try base.save(payload, replacing: previous, validating: validatePublication) }
        else {
            let file = try base.load(backend: .file)?.data
            let preservesFile = base.mode.usesKeyring && file != nil && !AuthStorage$Codex.sameCredentials(file, previous?.data)
            try base.delete(preservingFile: preservesFile, validating: validatePublication)
        }
        rememberNativeGrant(payload, home: base.home.path)
        let verifyPublication = { try requirePublication(payload, storage: base, owner: baseOwner) }
        var removedBackup: AuthStorage$Codex.Record?
        do {
            try verifyPublication()
            if var primaryReturn {
                primaryReturn.published = true
                try savePrimaryReturn(primaryReturn)
            }
            if columnID == defaultColumnID && !keepBackup {
                removedBackup = checked.record
                let retainsLogin = try deleteBackup(checked.record, storage: backup, owner: backupOwner,
                                                    protecting: [(baseHome, base.mode)], validating: {
                    guard try ownsPublication(payload, storage: base, owner: baseOwner) else { throw Failure.busy }
                })
                try verifyPublication()
                if retainsLogin { _ = try retainUnreadableBackup(backup, owner: backupOwner) }
            }
        } catch {
            var recovered: AuthStorage$Codex.Record?
            do {
                try verifyPublication()
                if columnID == defaultColumnID {
                    try restoreBackup(removedBackup, to: backup, owner: backupOwner, recovered: &recovered)
                    try startPrimaryRollback()
                }
                try rollbackPublication(previous, storage: base, owner: baseOwner, validating: verifyPublication)
            } catch {
                clearActiveRouting()
                try exposeUnroutedBackup(backup, owner: backupOwner, removed: removedBackup,
                                         published: columnID == defaultColumnID ? checked.record : nil,
                                         alreadyVisible: recovered)
                if primaryReturn != nil { finishPrimaryReturn() }
                throw error
            }
            if primaryReturn != nil { finishPrimaryReturn() }
            throw error
        }
        if columnID == defaultColumnID {
            UserDefaults.standard.removeObject(forKey: activeIDKey)
            UserDefaults.standard.removeObject(forKey: activeHomeKey)
            UserDefaults.standard.removeObject(forKey: activePhysicalHomeKey)
            if !keepBackup { UserDefaults.standard.removeObject(forKey: sourceAuthKey) }
            if !keepBackup { UserDefaults.standard.removeObject(forKey: stashStoreKey) }
            if !keepBackup { UserDefaults.standard.removeObject(forKey: stashHomeKey) }
            if let payload, let owner = DirectoryIdentity.capture(base.home) {
                primarySession = (payload, owner, generations[base.home.path])
                rememberPrimarySession(payload)
            } else { clearPrimarySession() }
            if !keepBackup { finishPrimaryReturn() }
        } else {
            UserDefaults.standard.set(columnID, forKey: activeIDKey)
            UserDefaults.standard.set(home.path, forKey: activeHomeKey)
            UserDefaults.standard.set(source.home.path, forKey: activePhysicalHomeKey)
            UserDefaults.standard.set(payload.flatMap(authIdentity), forKey: sourceAuthKey)
        }
        return (previous, checked.record)
    }

    /// Вернуть основной аккаунт в `~/.codex` (перед удалением аккаунта и т.п.).
    static func restoreDefault() throws {
        try activate(columnID: defaultColumnID, home: baseHome)
    }

    /// Reserve the source before any refresh POST. Switching cannot publish its
    /// old grant until persistence finishes; successful removal retires the owner.
    static func beginRenewal(columnID: String, home: URL, expected: AuthSnapshot? = nil) throws -> Renewal? {
        lock.lock()
        defer { lock.unlock() }
        try recoverPrimaryReturnLocked()
        let key = homeKey(home)
        if let expected, expected.key != key || expected.generation != generations[key]
            || expected.columnGeneration != columnGenerations[columnID] { return nil }
        let nativeStorage = try storage(at: baseHome)
        let nativeOwner = DirectoryIdentity.capture(nativeStorage.home)
        let native = try nativeStorage.load(verifyingOwner: true)
        try requireNative(nativeStorage, owner: nativeOwner)
        try observeNativeGrant(native?.data, home: nativeStorage.home.path)
        guard renewals[key] == nil,
              !renewals.values.contains(where: { $0.columnID == columnID }) else { throw Failure.busy }
        let live = liveHome(columnID: columnID, home: home)
        guard !isBaseHome(live) else { return nil }
        let source = try storage(at: live)
        try requireIdle(source)
        // Usage may read a native auto fallback, but a refresh must not spend
        // its stale grant while the preferred Keychain owner is unavailable.
        guard var observed = try source.load(verifyingOwner: true) else { return nil }
        if try advancePrimaryCopies(matching: observed.data) {
            guard let current = try source.load(verifyingOwner: true) else { return nil }
            observed = current
        }
        try requireIdleGrant(observed.data)
        let record = try reconcile(source, record: observed)
        guard homeKey(home) == key, homeKey(live) == source.home.path else { throw Failure.busy }
        try requireNative(nativeStorage, owner: nativeOwner)
        guard !(try sameOwner(source, nativeStorage)),
              !(try removesFile(source, backend: record.backend, ownedBy: nativeStorage)) else { return nil }
        if let active = activeOwnerPath, isSwapped {
            let owner = try storage(at: URL(fileURLWithPath: active))
            if try sameOwner(source, owner) || removesFile(source, backend: record.backend, ownedBy: owner) { return nil }
        }
        let sourceKey = sourceKey(source, backend: record.backend)
        if let expected, expected.sourceKey != sourceKey || expected.sourceGeneration != generations[sourceKey] { return nil }
        if let expected, authIdentity(record.data) != authIdentity(expected.data) { return nil }
        // A copied grant is still native-owned even in a different directory.
        // Independent sessions of the same account have different refresh tokens.
        if let token = refreshToken(record.data) {
            guard try !nativeOwnsOrRetired(record.data) else { return nil }
            if let native = try nativeStorage.load(verifyingOwner: true), refreshToken(native.data) == token { return nil }
            let proof = isSwapped ? try sourceProof() : nil
            if isSwapped, let identity = authIdentity(record.data),
               proof?.identities.contains(identity) == true { return nil }
            // Native refresh may already have advanced its token. The captured
            // selected record still proves which original grant it owns.
            if isSwapped, let active = activeOwnerPath,
               let selected = try storage(at: URL(fileURLWithPath: active)).load(verifyingOwner: true),
               let identity = authIdentity(selected.data), proof?.ownsSelected(identity) == true,
               refreshToken(selected.data) == token { return nil }
        }
        trackCopies(of: record.data)
        let renewal = Renewal(columnID: columnID, key: key, generation: generations[key],
                              columnGeneration: columnGenerations[columnID],
                              sourceKey: sourceKey, sourceGeneration: generations[sourceKey],
                              storage: source, record: record,
                              copies: sessionCopies(of: record.data, excluding: sourceKey),
                              nativeStorage: nativeStorage, nativeOwner: nativeOwner)
        try requireNative(nativeStorage, owner: nativeOwner)
        renewals[key] = renewal
        return renewal
    }

    /// Quarantine persistence is outside the swap lock and may block. Recheck
    /// the complete reservation after it, before spending the one-use grant.
    static func canSubmit(_ renewal: Renewal, home: URL) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard renewals[renewal.key]?.id == renewal.id,
              generations[renewal.key] == renewal.generation,
              columnGenerations[renewal.columnID] == renewal.columnGeneration,
              generations[renewal.sourceKey] == renewal.sourceGeneration else { return false }
        try requireNative(renewal.nativeStorage, owner: renewal.nativeOwner)
        let live = liveHome(columnID: renewal.columnID, home: home)
        let source = try storage(at: live)
        guard source.home == renewal.storage.home, source.mode == renewal.storage.mode else { return false }
        let native = try renewal.nativeStorage.load(verifyingOwner: true)
        try observeNativeGrant(native?.data, home: renewal.nativeStorage.home.path)
        guard try !nativeOwnsOrRetired(renewal.record.data),
              native.flatMap({ refreshToken($0.data) }) != refreshToken(renewal.record.data),
              !(try sameOwner(source, renewal.nativeStorage)),
              !(try removesFile(source, backend: renewal.record.backend, ownedBy: renewal.nativeStorage)) else { return false }
        try requireNative(renewal.nativeStorage, owner: renewal.nativeOwner)
        // Finish configuration and grant-metadata I/O before the final source
        // read. Subsequent checks inspect only the captured location bindings.
        guard let current = try source.load(verifyingOwner: true),
              current.backend == renewal.record.backend,
              authIdentity(current.data) == authIdentity(renewal.record.data) else { return false }
        try requireNativeLocation(renewal.nativeStorage, owner: renewal.nativeOwner)
        return homeKey(home) == renewal.key && homeKey(live) == source.home.path
            && sourceKey(source, backend: current.backend) == renewal.sourceKey
    }

    static func isCurrent(_ renewal: Renewal) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return renewals[renewal.key]?.id == renewal.id
    }

    static func finishRenewal(_ renewal: Renewal) {
        lock.lock()
        defer { lock.unlock() }
        let key = renewal.key
        if renewals[key]?.id == renewal.id { renewals[key] = nil }
        renewalRecoveries[renewal.id] = nil
    }

    /// Removal already holds the swap lock. A refused rollback must preserve a
    /// pending rotation in the recovery namespace without publishing over a new login.
    static func retainRemovalRecovery(_ recovery: AuthStorage$Codex.RemovalKeyring) {
        for renewal in renewals.values where renewal.record.backend == .keyring {
            let storage = renewalRecoveries[renewal.id]?.removal.storage ?? renewal.storage
            if storage.home.path == recovery.original.home.path {
                renewalRecoveries[renewal.id] = RenewalRecovery(removal: recovery,
                                                               generation: generations[recovery.storage.home.path])
            }
        }
    }

    /// Discovery gives a retained recovery its own column. Retry only the
    /// pending grant routed to that native namespace; persistence verifies its owner.
    static func recoveryMatches(_ renewal: Renewal, columnID: String, home: URL) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard renewals[renewal.key]?.id == renewal.id,
              let recovery = renewalRecoveries[renewal.id] else { return false }
        return homeKey(liveHome(columnID: columnID, home: home)) == recovery.removal.storage.home.path
    }

    /// Retry only the backend that supplied the submitted refresh grant. In auto
    /// mode a temporary Keychain error must not turn a file fallback into a re-login.
    @discardableResult
    static func storeRenewed(_ renewal: Renewal, usedRefreshToken: String,
                             tokens: OAuth$Codex.Tokens) throws -> AuthSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        let key = renewal.key
        guard renewals[key]?.id == renewal.id else { return nil }
        let recovery = renewalRecoveries[renewal.id]
        let destination = recovery?.removal.storage ?? renewal.storage
        let destinationKey = recovery?.removal.storage.home.path ?? renewal.sourceKey
        if let recovery {
            // Recovery is now a separate owner. Removing a replacement at the
            // old column must not discard this owner's accepted rotation.
            guard try ownsDirectory(recovery.removal.owner, at: destination.home),
                  generations[destinationKey] == recovery.generation else { return nil }
        } else {
            guard generations[key] == renewal.generation,
                  columnGenerations[renewal.columnID] == renewal.columnGeneration,
                  generations[renewal.sourceKey] == renewal.sourceGeneration else { return nil }
        }
        guard let projected = renewedAuth(renewal.record.data, usedRefreshToken: usedRefreshToken,
                                         tokens: tokens, now: Date()) else { return nil }
        rememberRotation(from: renewal.record.data, to: projected)
        var failure: Error?
        for copy in renewal.copies {
            do { try persist(copy, tokens: tokens, usedRefreshToken: usedRefreshToken) }
            catch { failure = error }
        }
        let currentKey = try renewal.record.backend == .file
            ? availableFileOwnerKey(destination.home) : destination.home.path
        guard currentKey == destinationKey else {
            if let failure { throw failure }
            return nil
        }
        var updated: Data?
        do {
            if let record = try destination.load(backend: renewal.record.backend) {
                if authIdentity(record.data) == authIdentity(projected) {
                    updated = record.data
                } else if authIdentity(record.data) == authIdentity(renewal.record.data),
                          let data = renewedAuth(record.data, usedRefreshToken: usedRefreshToken,
                                                 tokens: tokens, now: Date()) {
                    try destination.save(data, backend: record.backend, replacing: record, validating: {
                        if let recovery {
                            guard try ownsDirectory(recovery.removal.owner, at: destination.home) else { throw Failure.busy }
                        }
                        guard try matchesPinnedRecord(record, storage: destination, key: destinationKey) else {
                            throw Failure.busy
                        }
                    })
                    // A native Keychain change during fallback cleanup can
                    // retire this publication before we return its snapshot.
                    if record.backend == .keyring {
                        let current = try destination.load(backend: .keyring)
                        if current.flatMap({ authIdentity($0.data) }) == authIdentity(data) { updated = current?.data }
                    } else { updated = data }
                }
            }
        } catch { failure = error }
        if let failure { throw failure }
        guard let updated else { return nil }
        if recovery != nil {
            return AuthSnapshot(data: updated, key: destinationKey, generation: generations[destinationKey],
                                columnGeneration: columnGenerations[profileColumnID(destination.home.lastPathComponent)],
                                sourceKey: destinationKey, sourceGeneration: generations[destinationKey])
        }
        return AuthSnapshot(data: updated, key: renewal.key, generation: renewal.generation,
                            columnGeneration: renewal.columnGeneration,
                            sourceKey: destinationKey, sourceGeneration: generations[destinationKey])
    }

    /// auth.json с продлёнными токенами, или nil, если в нём уже другой
    /// refresh-токен (его обновил кто-то ещё) или файл не разобрать.
    /// Незнакомые поля сохраняются. Чистая функция — покрыта самопроверкой.
    static func renewedAuth(_ data: Data, usedRefreshToken: String,
                            tokens: OAuth$Codex.Tokens, now: Date) -> Data? {
        guard var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              var stored = root["tokens"] as? [String: Any],
              stored["refresh_token"] as? String == usedRefreshToken
        else { return nil }

        stored["access_token"] = tokens.accessToken
        if let idToken = tokens.idToken { stored["id_token"] = idToken }
        if let refreshToken = tokens.refreshToken { stored["refresh_token"] = refreshToken }
        root["tokens"] = stored
        root["last_refresh"] = timestamp.string(from: now)
        return try? JSONSerialization.data(withJSONObject: root,
                                           options: [.prettyPrinted, .withoutEscapingSlashes])
    }

    /// Формат `last_refresh`, как у CLI: RFC 3339 с долями секунды.
    private static let timestamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    /// Revalidate the native namespace, storage mode and physical directory.
    private static func requireNative(_ expected: AuthStorage$Codex, owner: DirectoryIdentity?) throws {
        try requireStorage(expected, home: baseHome, owner: owner)
    }

    private static func requireStorage(_ expected: AuthStorage$Codex, home: URL, owner: DirectoryIdentity?) throws {
        let current = try storage(at: home)
        guard current.home.path == expected.home.path, current.mode == expected.mode else { throw Failure.busy }
        guard try matchesLocation(expected, home: home, owner: owner) else { throw Failure.busy }
    }

    /// Finish configuration and credential I/O before checking the captured
    /// physical binding. Equal credentials do not authorize a recreated owner.
    private static func checkedRecord(_ record: AuthStorage$Codex.Record?, storage expected: AuthStorage$Codex,
                                      home: URL, owner: DirectoryIdentity?) throws
        -> (matches: Bool, record: AuthStorage$Codex.Record?) {
        let current = try storage(at: home)
        guard current.home.path == expected.home.path, current.mode == expected.mode else { return (false, nil) }
        let observed = try current.load(verifyingOwner: true)
        let matches = try observed?.backend == record?.backend
            && observed.flatMap { authIdentity($0.data) } == record.flatMap { authIdentity($0.data) }
            && matchesLocation(expected, home: home, owner: owner)
        return (matches, observed)
    }

    private static func matchesLocation(_ storage: AuthStorage$Codex, home: URL,
                                        owner: DirectoryIdentity?) throws -> Bool {
        let matches = try owner.map { try ownsDirectory($0, at: storage.home) }
            ?? (DirectoryIdentity.missingPath(storage.home) != nil)
        return matches && homeKey(home) == storage.home.path
    }

    private static func requireNativeLocation(_ expected: AuthStorage$Codex, owner: DirectoryIdentity?) throws {
        guard DirectoryIdentity.capture(expected.home) == owner,
              homeKey(baseHome) == expected.home.path else { throw Failure.busy }
    }

    /// Publication can change an auto backend. Its intended credentials, not
    /// an unverified read after the write, authorize cleanup and rollback.
    private static func ownsPublication(_ data: Data?, storage: AuthStorage$Codex,
                                        owner: DirectoryIdentity?) throws -> Bool {
        try requireNative(storage, owner: owner)
        let current = try storage.load(verifyingOwner: true)
        try requireNativeLocation(storage, owner: owner)
        return AuthStorage$Codex.sameCredentials(current?.data, data)
    }

    private static func requirePublication(_ data: Data?, storage: AuthStorage$Codex,
                                           owner: DirectoryIdentity?) throws {
        try AuthStorage$Codex.validateMutation(homes: [baseHome], includesKeyring: storage.mode.usesKeyring,
                                               tracksDirectoryContents: false) {
            guard try ownsPublication(data, storage: storage, owner: owner) else { throw Failure.busy }
        }
    }

    private static func rollbackPublication(_ record: AuthStorage$Codex.Record?, storage: AuthStorage$Codex,
                                            owner: DirectoryIdentity?, validating: @escaping () throws -> Void) throws {
        try validating()
        try storage.restore(record, preservingFile: storage.mode.usesKeyring, validating: validating)
        try requirePublication(record?.data, storage: storage, owner: owner)
        rememberNativeGrant(record?.data, home: storage.home.path)
    }

    private static func clearActiveRouting() {
        for key in [activeIDKey, activeHomeKey, activePhysicalHomeKey, sourceAuthKey] {
            UserDefaults.standard.removeObject(forKey: key)
        }
        clearPrimarySession()
    }

    /// Вход, что сейчас в `~/.codex`, — обратно владельцу.
    private static func giveBackCurrent(_ expected: AuthStorage$Codex? = nil) throws -> AuthStorage$Codex.Record? {
        let live = try expected ?? storage(at: baseHome)
        let owner = DirectoryIdentity.capture(live.home)
        try requireNative(live, owner: owner)
        let record = try live.load(verifyingOwner: true)
        let payload = record?.data
        try requireNative(live, owner: owner)
        try observeNativeGrant(payload, home: live.home.path)
        if !isSwapped {
            try advancePrimaryCopies()
            if let payload { trackCopies(of: payload) }
            try FileManager.default.createDirectory(at: stashHome, withIntermediateDirectories: true)
            let stashMode = record?.backend == .file ? AuthStorage$Codex.Mode.file : live.mode
            let stash = try AuthStorage$Codex(home: stashHome, mode: stashMode)
            let stashOwner = DirectoryIdentity.capture(stash.home)
            try requireIdle(stash)
            let previousStash = try stash.load(verifyingOwner: true)
            guard try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches,
                  try matchesLocation(stash, home: stashHome, owner: stashOwner) else { throw Failure.busy }
            let validateBackup = {
                guard try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches,
                      try matchesLocation(stash, home: stashHome, owner: stashOwner) else { throw Failure.busy }
                let current = try stash.load(verifyingOwner: true)
                guard current?.backend == previousStash?.backend,
                      current.flatMap({ authIdentity($0.data) }) == previousStash.flatMap({ authIdentity($0.data) }),
                      try matchesLocation(stash, home: stashHome, owner: stashOwner) else { throw Failure.busy }
                try requireNativeLocation(live, owner: owner)
            }
            if let payload { try stash.save(payload, backend: record?.backend, replacing: previousStash, validating: validateBackup) }
            else { try stash.delete(validating: validateBackup) }
            // A CLI re-login into our internal backup must use that same backend.
            try ("cli_auth_credentials_store = \"" + stashMode.rawValue + "\"\n")
                .write(to: stashHome.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
            UserDefaults.standard.set(stashMode.rawValue, forKey: stashStoreKey)
            return record
        }
        let proof = try sourceProof()
        guard let payload, let path = UserDefaults.standard.string(forKey: activeHomeKey) else {
            guard proof?.isPending != true else { throw Failure.busy }
            return record
        }
        // Old selections have no physical marker. A canonical spelling remains
        // usable; an unpinned symlink cannot prove its original owner after an upgrade.
        let physical = UserDefaults.standard.string(forKey: activePhysicalHomeKey)
            ?? (homeKey(URL(fileURLWithPath: path)) == path ? path : nil)
        let profile = try physical.map { try storage(at: URL(fileURLWithPath: $0)) }
        let profileOwner = profile.flatMap { DirectoryIdentity.capture($0.home) }
        if let profile, profile.home.path == physical,
           let previousRecord = try profile.load(verifyingOwner: true),
           sameAccount(payload, previousRecord.data),
           let identity = authIdentity(previousRecord.data),
           proof?.ownsSelected(identity) ?? (identity == authIdentity(payload)) {
            let previous = previousRecord.data
            try requireIdle(profile)
            let backup = try storage(at: stashHome)
            let backupOwner = DirectoryIdentity.capture(backup.home)
            let primary = try backup.load(verifyingOwner: true)
            let backupIdentity = primary.flatMap { authIdentity($0.data) }
            if proof?.isPending == true {
                guard let backupIdentity, proof?.ownsBackup(backupIdentity) == true else { throw Failure.busy }
            }
            let originalRefresh = refreshToken(previous)
            let sameGrant = originalRefresh != nil && primary.flatMap { refreshToken($0.data) } == originalRefresh
            guard try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches,
                  try checkedRecord(previousRecord, storage: profile, home: profile.home, owner: profileOwner).matches else {
                throw Failure.busy
            }
            let savedProof = UserDefaults.standard.object(forKey: sourceAuthKey)
            var changedProof = false
            func validateProfile() throws {
                guard try checkedRecord(previousRecord, storage: profile, home: profile.home, owner: profileOwner).matches else {
                    if changedProof { UserDefaults.standard.set(savedProof, forKey: sourceAuthKey) }
                    throw Failure.busy
                }
            }
            if proof?.isPending == true || sameGrant {
                // These are copies of one proven session, rather than separate
                // sessions of the same account. Preserve its native rotation in
                // the primary backup before advancing the selected baseline.
                guard let backupIdentity, let intended = authIdentity(payload) else { throw Failure.busy }
                try requireIdle(backup)
                UserDefaults.standard.set([identity, backupIdentity, intended], forKey: sourceAuthKey)
                changedProof = true
                try backup.save(payload, replacing: primary, validating: {
                    guard try checkedRecord(primary, storage: backup, home: stashHome, owner: backupOwner).matches,
                          try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches else {
                        throw Failure.busy
                    }
                    try validateProfile()
                })
            }
            guard try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches else { throw Failure.busy }
            try validateProfile()
            try requireNativeLocation(live, owner: owner)
            try profile.save(payload, replacing: previousRecord, validating: {
                guard try checkedRecord(record, storage: live, home: baseHome, owner: owner).matches else { throw Failure.busy }
                try validateProfile()
                try requireNativeLocation(live, owner: owner)
            })
            UserDefaults.standard.set(authIdentity(payload), forKey: sourceAuthKey)
            rememberRotation(from: previous, to: payload)
            try synchronizeCopies(from: previous, to: payload)
        } else {
            guard proof?.isPending != true else { throw Failure.busy }
            if let record {
                try preserveUnexpectedNativeLogin(record, storage: live, owner: owner)
            }
        }
        return record
    }

    private static func preserveUnexpectedNativeLogin(_ record: AuthStorage$Codex.Record,
                                                      storage native: AuthStorage$Codex,
                                                      owner: DirectoryIdentity?) throws {
        try requirePublication(record.data, storage: native, owner: owner)
        let login = authIdentity(record.data)
        // Reuse a copy saved by an interrupted switch.
        discoverPreviouslySavedNativeLogins()
        for entry in recoveredBackups.values where login != nil && entry["nativeLogin"] == login {
            guard let home = recoveredBackupHome(entry),
                  let saved = try? storage(at: home).load(backend: record.backend),
                  AuthStorage$Codex.sameCredentials(saved.data, record.data) else { continue }
            return
        }
        let root = defaultStashHome.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let id = UUID().uuidString
        let recovery = root.appendingPathComponent("orphaned-" + id, isDirectory: true)
        guard mkdir(recovery.path, 0o700) == 0 else { throw Failure.busy }
        let mode: AuthStorage$Codex.Mode = record.backend == .file ? .file : .keyring
        let destination = try AuthStorage$Codex(home: recovery, mode: mode)
        guard let recoveryOwner = DirectoryIdentity.capture(destination.home),
              let key = try availableFileOwnerKey(destination.home) else { throw Failure.busy }
        func validate() throws {
            try requirePublication(record.data, storage: native, owner: owner)
            guard try matchesLocation(destination, home: recovery, owner: recoveryOwner) else { throw Failure.busy }
        }
        let config = recovery.appendingPathComponent("config.toml")
        try Data(("cli_auth_credentials_store = \"" + mode.rawValue + "\"\n").utf8)
            .write(to: config, options: .withoutOverwriting)
        var state = recoveredBackupState
        var entries = recoveredBackups
        var entry = ["home": destination.home.path, "owner": key]
        entry["nativeLogin"] = login
        entries[id] = entry
        state["profiles"] = entries
        UserDefaults.standard.set(state, forKey: recoveredBackupKey)
        guard UserDefaults.standard.synchronize() else { throw Failure.busy }
        guard try destination.restoreRecoveryRecordIfAbsent(record, validating: validate) else { throw Failure.busy }
    }

    private static func discoverPreviouslySavedNativeLogins() {
        let root = defaultStashHome.deletingLastPathComponent()
        guard let children = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return }
        var state = recoveredBackupState
        var entries = recoveredBackups
        let previous = entries
        for home in children where home.lastPathComponent.hasPrefix("orphaned-") {
            let id = String(home.lastPathComponent.dropFirst("orphaned-".count))
            guard UUID(uuidString: id) != nil, entries[id] == nil,
                  let candidate = try? AuthStorage$Codex(home: home),
                  candidate.home.deletingLastPathComponent().path == homeKey(root), candidate.home.lastPathComponent == home.lastPathComponent,
                  let owner = DirectoryIdentity.capture(candidate.home),
                  let record = try? candidate.load(verifyingOwner: true),
                  let key = try? availableFileOwnerKey(candidate.home), owner.matches(candidate.home) else { continue }
            var entry = ["home": candidate.home.path, "owner": key]
            entry["nativeLogin"] = authIdentity(record.data)
            entries[id] = entry
        }
        if entries != previous {
            state["profiles"] = entries
            UserDefaults.standard.set(state, forKey: recoveredBackupKey)
        }
    }

    static func authData(home: URL) throws -> Data? { try storage(at: home).load()?.data }

    /// Resolve the column and read its credentials in one snapshot. A switch
    /// must not replace base credentials between routing and the file/Keychain read.
    static func authData(columnID: String, home: URL) throws -> Data? {
        try authSnapshot(columnID: columnID, home: home)?.data
    }

    static func authSnapshot(columnID: String, home: URL, verifyingOwner: Bool = false) throws -> AuthSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        try recoverPrimaryReturnLocked()
        let key = homeKey(home)
        let live = liveHome(columnID: columnID, home: home)
        let source = try storage(at: live)
        guard let record = try source.load(verifyingOwner: verifyingOwner) else { return nil }
        guard homeKey(home) == key, homeKey(live) == source.home.path else { throw Failure.busy }
        let sourceKey = sourceKey(source, backend: record.backend)
        return AuthSnapshot(data: record.data, key: key, generation: generations[key],
                            columnGeneration: columnGenerations[columnID],
                            sourceKey: sourceKey, sourceGeneration: generations[sourceKey])
    }

    static func isCurrent(_ snapshot: AuthSnapshot, columnID: String, home: URL) throws -> Bool {
        guard let current = try authSnapshot(columnID: columnID, home: home, verifyingOwner: true) else { return false }
        return current.key == snapshot.key && current.generation == snapshot.generation
            && current.columnGeneration == snapshot.columnGeneration
            && current.sourceKey == snapshot.sourceKey && current.sourceGeneration == snapshot.sourceGeneration
            && authIdentity(current.data) == authIdentity(snapshot.data)
    }

    static func hasAuth(home: URL) -> Bool { (try? storage(at: home))?.contains() ?? false }

    static func removeAuth(home: URL, columnID: String? = nil, removingProfileLink: Bool = false,
                           requireIncomplete: Bool = false, expectedAccount: DiscoveredAccount? = nil,
                           expectedLogin: ActionLogin? = nil,
                           operation: (AuthStorage$Codex) throws -> Void = { try $0.delete() }) throws {
        lock.lock()
        defer { lock.unlock() }
        try recoverPrimaryReturnLocked()
        let key = homeKey(home)
        let target = try storage(at: home)
        var targetOwner = DirectoryIdentity.capture(target.home)
        guard target.home.path == key, homeKey(home) == key else { throw Failure.busy }
        // A discovered column cannot authorize a replacement directory. Check
        // under the swap lock before restoring native auth or deleting a backup.
        if let expectedAccount {
            let missingPrimary = columnID == defaultColumnID && isBaseHome(home)
                && expectedAccount.codexHomeMissingPath != nil
                && expectedAccount.codexHomeMissingPath == DirectoryIdentity.missingPath(home)
            guard expectedAccount.codexHomeOwner?.matches(home) == true || missingPrimary else { throw Failure.busy }
        }
        // Stale discovery or a caller without a column ID cannot authorize
        // deleting the primary through another name for its current backup.
        // The proven primary transaction removes credentials, never its home.
        guard !containsPrimaryBackup(target.home, excludingRecoveryID: columnID)
            || columnID == defaultColumnID && isBaseHome(target.home) else { throw Failure.busy }
        let liveTarget = columnID == defaultColumnID
            ? URL(fileURLWithPath: homeKey(liveHome(columnID: defaultColumnID, home: home))) : target.home
        if hasPendingRecovery(for: target.home) || (liveTarget != target.home && hasPendingRecovery(for: liveTarget)) {
            resolveRecoveredBackups(managedDirectories: ProfileDirectories.codexProfiles())
            guard !hasPendingRecovery(for: target.home),
                  liveTarget == target.home || !hasPendingRecovery(for: liveTarget) else { throw Failure.busy }
        }
        let entries = recoveredBackups
        try requireActionLogin(expectedAccount, owner: expectedLogin)
        let usesSelectedNamespace = expectedAccount.map {
            homeKey(liveHome(columnID: $0.id, home: home)) == target.home.path
        } == true
        let protectsInactiveFile = target.mode.usesKeyring && entries.values.contains { stage in
            guard let source = stage["cleanupSource"] else { return false }
            return [entries[source]?["home"], stage["home"], stage["cleanupRetainedHome"]].contains(target.home.path)
        }
        var removalRecord: AuthStorage$Codex.Record?
        var verifiesLogin = false
        do {
            removalRecord = try target.load(verifyingOwner: true)
            verifiesLogin = true
        } catch {
            // Explicit namespace removal does not require secret-read access.
            // Existing shared-fallback checks still govern auto cleanup below.
            guard target.mode.usesKeyring else { throw error }
            if usesSelectedNamespace, case .readable = expectedLogin { throw error }
        }
        if verifiesLogin, usesSelectedNamespace {
            try requireSelectedRecord(removalRecord, account: expectedAccount, owner: expectedLogin)
        }
        func validateRemoval(at location: URL) throws {
            if protectsInactiveFile, let file = try target.load(backend: .file),
               !AuthStorage$Codex.sameCredentials(file.data, removalRecord?.data) { throw Failure.busy }
            guard verifiesLogin else {
                if usesSelectedNamespace, case .opaque(_, let current) = expectedLogin {
                    guard try current() else { throw Failure.busy }
                }
                try requireStorage(target, home: location, owner: targetOwner)
                return
            }
            guard try checkedRecord(removalRecord, storage: target, home: location, owner: targetOwner).matches else {
                throw Failure.busy
            }
        }
        // Managed removal pins its physical entry before recovery I/O. A root
        // alias change must neither redirect deletion nor retire the old owner.
        let validateMutation = {
            try validateRemoval(at: columnID == defaultColumnID ? home : target.home)
        }
        if requireIncomplete {
            var owners = [target]
            if let columnID {
                let live = try storage(at: liveHome(columnID: columnID, home: home))
                if live.home != target.home { owners.append(live) }
            }
            for owner in owners {
                guard owner.mode != .ephemeral else { throw AuthStorage$Codex.Failure.ephemeral }
                guard try owner.load(verifyingOwner: true) == nil else { throw Failure.busy }
                // Include the selected native login, even if its sleeping copy
                // vanished after the menu was built. Ignored fallbacks also count.
                var info = stat()
                guard lstat(owner.home.appendingPathComponent("auth.json").path, &info) != 0,
                      errno == ENOENT else { throw Failure.busy }
            }
        }
        // Complete account removal must not preserve an unknown fallback and
        // then report success after deleting only its preferred Keychain entry.
        try requireRemovalOwners(target, removingProfileLink: removingProfileLink)
        for renewal in renewals.values {
            let destination = renewalRecoveries[renewal.id]?.removal.storage ?? renewal.storage
            if destination.home.path == target.home.path,
               try hasUnwrittenCopies(renewal) { throw Failure.busy }
        }
        if !rotations.isEmpty, let record = try? target.load(verifyingOwner: true) {
            try synchronizeCopies(to: record.data)
        }
        let fileOwner = fileOwnerKey(target.home)
        // Unlinking an independent Keychain alias preserves the shared file.
        // Its remaining owner's in-flight refresh must still become durable.
        let preservesSharedFile = removingProfileLink && target.mode != .file
            && fileIsShared(home: target.home, fileHome: target.home)
        let restore = isSwapped && columnID.map { [defaultColumnID, activeColumnID].contains($0) } == true
        if restore || columnID == defaultColumnID {
            let base = try storage(at: baseHome)
            var baseOwner = DirectoryIdentity.capture(base.home)
            let backup = try storage(at: stashHome)
            let backupOwner = DirectoryIdentity.capture(backup.home)
            try requireRemovalOwners(backup)
            try requireIdle(base)
            try requireIdle(backup)
            if !restore, try nativeGrantOwner(home: base.home.path) != nil {
                // Deletion must not erase an unobserved native rotation before
                // its spent grant has been durably reserved across copies.
                let native = try base.load(verifyingOwner: true)
                guard homeKey(baseHome) == base.home.path else { throw Failure.busy }
                try observeNativeGrant(native?.data, home: base.home.path)
            }
            let route = PrimaryReturn.Route()
            // Restore primary credentials before removing their backup. A
            // refused cleanup must precede destructive profile deletion.
            let activation = restore ? try activateLocked(columnID: defaultColumnID, home: baseHome, keepBackup: true) : nil
            if restore && baseOwner == nil { baseOwner = DirectoryIdentity.capture(base.home) }
            if restore && targetOwner == nil && target.home == base.home { targetOwner = baseOwner }
            var removedBackup: AuthStorage$Codex.Record?
            var validateNative: (() throws -> Void)?
            do {
                let native = restore ? try base.load(verifyingOwner: true) : nil
                if let activation {
                    // Either store may change after activation. Neither read can
                    // establish what the transaction actually published.
                    guard AuthStorage$Codex.sameCredentials(native?.data, activation.published?.data) else {
                        throw Failure.busy
                    }
                    validateNative = {
                        guard try checkedRecord(native, storage: base, home: baseHome, owner: baseOwner).matches else {
                            throw Failure.busy
                        }
                    }
                }
                let primary = try backup.load(verifyingOwner: true)
                if let activation {
                    guard AuthStorage$Codex.sameCredentials(primary?.data, activation.published?.data),
                          primary?.backend == activation.published?.backend else {
                        throw Failure.busy
                    }
                    let current = try target.load(verifyingOwner: true)
                    let expected = target.home == base.home ? primary?.data : removalRecord.map { forwarded($0.data) }
                    guard current.flatMap({ authIdentity($0.data) }) == expected.flatMap(authIdentity) else { throw Failure.busy }
                    removalRecord = current
                    verifiesLogin = true
                }
                try validateRemoval(at: home)
                removedBackup = primary
                let retainsLogin = try deleteBackup(primary, storage: backup, owner: backupOwner,
                                                    protecting: [(baseHome, base.mode), (home, target.mode)], validating: {
                    try validateRemoval(at: home)
                    try validateNative?()
                })
                try validateRemoval(at: home)
                try operation(target.validatingMutation(validateMutation))
                if retainsLogin { _ = try retainUnreadableBackup(backup, owner: backupOwner) }
            } catch {
                var recovered: AuthStorage$Codex.Record?
                if let activation {
                    let validateRollback = validateNative ?? {
                        try requirePublication(activation.published?.data, storage: base, owner: baseOwner)
                    }
                    do {
                        try validateRollback()
                        try restoreBackup(removedBackup, to: backup, owner: backupOwner, recovered: &recovered)
                        try startPrimaryRollback()
                        try rollbackPublication(activation.previous, storage: base, owner: baseOwner,
                                                validating: validateRollback)
                        route.restore()
                    } catch {
                        clearActiveRouting()
                        try exposeUnroutedBackup(backup, owner: backupOwner, removed: removedBackup,
                                                 published: activation.published, alreadyVisible: recovered)
                        finishPrimaryReturn()
                        throw error
                    }
                    finishPrimaryReturn()
                } else if let removedBackup {
                    try restoreBackup(removedBackup, to: backup, owner: backupOwner, recovered: &recovered)
                }
                throw error
            }
            UserDefaults.standard.removeObject(forKey: stashStoreKey)
            UserDefaults.standard.removeObject(forKey: stashHomeKey)
            UserDefaults.standard.removeObject(forKey: sourceAuthKey)
            if columnID == defaultColumnID {
                clearPrimarySession()
                rememberNativeGrant(nil, home: base.home.path)
            }
            if restore { finishPrimaryReturn() }
        } else {
            try validateRemoval(at: home)
            try operation(target.validatingMutation(validateMutation))
        }
        generations[key] = UUID()
        if !preservesSharedFile, let fileOwner { generations[fileOwner] = UUID() }
        if let columnID { columnGenerations[columnID] = UUID() }
        // The logical profile may have moved to another physical root while its
        // old request was in flight. Recovery retains its own separate owner.
        let retired = renewals.filter {
            if let recovery = renewalRecoveries[$0.value.id] {
                return recovery.removal.storage.home.path == target.home.path
            }
            return $0.key == key || $0.value.columnID == columnID
                || $0.value.storage.home.path == target.home.path
                || !preservesSharedFile && $0.value.record.backend == .file && $0.value.sourceKey == fileOwner
        }.map(\.key)
        for key in retired {
            generations[key] = UUID()
            if let renewal = renewals.removeValue(forKey: key) { renewalRecoveries[renewal.id] = nil }
        }
        if let columnID, columnID.hasPrefix(recoveredBackupIDPrefix) {
            var state = recoveredBackupState
            var entries = state["profiles"] as? [String: [String: String]] ?? [:]
            let id = String(columnID.dropFirst(recoveredBackupIDPrefix.count))
            // Removing the active file can leave a different login in Keychain.
            // Keep its ownership until the interrupted cleanup can be reconciled.
            if entries[id]?["returnedLogin"] == nil, entries[id]?["cleanupSource"] == nil,
               !entries.values.contains(where: { $0["cleanupSource"] == id }) {
                entries[id] = nil
            }
            state["profiles"] = entries
            UserDefaults.standard.set(state, forKey: recoveredBackupKey)
        }
    }

    /// Carry both publication and backup admission through unlink, Keychain
    /// deletion and completion. Shared fallbacks retain their independent owner.
    private static func deleteBackup(_ record: AuthStorage$Codex.Record?, storage backup: AuthStorage$Codex,
                                     owner: DirectoryIdentity?, protecting owners: [(home: URL, mode: AuthStorage$Codex.Mode)],
                                     validating publication: @escaping () throws -> Void) throws -> Bool {
        let shared = backup.mode != .file && fileIsShared(home: backup.home, fileHome: backup.home)
        let file = try backup.load(backend: .file)?.data
        let retainsFileLogin = backup.mode.usesKeyring && record?.backend != .file && file != nil
            && !AuthStorage$Codex.sameCredentials(file, record?.data)
        func validate(_ remaining: AuthStorage$Codex.Record?, fileRemoved: Bool) throws {
            // History or project metadata can change without replacing either login.
            let configured = try AuthStorage$Codex(home: backup.home)
            let includesKeyring = backup.mode.usesKeyring || configured.mode.usesKeyring
                || owners.contains { $0.mode.usesKeyring }
            try AuthStorage$Codex.validateMutation(homes: [stashHome] + owners.map { $0.home },
                                                   includesKeyring: includesKeyring, tracksDirectoryContents: false) {
                try publication()
                if fileRemoved && retainsFileLogin {
                    guard try backup.load(backend: .keyring) == nil,
                          try matchesLocation(backup, home: stashHome, owner: owner) else { throw Failure.busy }
                } else {
                    guard try checkedRecord(remaining, storage: backup, home: stashHome, owner: owner).matches else {
                        throw Failure.busy
                    }
                }
                // The pinned backup still owns the original login. A CLI
                // re-login can change modes and publish a different login.
                guard try configuredBackup(replacing: record, pinnedMode: backup.mode, at: configured) == nil,
                      try AuthStorage$Codex(home: backup.home).mode == configured.mode else { throw Failure.busy }
                if !shared {
                    let current = try backup.load(backend: .file)?.data
                    if fileRemoved && !retainsFileLogin {
                        guard current == nil else { throw Failure.busy }
                    } else {
                        guard current == file || current.flatMap(authIdentity) != nil
                            && current.flatMap(authIdentity) == file.flatMap(authIdentity) else { throw Failure.busy }
                    }
                }
                try publication()
                guard try matchesLocation(backup, home: stashHome, owner: owner) else { throw Failure.busy }
            }
        }
        try validate(record, fileRemoved: false)
        try backup.delete(preservingFile: retainsFileLogin, validating: { try validate(record, fileRemoved: false) }, afterFileRemoval: {
            try validate(record?.backend == .file ? nil : record, fileRemoved: true)
        })
        try validate(nil, fileRemoved: true)
        return retainsFileLogin || !backup.canRetireProfileDirectory()
    }

    private static func configuredBackup(replacing record: AuthStorage$Codex.Record?, pinnedMode: AuthStorage$Codex.Mode,
                                         at configured: AuthStorage$Codex) throws -> AuthStorage$Codex.Record? {
        guard configured.mode != pinnedMode,
              let replacement = try configured.load(verifyingOwner: true),
              replacement.backend != record?.backend else { return nil }
        return replacement
    }

    /// Keep primary durable before restoring the selected native account. A
    /// refusal at the old backup path must not discard it or skip native rollback.
    private static func restoreBackup(_ record: AuthStorage$Codex.Record?, to backup: AuthStorage$Codex,
                                       owner: DirectoryIdentity?, recovered: inout AuthStorage$Codex.Record?) throws {
        // Only adopt a readable replacement. If its secret is unavailable,
        // restore the captured backup without changing the current route.
        if (try? matchesLocation(backup, home: stashHome, owner: owner)) == true,
           let configured = try? AuthStorage$Codex(home: backup.home),
           let replacement = try? configuredBackup(replacing: record, pinnedMode: backup.mode, at: configured),
           (try? matchesLocation(backup, home: stashHome, owner: owner)) == true {
            if let record, !AuthStorage$Codex.sameCredentials(record.data, replacement.data) {
                let recovery = ProfileDirectories.codexRoot
                    .appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
                try saveRecoveredBackup(record, mode: backup.mode, at: recovery)
                recovered = record
            }
            try AuthStorage$Codex.validateMutation(homes: [stashHome], includesKeyring: configured.mode.usesKeyring,
                                                   tracksDirectoryContents: false) {
                guard try matchesLocation(backup, home: stashHome, owner: owner),
                      try AuthStorage$Codex(home: backup.home).mode == configured.mode else { throw Failure.busy }
                let current = try configured.load(verifyingOwner: true)
                guard current?.backend == replacement.backend,
                      AuthStorage$Codex.sameCredentials(current?.data, replacement.data),
                      try matchesLocation(backup, home: stashHome, owner: owner) else { throw Failure.busy }
            }
            // A successful retry must retain the backend we actually verified.
            // In auto mode the old file can coexist with the new Keychain item.
            UserDefaults.standard.set(configured.mode.rawValue, forKey: stashStoreKey)
            return
        }
        guard let record else { return }
        do {
            if let current = try backup.load(verifyingOwner: true) {
                if authIdentity(current.data) == authIdentity(record.data),
                   homeKey(stashHome) == backup.home.path, homeKey(backup.home) == backup.home.path { return }
                throw Failure.busy
            }
            guard try checkedRecord(nil, storage: backup, home: stashHome, owner: owner).matches else { throw Failure.busy }
            try backup.save(record.data, backend: record.backend, validating: {
                guard try checkedRecord(nil, storage: backup, home: stashHome, owner: owner).matches else { throw Failure.busy }
            })
        }
        catch {
            // Preserve a new primary's credentials and route. Its former login
            // remains discoverable in a separate managed recovery namespace.
            let replaced = (try? backup.load(verifyingOwner: true)) != nil
            let recovery = replaced
                ? ProfileDirectories.codexRoot.appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
                : DesktopApp.supportDirectory.appendingPathComponent("codex-app/recovery-" + UUID().uuidString, isDirectory: true)
            try saveRecoveredBackup(record, mode: backup.mode, at: recovery)
            if replaced { recovered = record }
            else { UserDefaults.standard.set(recovery.path, forKey: stashHomeKey) }
        }
    }

    /// Native routing now belongs to another login. Keep the removed snapshot
    /// and any independent backup login discoverable, once each.
    private static func exposeUnroutedBackup(_ backup: AuthStorage$Codex, owner: DirectoryIdentity?,
                                             removed: AuthStorage$Codex.Record?,
                                             published: AuthStorage$Codex.Record?,
                                             alreadyVisible: AuthStorage$Codex.Record?) throws {
        let observed: [AuthStorage$Codex.Record]
        var retainsUnreadableBackup = false
        do {
            let location = stashHome
            let current = try storage(at: location)
            guard current.home == backup.home else { throw Failure.busy }
            try requireStorage(current, home: location, owner: owner)
            let pinned = Result { try current.load(verifyingOwner: true) }
            // A CLI login can change config.toml and use a different store
            // while Notchlimits still has the backup's previous mode pinned.
            var configuredRecord: AuthStorage$Codex.Record?
            if let configured = try? AuthStorage$Codex(home: location), configured.home == current.home {
                let observed = configured.mode == current.mode ? pinned
                    : Result { try configured.load(verifyingOwner: true) }
                if let latest = try? AuthStorage$Codex(home: location),
                   latest.home == configured.home, latest.mode == configured.mode {
                    switch observed {
                    case .success(let record):
                        if configured.mode != current.mode { configuredRecord = record }
                    case .failure:
                        // A failed read cannot establish that this namespace is empty.
                        retainsUnreadableBackup = configured.mode.usesKeyring
                    }
                }
            }
            guard stashHome == location else { throw Failure.busy }
            try requireStorage(current, home: location, owner: owner)
            switch pinned {
            case .success(let record): observed = [record, configuredRecord].compactMap { $0 }
            case .failure: observed = [published, configuredRecord].compactMap { $0 }
            }
        } catch {
            retainsUnreadableBackup = false
            observed = [published].compactMap { $0 }
        }
        let retainedID = retainsUnreadableBackup ? try retainUnreadableBackup(backup, owner: owner) : nil
        let native = try? storage(at: baseHome)
        let nativeOwner = native.flatMap { DirectoryIdentity.capture($0.home) }
        var visible = [alreadyVisible].compactMap { $0?.data }
        for record in [removed].compactMap({ $0 }) + observed {
            guard !visible.contains(where: { AuthStorage$Codex.sameCredentials($0, record.data) }) else { continue }
            if let native, (try? requirePublication(record.data, storage: native, owner: nativeOwner)) != nil {
                continue
            }
            let recoveryRoot = retainedID == nil ? ProfileDirectories.codexRoot : defaultStashHome.deletingLastPathComponent()
            let recovery = recoveryRoot.appendingPathComponent("recovered-" + UUID().uuidString, isDirectory: true)
            try saveRecoveredBackup(record, mode: record.backend == .file ? .file : .keyring, at: recovery) {
                guard let retainedID else { return }
                let path = homeKey(recovery)
                guard let owner = try availableFileOwnerKey(URL(fileURLWithPath: path)) else { throw Failure.busy }
                var state = recoveredBackupState
                var entries = recoveredBackups
                entries[UUID().uuidString] = ["home": path, "owner": owner, "pendingOn": retainedID]
                state["profiles"] = entries
                UserDefaults.standard.set(state, forKey: recoveredBackupKey)
            }
            visible.append(record.data)
        }
    }

    private static func saveRecoveredBackup(_ record: AuthStorage$Codex.Record,
                                            mode: AuthStorage$Codex.Mode, at recovery: URL,
                                            beforeSave: () throws -> Void = {}) throws {
        try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try ("cli_auth_credentials_store = \"" + mode.rawValue + "\"\n")
            .write(to: recovery.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
        try beforeSave()
        try AuthStorage$Codex(home: recovery, mode: mode).save(record.data, backend: record.backend)
    }

    /// Logical columns can route to another physical owner, notably primary's
    /// backup. Fence the actual source/destination while its grant is in flight.
    private static func requireIdle(_ storage: AuthStorage$Codex) throws {
        for renewal in renewals.values {
            let destination = renewalRecoveries[renewal.id]?.removal.storage ?? renewal.storage
            if destination.home.path == storage.home.path { throw Failure.busy }
            guard let owner = fileOwnerKey(storage.home), owner == fileOwnerKey(destination.home) else { continue }
            // Keychain saves also remove auth.json. A pending file grant must
            // survive that cleanup; independent Keychain records remain separate.
            if try renewal.record.backend == .file || usesFile(storage) { throw Failure.busy }
        }
    }

    /// The native home must never receive a grant whose rotation is in flight,
    /// including a separate directory containing the same session.
    private static func requireIdleGrant(_ data: Data) throws {
        let grants = Set([refreshToken(data), refreshToken(forwarded(data))].compactMap { $0 })
        for renewal in renewals.values {
            let pending = authIdentity(renewal.record.data).flatMap { rotations[$0] }
            if [refreshToken(renewal.record.data), pending.flatMap(refreshToken)].compactMap({ $0 })
                .contains(where: grants.contains) { throw Failure.busy }
        }
    }

    /// Read only supported, available managed owners. Unknown profiles are not
    /// permission to write; a known copy retains its snapshot across read failures.
    private static func copyInventory() -> [SessionCopy] {
        var seen: Set<String> = []
        let homes = [stashHome] + ProfileDirectories.codexProfiles() + recoveredBackupHomes().map(\.home)
        return homes.compactMap { home in
            guard let source = try? storage(at: home), source.home.path != homeKey(baseHome),
                  let owner = DirectoryIdentity.capture(source.home),
                  let record = try? source.load(verifyingOwner: true),
                  owner.matches(source.home), !isDeferredReturnedCopy(record, at: source.home) else { return nil }
            if record.backend == .file, fileOwnerKey(source.home) == fileOwnerKey(baseHome) { return nil }
            let key = sourceKey(source, backend: record.backend)
            guard seen.insert(key).inserted else { return nil }
            return SessionCopy(storage: source, record: record, owner: owner,
                               sourceKey: key, generation: generations[key])
        }
    }

    private static func sessionCopies(of data: Data, excluding key: String) -> [SessionCopy] {
        guard let grant = refreshToken(data) else { return [] }
        return copyInventory().filter { $0.sourceKey != key && refreshToken($0.record.data) == grant }
    }

    private static func trackCopies(of data: Data) {
        guard let grant = refreshToken(data) else { return }
        for copy in copyInventory() where refreshToken(copy.record.data) == grant {
            knownCopies[copy.sourceKey] = copy
        }
    }

    /// Preserve each copy's account routing and metadata while advancing only
    /// the shared OAuth credentials. Never create another backend or a new file.
    private static func sessionUpdate(from fresh: Data, in original: Data) -> Data? {
        guard var root = (try? JSONSerialization.jsonObject(with: original)) as? [String: Any],
              var tokens = root["tokens"] as? [String: Any],
              let update = (try? JSONSerialization.jsonObject(with: fresh)) as? [String: Any],
              let next = update["tokens"] as? [String: Any] else { return nil }
        for key in ["access_token", "refresh_token", "id_token"] { tokens[key] = next[key] }
        root["tokens"] = tokens
        root["last_refresh"] = update["last_refresh"]
        return try? JSONSerialization.data(withJSONObject: root)
    }

    private static func rememberRotation(from old: Data, to fresh: Data) {
        guard Provider$Codex.parseAuth(old) != nil, Provider$Codex.parseAuth(fresh) != nil,
              let identity = authIdentity(old), let grant = refreshToken(old),
              let updated = sessionUpdate(from: fresh, in: old), authIdentity(updated) != identity else { return }
        let login = usageLoginLocked(old)
        for (key, value) in rotations where refreshToken(value) == grant {
            if let next = sessionUpdate(from: fresh, in: value) {
                if let nextIdentity = authIdentity(next), let nextLogin = usageLogins[key] ?? login {
                    rememberUsageLogin(nextLogin, identity: nextIdentity)
                }
                rotations[key] = next
            }
        }
        rotations[identity] = updated
        if let nextIdentity = authIdentity(updated), let login { rememberUsageLogin(login, identity: nextIdentity) }
    }

    /// Accepted rotations retain the usage epoch; an independent login does not.
    static func usageLogin(_ data: Data) -> UUID? {
        lock.lock()
        defer { lock.unlock() }
        return usageLoginLocked(data)
    }

    static func usageLogin(_ owner: LoginOwner) -> UUID? {
        lock.lock()
        defer { lock.unlock() }
        guard let identity = owner.authIdentity else { return nil }
        if let next = rotations[identity] { return usageLoginLocked(next) }
        if let login = usageLogins[identity] { return login }
        let login = UUID()
        rememberUsageLogin(login, identity: identity)
        return login
    }

    private static func usageLoginLocked(_ data: Data) -> UUID? {
        guard let identity = authIdentity(forwarded(data)) else { return nil }
        if let login = usageLogins[identity] { return login }
        let login = UUID()
        rememberUsageLogin(login, identity: identity)
        return login
    }

    private static func rememberUsageLogin(_ login: UUID, identity: String) {
        guard usageLogins[identity] != login else { return }
        usageLogins[identity] = login
        UserDefaults.standard.set(usageLogins.mapValues(\.uuidString), forKey: "codexUsageLogins")
    }

    private static func forwarded(_ data: Data) -> Data {
        var current = data
        var visited: Set<String> = []
        while let key = authIdentity(current), visited.insert(key).inserted,
              let next = rotations[key], let updated = sessionUpdate(from: next, in: current),
              authIdentity(updated) != key { current = updated }
        return current
    }

    private static func ownsDirectory(_ owner: DirectoryIdentity, at home: URL) throws -> Bool {
        if let current = DirectoryIdentity.capture(home) { return current == owner }
        if DirectoryIdentity.missingPath(home) != nil { return false }
        // An unreadable directory is not evidence of removal or replacement.
        throw Failure.busy
    }

    private static func ownsCopy(_ copy: SessionCopy) throws -> Bool {
        guard generations[copy.sourceKey] == copy.generation,
              !isDeferredReturnedCopy(copy.record, at: copy.storage.home) else { return false }
        if copy.record.backend == .keyring, homeKey(copy.storage.home) != copy.sourceKey { return false }
        let sameDirectory = try ownsDirectory(copy.owner, at: copy.storage.home)
        // Recreating a directory does not replace its native Keychain namespace.
        // Defer unavailable owners; persistence still verifies their credentials.
        return copy.record.backend == .keyring || sameDirectory
    }

    private static func isDeferredReturnedCopy(_ record: AuthStorage$Codex.Record, at home: URL) -> Bool {
        guard let login = authIdentity(record.data) else { return false }
        return recoveredBackups.values.contains { entry in
            entry["returnedLogin"] == login && entry["home"] == home.path && recoveredBackupHome(entry) == home
        }
    }

    /// Codex removal holds the swap lock. An exclusive rollback rename can
    /// authorize the restored file's new directory, unlike a copied login.
    static func recordRestoredFileOwner(from source: Int32, to destination: Int32) {
        var original = stat(), restored = stat()
        guard fstat(source, &original) == 0, fstat(destination, &restored) == 0,
              let oldKey = fileOwnerKey(original), let key = fileOwnerKey(restored),
              let previous = knownCopies[oldKey], previous.record.backend == .file,
              let owner = DirectoryIdentity.capture(descriptor: destination),
              let storage = try? AuthStorage$Codex(home: URL(fileURLWithPath: owner.path), mode: .file) else { return }
        knownCopies[key] = SessionCopy(storage: storage, record: previous.record, owner: owner,
                                      sourceKey: key, generation: generations[key])
    }

    /// Pending rotations retain their captured backend even after config edits.
    /// Check credentials after blocking preparation, then their physical binding.
    private static func matchesPinnedRecord(_ record: AuthStorage$Codex.Record,
                                            storage: AuthStorage$Codex, key: String) throws -> Bool {
        guard let current = try storage.load(backend: record.backend),
              authIdentity(current.data) == authIdentity(record.data) else { return false }
        return try record.backend == .file
            ? availableFileOwnerKey(storage.home) == key : homeKey(storage.home) == key
    }

    private static func persist(_ copy: SessionCopy, data: Data) throws {
        guard try ownsCopy(copy) else { return }
        guard let current = try copy.storage.load(backend: copy.record.backend) else { return }
        var stored = current.data
        if authIdentity(current.data) == authIdentity(copy.record.data) {
            guard let merged = sessionUpdate(from: data, in: current.data) else { throw Failure.busy }
            try copy.storage.save(merged, backend: current.backend, replacing: current, validating: {
                guard try matchesPinnedRecord(current, storage: copy.storage, key: copy.sourceKey),
                      try ownsCopy(copy) else { throw Failure.busy }
            })
            stored = merged
        } else if authIdentity(current.data) != authIdentity(data) { return }
        knownCopies[copy.sourceKey] = SessionCopy(storage: copy.storage,
            record: AuthStorage$Codex.Record(data: stored, backend: current.backend), owner: copy.owner,
            sourceKey: copy.sourceKey, generation: copy.generation)
    }

    private static func persist(_ copy: SessionCopy, tokens: OAuth$Codex.Tokens,
                                usedRefreshToken: String) throws {
        guard let data = renewedAuth(copy.record.data, usedRefreshToken: usedRefreshToken,
                                     tokens: tokens, now: Date()) else { return }
        rememberRotation(from: copy.record.data, to: data)
        do {
            try persist(copy, data: data)
            copyDebt[copy.sourceKey] = nil
        } catch {
            copyDebt[copy.sourceKey] = copy
            throw error
        }
    }

    private static func reconcile(_ source: AuthStorage$Codex,
                                  record: AuthStorage$Codex.Record) throws -> AuthStorage$Codex.Record {
        let data = forwarded(record.data)
        guard authIdentity(data) != authIdentity(record.data),
              let owner = DirectoryIdentity.capture(source.home) else { return record }
        let key = sourceKey(source, backend: record.backend)
        // File copies retain their physical directory; Keychain copies retain
        // their native namespace. Neither may republish a known spent grant.
        guard let known = knownCopies[key], known.record.backend == record.backend,
              try ownsCopy(known) else { throw Failure.busy }
        let copy = SessionCopy(storage: source, record: record, owner: owner,
                               sourceKey: key, generation: generations[key])
        do {
            try persist(copy, data: data)
            copyDebt[key] = nil
        } catch {
            copyDebt[key] = copy
            throw error
        }
        // A newer login observed at the write boundary owns the subsequent read.
        return try source.load(verifyingOwner: true) ?? record
    }

    private static func synchronizeCopies(from old: Data? = nil, to fresh: Data) throws {
        var failure: Error?
        for copy in Array(knownCopies.values) {
            if let old, let grant = refreshToken(old), refreshToken(copy.record.data) == grant {
                rememberRotation(from: copy.record.data, to: fresh)
            }
            let data = forwarded(copy.record.data)
            guard authIdentity(data) != authIdentity(copy.record.data),
                  refreshToken(data) == refreshToken(fresh),
                  Provider$Codex.parseAuth(data)?.accessToken == Provider$Codex.parseAuth(fresh)?.accessToken else { continue }
            do {
                try persist(copy, data: data)
                copyDebt[copy.sourceKey] = nil
            } catch {
                copyDebt[copy.sourceKey] = copy
                failure = error
            }
        }
        if let failure { throw failure }
    }

    private static func hasUnwrittenCopies(_ renewal: Renewal) throws -> Bool {
        let accepted = authIdentity(renewal.record.data).flatMap { rotations[$0] } != nil
        for copy in renewal.copies {
            guard try ownsCopy(copy) else { continue }
            if let current = try copy.storage.load(backend: copy.record.backend),
               authIdentity(current.data) == authIdentity(copy.record.data),
               !accepted || authIdentity(forwarded(current.data)) != authIdentity(current.data) { return true }
        }
        return false
    }

    private static func grantIdentity(_ data: Data) -> String? {
        refreshToken(data).map { SHA256.hash(data: Data($0.utf8)).map { String(format: "%02x", $0) }.joined() }
    }

    private static func primaryAccountOwner(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tokens = root["tokens"] as? [String: Any], let account = accountID(data) else { return nil }
        for name in ["id_token", "access_token"] {
            if let token = tokens[name] as? String, let claims = JWT.claims(token),
               let issuer = claims["iss"] as? String, let subject = claims["sub"] as? String,
               !issuer.isEmpty, !subject.isEmpty,
               let identity = try? JSONEncoder().encode([account, issuer, subject]) {
                return SHA256.hash(data: identity).map { String(format: "%02x", $0) }.joined()
            }
        }
        return nil
    }

    private static func nativeGrantProof(_ data: Data?, home: String) -> [String: String]? {
        guard let data, let grant = grantIdentity(data), let account = accountID(data) else { return nil }
        var proof = ["home": home, "account": account, "grant": grant]
        proof["owner"] = primaryAccountOwner(data)
        return proof
    }

    private static func sameAccount(_ left: Data, _ right: Data) -> Bool {
        if AuthStorage$Codex.sameCredentials(left, right) { return true }
        guard let account = accountID(left), account == accountID(right) else { return false }
        return primaryAccountOwner(left) == primaryAccountOwner(right)
    }

    /// Intentional handoff releases an unchanged grant to its sleeping profile.
    /// Normal termination must flush the new native owner before a restart.
    private static func rememberNativeGrant(_ data: Data?, home: String) {
        let proof = nativeGrantProof(data, home: home)
        guard UserDefaults.standard.dictionary(forKey: nativeGrantKey) as? [String: String] != proof else { return }
        UserDefaults.standard.set(proof, forKey: nativeGrantKey)
        nativeGrantsDirty = true
    }

    private static func nativeGrantOwner(home: String) throws -> [String: String]? {
        if let value = UserDefaults.standard.object(forKey: nativeGrantKey) {
            guard let proof = value as? [String: String], proof["home"] != nil,
                  proof["account"] != nil, proof["grant"]?.count == 64 else { throw Failure.busy }
            return proof
        }
        // Upgrade existing selections without making credential identity or
        // physical copy ownership the authority to spend a native grant.
        if !isSwapped {
            return UserDefaults.standard.dictionary(forKey: primarySessionKey) as? [String: String]
        }
        if let path = activeOwnerPath,
           let selected = try storage(at: URL(fileURLWithPath: path)).load(verifyingOwner: true),
           let identity = authIdentity(selected.data), try sourceProof()?.ownsSelected(identity) == true {
            return nativeGrantProof(selected.data, home: home)
        }
        return nil
    }

    private static func retiredNativeGrants() throws -> Set<String> {
        guard let value = UserDefaults.standard.object(forKey: retiredNativeGrantsKey) else { return [] }
        guard let grants = value as? [String] else { throw Failure.busy }
        return Set(grants)
    }

    private static func retireNativeGrant(_ grant: String) throws {
        var retired = try retiredNativeGrants()
        if retired.insert(grant).inserted {
            UserDefaults.standard.set(retired.sorted(), forKey: retiredNativeGrantsKey)
            nativeGrantsDirty = true
        }
    }

    /// Native rotation retires the grant itself, including unobserved copies
    /// and copies with another account routing or a replaced file directory.
    private static func observeNativeGrant(_ data: Data?, home: String) throws {
        if let current = nativeGrantProof(data, home: home), let previous = try nativeGrantOwner(home: home) {
            var observed: [String: String]? = current
            if let formerHome = previous["home"], formerHome != home {
                // A file alias can still expose the same native rotation, while
                // Keychain aliases have independent native namespaces.
                let former = try AuthStorage$Codex(home: URL(fileURLWithPath: formerHome))
                observed = nil
                if former.home.path == formerHome {
                    let record = try former.load(verifyingOwner: true)
                    guard homeKey(former.home) == formerHome else { throw Failure.busy }
                    observed = nativeGrantProof(record?.data, home: formerHome)
                }
            }
            if let grant = previous["grant"], observed == nil
                || previous["home"] == observed?["home"] && previous["account"] == observed?["account"]
                    && previous["owner"] == observed?["owner"]
                    && grant != observed?["grant"] {
                try retireNativeGrant(grant)
            }
        }
        if data != nil { rememberNativeGrant(data, home: home) }
        try flushNativeGrants()
    }

    private static func nativeOwnsOrRetired(_ data: Data) throws -> Bool {
        guard let grant = grantIdentity(data) else { return false }
        if try retiredNativeGrants().contains(grant) { return true }
        let owner = try nativeGrantOwner(home: homeKey(baseHome))
        return owner?["home"] == homeKey(baseHome) && owner?["grant"] == grant
    }

    private static func flushNativeGrants() throws {
        guard nativeGrantsDirty else { return }
        guard UserDefaults.standard.synchronize() else { throw Failure.busy }
        nativeGrantsDirty = false
    }

    private static func rememberPrimarySession(_ data: Data, grant: String? = nil, accountOwner: String? = nil) {
        guard let grant = grant ?? grantIdentity(data), let account = accountID(data) else {
            UserDefaults.standard.removeObject(forKey: primarySessionKey)
            return
        }
        // Only a grant digest, account routing and canonical home survive restart.
        var proof = ["home": homeKey(baseHome), "account": account, "grant": grant]
        proof["owner"] = accountOwner ?? primaryAccountOwner(data)
        UserDefaults.standard.set(proof, forKey: primarySessionKey)
    }

    private static func clearPrimarySession() {
        primarySession = nil
        UserDefaults.standard.removeObject(forKey: primarySessionKey)
    }

    /// Returning to primary transfers the shared session back to native clients.
    /// Keep its observed copies attached to that owner after native rotation too.
    @discardableResult
    private static func advancePrimaryCopies(matching data: Data? = nil) throws -> Bool {
        guard !isSwapped else { return false }
        let proof = UserDefaults.standard.dictionary(forKey: primarySessionKey) as? [String: String]
        if primarySession == nil,
           let proof,
           proof["home"] == homeKey(baseHome),
           data == nil || data.flatMap(grantIdentity) == proof["grant"],
           let copy = copyInventory().first(where: { grantIdentity($0.record.data) == proof["grant"] }),
           let native = try storage(at: baseHome).load(verifyingOwner: true),
           accountID(native.data) == proof["account"],
           sameAccount(native.data, copy.record.data),
           proof["owner"] == nil || primaryAccountOwner(native.data) == proof["owner"],
           let baseline = sessionUpdate(from: copy.record.data, in: native.data),
           let owner = DirectoryIdentity.capture(baseHome) {
            primarySession = (baseline, owner, generations[homeKey(baseHome)])
            trackCopies(of: copy.record.data)
        }
        guard let primary = primarySession else { return false }
        let baseline = forwarded(primary.data)
        if let data, refreshToken(data) != refreshToken(primary.data),
           refreshToken(data) != refreshToken(baseline) { return false }
        guard primary.owner.matches(baseHome), generations[homeKey(baseHome)] == primary.generation else {
            clearPrimarySession()
            return false
        }
        guard try knownCopies.values.contains(where: {
            guard refreshToken($0.record.data) == refreshToken(baseline) else { return false }
            return try ownsCopy($0)
        }) else { return false }
        guard let native = try storage(at: baseHome).load(verifyingOwner: true),
              sameAccount(native.data, primary.data),
              proof?["owner"] == nil || primaryAccountOwner(native.data) == proof?["owner"] else {
            clearPrimarySession()
            return false
        }
        rememberRotation(from: baseline, to: native.data)
        try synchronizeCopies(from: baseline, to: native.data)
        primarySession = (native.data, primary.owner, primary.generation)
        rememberPrimarySession(native.data)
        return true
    }

    /// A known copy cannot be left with a spent grant on normal termination.
    /// Refresh the selected native lineage before draining deferred copy writes.
    static func flushCopies() throws {
        lock.lock()
        defer { lock.unlock() }
        try advancePrimaryCopies()
        if !rotations.isEmpty, isSwapped, let path = activeOwnerPath,
           let selected = try? storage(at: URL(fileURLWithPath: path)).load(verifyingOwner: true),
           rotations.values.contains(where: { refreshToken($0) == refreshToken(selected.data) }),
           let native = try storage(at: baseHome).load(verifyingOwner: true),
           accountID(native.data) == accountID(selected.data),
           let identity = authIdentity(selected.data), try sourceProof()?.ownsSelected(identity) == true,
           authIdentity(native.data) != identity { _ = try giveBackCurrent() }
        for (key, copy) in Array(copyDebt) {
            try persist(copy, data: forwarded(copy.record.data))
            copyDebt[key] = nil
        }
        for data in Array(rotations.values) { try synchronizeCopies(to: data) }
        try flushNativeGrants()
    }

    private static func storage(at home: URL) throws -> AuthStorage$Codex {
        if home.standardizedFileURL == stashHome.standardizedFileURL {
            guard let saved = UserDefaults.standard.string(forKey: stashStoreKey) else {
                return try AuthStorage$Codex(home: home)
            }
            guard let mode = AuthStorage$Codex.Mode(rawValue: saved) else { throw AuthStorage$Codex.Failure.settings }
            return try AuthStorage$Codex(home: home, mode: mode)
        }
        return try AuthStorage$Codex(home: home)
    }

    private static func accountID(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tokens = root["tokens"] as? [String: Any] else { return nil }
        return tokens["account_id"] as? String
    }

    /// Persist only a digest of the source session, never credentials in defaults.
    /// Native metadata updates do not constitute another login.
    static func authIdentity(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let fields = ["auth_mode", "tokens", "OPENAI_API_KEY"]
        let auth = root.filter { fields.contains($0.key) }
        guard !auth.isEmpty, let canonical = try? JSONSerialization.data(withJSONObject: auth, options: [.sortedKeys]) else { return nil }
        return SHA256.hash(data: canonical).map { String(format: "%02x", $0) }.joined()
    }
}
