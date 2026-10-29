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
    private static let sourceAuthKey = "codexAppSourceAuth"
    private static let primarySessionKey = "codexAppPrimarySession"

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
    private static var knownCopies: [String: SessionCopy] = [:]
    private static var copyDebt: [String: SessionCopy] = [:]
    private static var primarySession: (data: Data, owner: DirectoryIdentity, generation: UUID?)?

    /// Базовый CODEX_HOME: его берут голая `codex` и приложение.
    static var baseHome: URL {
        ProcessInfo.processInfo.environment["CODEX_HOME"].map { URL(fileURLWithPath: $0) }
            ?? ProfileDirectories.home.appendingPathComponent(".codex")
    }

    /// Куда убран вход основного аккаунта, пока в `~/.codex` чужой.
    static var stashHome: URL {
        if let path = UserDefaults.standard.string(forKey: stashHomeKey) {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        return DesktopApp.supportDirectory.appendingPathComponent("codex-app/default", isDirectory: true)
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

    /// Polling follows the routed credentials; removal owns the profile itself.
    /// Capture routing and physical identity together, including backup recovery.
    static func usageOwner(columnID: String, home: URL) -> UsageOwner {
        lock.lock()
        defer { lock.unlock() }
        let path = homeKey(liveHome(columnID: columnID, home: home))
        return UsageOwner(path: path, directory: DirectoryIdentity.capture(URL(fileURLWithPath: path)))
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
    static func containsPrimaryBackup(_ url: URL) -> Bool {
        let candidate = URL(fileURLWithPath: homeKey(url))
        var backup = URL(fileURLWithPath: homeKey(stashHome))
        let prefix = candidate.path.hasSuffix("/") ? candidate.path : candidate.path + "/"
        if backup.path == candidate.path || backup.path.hasPrefix(prefix) { return true }
        guard let owner = fileOwnerKey(candidate) else { return false }
        while backup.path != "/" {
            if owner == fileOwnerKey(backup) { return true }
            backup.deleteLastPathComponent()
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
        var homes = [baseHome, stashHome] + entries.map {
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
    static func activate(columnID: String, home: URL) throws {
        lock.lock()
        defer { lock.unlock() }
        _ = try activateLocked(columnID: columnID, home: home)
    }

    private static func activateLocked(columnID: String, home: URL,
                                       keepBackup: Bool = false) throws -> AuthStorage$Codex.Record? {
        let base = try storage(at: baseHome)
        guard base.mode != .ephemeral else { throw AuthStorage$Codex.Failure.ephemeral }
        guard columnID == defaultColumnID || !isBaseHome(home) else { throw Failure.busy }
        guard columnID != activeColumnID else { return nil }
        guard !renewals.values.contains(where: {
            renewalRecoveries[$0.id] == nil
                && ($0.key == homeKey(home) || $0.columnID == columnID || $0.columnID == activeColumnID)
        }) else {
            throw Failure.busy
        }
        let incoming = columnID == defaultColumnID ? stashHome : home
        let source = try storage(at: incoming)
        try requireIdle(base)
        try requireIdle(source)
        var incomingRecord = try source.load(verifyingOwner: true)
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
        guard columnID == defaultColumnID || payload != nil else { throw Failure.missingAuth }
        try FileManager.default.createDirectory(at: baseHome, withIntermediateDirectories: true)
        let previous = try giveBackCurrent()
        // Copyback can advance a primary backup that shared the selected grant.
        // Publish that updated record instead of its pre-copyback token snapshot.
        incomingRecord = try source.load(verifyingOwner: true)
        if let record = incomingRecord {
            try requireIdleGrant(record.data)
            incomingRecord = try reconcile(source, record: record)
        }
        guard homeKey(incoming) == source.home.path else { throw Failure.busy }
        payload = incomingRecord?.data
        if let payload { try base.save(payload) } else { try base.delete() }
        if columnID == defaultColumnID {
            // Do not forget a refused backup cleanup or report a completed switch.
            if !keepBackup {
                do { try source.delete() } catch {
                    try base.restore(previous)
                    throw error
                }
            }
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
        } else {
            UserDefaults.standard.set(columnID, forKey: activeIDKey)
            UserDefaults.standard.set(home.path, forKey: activeHomeKey)
            UserDefaults.standard.set(source.home.path, forKey: activePhysicalHomeKey)
            UserDefaults.standard.set(payload.flatMap(authIdentity), forKey: sourceAuthKey)
        }
        return previous
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
        let key = homeKey(home)
        if let expected, expected.key != key || expected.generation != generations[key]
            || expected.columnGeneration != columnGenerations[columnID] { return nil }
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
        let nativeStorage = try storage(at: baseHome)
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
                              copies: sessionCopies(of: record.data, excluding: sourceKey))
        renewals[key] = renewal
        return renewal
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
        let currentKey = try renewal.record.backend == .file
            ? availableFileOwnerKey(destination.home) : destination.home.path
        guard currentKey == destinationKey else { return nil }
        var failure: Error?
        for copy in renewal.copies {
            do { try persist(copy, tokens: tokens, usedRefreshToken: usedRefreshToken) }
            catch { failure = error }
        }
        var updated: Data?
        do {
            if let record = try destination.load(backend: renewal.record.backend) {
                if authIdentity(record.data) == authIdentity(projected) {
                    updated = record.data
                } else if authIdentity(record.data) == authIdentity(renewal.record.data),
                          let data = renewedAuth(record.data, usedRefreshToken: usedRefreshToken,
                                                 tokens: tokens, now: Date()) {
                    try destination.save(data, backend: record.backend)
                    updated = data
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

    /// Вход, что сейчас в `~/.codex`, — обратно владельцу.
    private static func giveBackCurrent() throws -> AuthStorage$Codex.Record? {
        let live = try storage(at: baseHome)
        let record = try live.load(verifyingOwner: true)
        let payload = record?.data
        if !isSwapped {
            try advancePrimaryCopies()
            if let payload { trackCopies(of: payload) }
            try FileManager.default.createDirectory(at: stashHome, withIntermediateDirectories: true)
            let stash = try AuthStorage$Codex(home: stashHome, mode: live.mode)
            try requireIdle(stash)
            if let payload { try stash.save(payload) } else { try stash.delete() }
            // A CLI re-login into our internal backup must use that same backend.
            try ("cli_auth_credentials_store = \"" + live.mode.rawValue + "\"\n")
                .write(to: stashHome.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
            UserDefaults.standard.set(live.mode.rawValue, forKey: stashStoreKey)
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
        if let profile, profile.home.path == physical,
           let previous = try profile.load(verifyingOwner: true)?.data,
           accountID(payload) == accountID(previous),
           let identity = authIdentity(previous),
           proof?.ownsSelected(identity) ?? (identity == authIdentity(payload)) {
            try requireIdle(profile)
            let backup = try storage(at: stashHome)
            let primary = try backup.load(verifyingOwner: true)
            let backupIdentity = primary.flatMap { authIdentity($0.data) }
            if proof?.isPending == true {
                guard let backupIdentity, proof?.ownsBackup(backupIdentity) == true else { throw Failure.busy }
            }
            let originalRefresh = refreshToken(previous)
            let sameGrant = originalRefresh != nil && primary.flatMap { refreshToken($0.data) } == originalRefresh
            if proof?.isPending == true || sameGrant {
                // These are copies of one proven session, rather than separate
                // sessions of the same account. Preserve its native rotation in
                // the primary backup before advancing the selected baseline.
                guard let backupIdentity, let intended = authIdentity(payload) else { throw Failure.busy }
                try requireIdle(backup)
                UserDefaults.standard.set([identity, backupIdentity, intended], forKey: sourceAuthKey)
                try backup.save(payload)
            }
            try profile.save(payload)
            UserDefaults.standard.set(authIdentity(payload), forKey: sourceAuthKey)
            rememberRotation(from: previous, to: payload)
            try synchronizeCopies(from: previous, to: payload)
        } else {
            guard proof?.isPending != true else { throw Failure.busy }
            // Retain an unexpected native login without exporting a Keychain login to plaintext.
            let orphan = stashHome.deletingLastPathComponent().appendingPathComponent("orphaned-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: orphan, withIntermediateDirectories: true)
            try ("cli_auth_credentials_store = \"" + live.mode.rawValue + "\"\n")
                .write(to: orphan.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
            try AuthStorage$Codex(home: orphan, mode: live.mode).save(payload)
        }
        return record
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
                           operation: (AuthStorage$Codex) throws -> Void = { try $0.delete() }) throws {
        lock.lock()
        defer { lock.unlock() }
        let key = homeKey(home)
        let target = try storage(at: home)
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
        guard !containsPrimaryBackup(target.home)
            || columnID == defaultColumnID && isBaseHome(target.home) else { throw Failure.busy }
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
            let backup = try storage(at: stashHome)
            try requireRemovalOwners(backup)
            try requireIdle(base)
            try requireIdle(backup)
            let keys = [activeIDKey, activeHomeKey, activePhysicalHomeKey]
            let saved = keys.map { UserDefaults.standard.object(forKey: $0) }
            // Restore primary credentials before removing their backup. A
            // refused cleanup must precede destructive profile deletion.
            let selected = restore ? try activateLocked(columnID: defaultColumnID, home: baseHome, keepBackup: true) : nil
            var removedBackup: AuthStorage$Codex.Record?
            do {
                let primary = try backup.load(verifyingOwner: true)
                try backup.delete()
                removedBackup = primary
                try operation(target)
            } catch {
                if let primary = removedBackup { try restoreBackup(primary, to: backup) }
                if restore {
                    try base.restore(selected)
                    for (name, value) in zip(keys, saved) {
                        if let value { UserDefaults.standard.set(value, forKey: name) }
                        else { UserDefaults.standard.removeObject(forKey: name) }
                    }
                }
                throw error
            }
            UserDefaults.standard.removeObject(forKey: stashStoreKey)
            UserDefaults.standard.removeObject(forKey: stashHomeKey)
            UserDefaults.standard.removeObject(forKey: sourceAuthKey)
            if columnID == defaultColumnID { clearPrimarySession() }
        } else {
            try operation(target)
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
    }

    /// Keep primary durable before restoring the selected native account. A
    /// refusal at the old backup path must not discard it or skip native rollback.
    private static func restoreBackup(_ record: AuthStorage$Codex.Record, to backup: AuthStorage$Codex) throws {
        do { try backup.save(record.data, backend: record.backend) }
        catch {
            let recovery = DesktopApp.supportDirectory.appendingPathComponent("codex-app/recovery-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: recovery, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            try ("cli_auth_credentials_store = \"" + backup.mode.rawValue + "\"\n")
                .write(to: recovery.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
            try AuthStorage$Codex(home: recovery, mode: backup.mode).save(record.data, backend: record.backend)
            // Discovery, renewal and CLI re-login use the recovered primary too.
            UserDefaults.standard.set(recovery.path, forKey: stashHomeKey)
        }
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
        return ([stashHome] + ProfileDirectories.codexProfiles()).compactMap { home in
            guard let source = try? storage(at: home), source.home.path != homeKey(baseHome),
                  let owner = DirectoryIdentity.capture(source.home),
                  let record = try? source.load(verifyingOwner: true),
                  owner.matches(source.home) else { return nil }
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
        for (key, value) in rotations where refreshToken(value) == grant {
            if let next = sessionUpdate(from: fresh, in: value) { rotations[key] = next }
        }
        rotations[identity] = updated
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
        guard generations[copy.sourceKey] == copy.generation else { return false }
        return try ownsDirectory(copy.owner, at: copy.storage.home)
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

    private static func persist(_ copy: SessionCopy, data: Data) throws {
        guard try ownsCopy(copy) else { return }
        guard let current = try copy.storage.load(backend: copy.record.backend) else { return }
        var stored = current.data
        if authIdentity(current.data) == authIdentity(copy.record.data) {
            guard let merged = sessionUpdate(from: data, in: current.data) else { throw Failure.busy }
            try copy.storage.save(merged, backend: current.backend)
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
        // An identical login in a replacement directory does not authorize an
        // earlier request to write there. Never republish its known spent grant.
        guard let known = knownCopies[key], known.owner == owner,
              known.generation == generations[key] else { throw Failure.busy }
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

    private static func rememberPrimarySession(_ data: Data) {
        guard let grant = grantIdentity(data), let account = accountID(data) else {
            UserDefaults.standard.removeObject(forKey: primarySessionKey)
            return
        }
        // Only a grant digest, account routing and canonical home survive restart.
        UserDefaults.standard.set(["home": homeKey(baseHome), "account": account, "grant": grant],
                                  forKey: primarySessionKey)
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
        if primarySession == nil,
           let proof = UserDefaults.standard.dictionary(forKey: primarySessionKey) as? [String: String],
           proof["home"] == homeKey(baseHome),
           data == nil || data.flatMap(grantIdentity) == proof["grant"],
           let copy = copyInventory().first(where: { grantIdentity($0.record.data) == proof["grant"] }),
           let native = try storage(at: baseHome).load(verifyingOwner: true),
           accountID(native.data) == proof["account"],
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
        guard knownCopies.values.contains(where: {
            refreshToken($0.record.data) == refreshToken(baseline)
                && $0.owner.matches($0.storage.home) && generations[$0.sourceKey] == $0.generation
        }) else { return false }
        guard let native = try storage(at: baseHome).load(verifyingOwner: true),
              accountID(native.data) == accountID(primary.data) else {
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
