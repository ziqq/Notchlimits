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

    /// Перестановка входов и запись продлённых токенов не должны пересечься:
    /// иначе в `~/.codex` уедет уже потраченный refresh-токен.
    private static let lock = NSLock()
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
    }
    struct AuthSnapshot {
        let data: Data
        let key: String
        let generation: UUID?
        let columnGeneration: UUID?
        let sourceKey: String
        let sourceGeneration: UUID?
    }
    private static var generations: [String: UUID] = [:]
    private static var columnGenerations: [String: UUID] = [:]
    private static var renewals: [String: Renewal] = [:]

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
        var info = stat()
        guard home.path.withCString({ Darwin.lstat($0, &info) }) == 0,
              info.st_mode & S_IFMT == S_IFDIR else { return nil }
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
        guard renewals[homeKey(home)] == nil,
              !renewals.values.contains(where: { $0.columnID == columnID || $0.columnID == activeColumnID }) else {
            throw Failure.busy
        }
        let incoming = columnID == defaultColumnID ? stashHome : home
        let source = try storage(at: incoming)
        try requireIdle(base)
        try requireIdle(source)
        let incomingRecord = try source.load(verifyingOwner: true)
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
        if columnID == defaultColumnID { payload = try source.load(verifyingOwner: true)?.data }
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
        guard renewals[key] == nil else { throw Failure.busy }
        let live = liveHome(columnID: columnID, home: home)
        guard !isBaseHome(live) else { return nil }
        let source = try storage(at: live)
        try requireIdle(source)
        // Usage may read a native auto fallback, but a refresh must not spend
        // its stale grant while the preferred Keychain owner is unavailable.
        guard let record = try source.load(verifyingOwner: true) else { return nil }
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
        let renewal = Renewal(columnID: columnID, key: key, generation: generations[key],
                              columnGeneration: columnGenerations[columnID],
                              sourceKey: sourceKey, sourceGeneration: generations[sourceKey],
                              storage: source, record: record)
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
    }

    /// Retry only the backend that supplied the submitted refresh grant. In auto
    /// mode a temporary Keychain error must not turn a file fallback into a re-login.
    @discardableResult
    static func storeRenewed(_ renewal: Renewal, usedRefreshToken: String,
                             tokens: OAuth$Codex.Tokens) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = renewal.key
        guard generations[key] == renewal.generation,
              columnGenerations[renewal.columnID] == renewal.columnGeneration,
              generations[renewal.sourceKey] == renewal.sourceGeneration,
              renewals[key]?.id == renewal.id else { return false }
        let destination = renewal.storage
        guard sourceKey(destination, backend: renewal.record.backend) == renewal.sourceKey else { return false }
        guard let record = try destination.load(backend: renewal.record.backend) else { return false }
        guard let updated = renewedAuth(record.data, usedRefreshToken: usedRefreshToken,
                                       tokens: tokens, now: Date()) else { return false }
        try destination.save(updated, backend: record.backend)
        return true
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
                           requireIncomplete: Bool = false,
                           operation: (AuthStorage$Codex) throws -> Void = { try $0.delete() }) throws {
        lock.lock()
        defer { lock.unlock() }
        let key = homeKey(home)
        let target = try storage(at: home)
        guard target.home.path == key, homeKey(home) == key else { throw Failure.busy }
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
        } else {
            try operation(target)
        }
        generations[key] = UUID()
        if !preservesSharedFile, let fileOwner { generations[fileOwner] = UUID() }
        if let columnID { columnGenerations[columnID] = UUID() }
        renewals[key] = nil
        // The logical profile may have moved to another physical root while its
        // old request was in flight. Successful removal retires that owner too.
        let retired = renewals.filter {
            $0.value.columnID == columnID || $0.value.storage.home.path == target.home.path
                || !preservesSharedFile && $0.value.record.backend == .file && $0.value.sourceKey == fileOwner
        }.map(\.key)
        for key in retired {
            generations[key] = UUID()
            renewals[key] = nil
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
            if renewal.storage.home.path == storage.home.path { throw Failure.busy }
            guard let owner = fileOwnerKey(storage.home), owner == fileOwnerKey(renewal.storage.home) else { continue }
            // Keychain saves also remove auth.json. A pending file grant must
            // survive that cleanup; independent Keychain records remain separate.
            if try renewal.record.backend == .file || usesFile(storage) { throw Failure.busy }
        }
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
    private static func authIdentity(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let fields = ["auth_mode", "tokens", "OPENAI_API_KEY"]
        let auth = root.filter { fields.contains($0.key) }
        guard !auth.isEmpty, let canonical = try? JSONSerialization.data(withJSONObject: auth, options: [.sortedKeys]) else { return nil }
        return SHA256.hash(data: canonical).map { String(format: "%02x", $0) }.joined()
    }
}
