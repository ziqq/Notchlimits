import Foundation

/// Keep Desktop and CLI on the base CODEX_HOME while swapping only credentials.
/// Projects and threads stay in place. The primary account waits in an internal
/// backup using its original backend; native token changes return to the selected
/// profile's backend before the next switch. liveHome keeps column identities stable.
enum CodexAuthSwap {

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
    private static let stashStoreKey = "codexAppStashStore"

    /// Перестановка входов и запись продлённых токенов не должны пересечься:
    /// иначе в `~/.codex` уедет уже потраченный refresh-токен.
    private static let lock = NSLock()
    struct Renewal {
        let id = UUID()
        let columnID: String
        let key: String
        let generation: UUID?
        let storage: CodexAuthStorage
        let record: CodexAuthStorage.Record
    }
    private static var generations: [String: UUID] = [:]
    private static var renewals: [String: Renewal] = [:]

    /// Базовый CODEX_HOME: его берут голая `codex` и приложение.
    static var baseHome: URL {
        ProcessInfo.processInfo.environment["CODEX_HOME"].map { URL(fileURLWithPath: $0) }
            ?? ProfileDirectories.home.appendingPathComponent(".codex")
    }

    /// Куда убран вход основного аккаунта, пока в `~/.codex` чужой.
    static var stashHome: URL {
        DesktopApp.supportDirectory.appendingPathComponent("codex-app/default", isDirectory: true)
    }

    /// Колонка, чей вход сейчас в `~/.codex`.
    static var activeColumnID: String {
        guard let id = UserDefaults.standard.string(forKey: activeIDKey) else { return defaultColumnID }
        // The saved path identifies the owner even when its legacy ID collided.
        if let path = UserDefaults.standard.string(forKey: activeHomeKey) {
            let name = URL(fileURLWithPath: path).lastPathComponent
            if name.hasPrefix("profile:"), id == "codex:\(name)" {
                return profileColumnID(name)
            }
        }
        return id
    }

    static var isSwapped: Bool { activeColumnID != defaultColumnID }

    /// Папка, где сейчас лежит `auth.json` колонки (`home` — её собственная).
    static func liveHome(columnID: String, home: URL) -> URL {
        guard isSwapped else { return home }
        if columnID == activeColumnID { return baseHome }
        if columnID == defaultColumnID { return stashHome }
        return home
    }

    static func isBaseHome(_ url: URL) -> Bool {
        homeKey(url) == homeKey(baseHome)
    }

    private static func homeKey(_ home: URL) -> String { home.resolvingSymlinksInPath().path }

    /// Положить в `~/.codex` вход колонки. Приложение должно быть закрыто.
    static func activate(columnID: String, home: URL) throws {
        lock.lock()
        defer { lock.unlock() }
        let base = try storage(at: baseHome)
        guard base.mode != .ephemeral else { throw CodexAuthStorage.Failure.ephemeral }
        guard columnID != activeColumnID else { return }
        guard renewals[homeKey(home)] == nil,
              !renewals.values.contains(where: { $0.columnID == columnID || $0.columnID == activeColumnID }) else {
            throw Failure.busy
        }
        let incoming = columnID == defaultColumnID ? stashHome : home
        let payload = try storage(at: incoming).load()?.data
        guard columnID == defaultColumnID || payload != nil else { throw Failure.missingAuth }
        try FileManager.default.createDirectory(at: baseHome, withIntermediateDirectories: true)
        try giveBackCurrent()
        if let payload { try base.save(payload) } else { try base.delete() }
        if columnID == defaultColumnID {
            // The restored login is durable before its backup is removed.
            try? storage(at: stashHome).delete()
            UserDefaults.standard.removeObject(forKey: activeIDKey)
            UserDefaults.standard.removeObject(forKey: activeHomeKey)
            UserDefaults.standard.removeObject(forKey: stashStoreKey)
        } else {
            UserDefaults.standard.set(columnID, forKey: activeIDKey)
            UserDefaults.standard.set(home.path, forKey: activeHomeKey)
        }
    }

    /// Вернуть основной аккаунт в `~/.codex` (перед удалением аккаунта и т.п.).
    static func restoreDefault() throws {
        try activate(columnID: defaultColumnID, home: baseHome)
    }

    /// Reserve the source before any refresh POST. Switching cannot publish its
    /// old grant until persistence finishes; successful removal retires the owner.
    static func beginRenewal(columnID: String, home: URL) throws -> Renewal? {
        lock.lock()
        defer { lock.unlock() }
        let key = homeKey(home)
        guard renewals[key] == nil else { throw Failure.busy }
        let live = liveHome(columnID: columnID, home: home)
        guard !isBaseHome(live) else { return nil }
        let source = try storage(at: live)
        guard let record = try source.load() else { return nil }
        let renewal = Renewal(columnID: columnID, key: key, generation: generations[key],
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
                             tokens: CodexOAuth.Tokens) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = renewal.key
        guard generations[key] == renewal.generation, renewals[key]?.id == renewal.id else { return false }
        let destination = renewal.storage
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
                            tokens: CodexOAuth.Tokens, now: Date) -> Data? {
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
    private static func giveBackCurrent() throws {
        let live = try storage(at: baseHome)
        let payload = try live.load()?.data
        if !isSwapped {
            try FileManager.default.createDirectory(at: stashHome, withIntermediateDirectories: true)
            let stash = try CodexAuthStorage(home: stashHome, mode: live.mode)
            if let payload { try stash.save(payload) } else { try stash.delete() }
            // A CLI re-login into our internal backup must use that same backend.
            try ("cli_auth_credentials_store = \"" + live.mode.rawValue + "\"\n")
                .write(to: stashHome.appendingPathComponent("config.toml"), atomically: true, encoding: .utf8)
            UserDefaults.standard.set(live.mode.rawValue, forKey: stashStoreKey)
            return
        }
        guard let payload, let path = UserDefaults.standard.string(forKey: activeHomeKey) else { return }
        let profile = try storage(at: URL(fileURLWithPath: path))
        if let previous = try profile.load()?.data, accountID(payload) == accountID(previous) {
            try profile.save(payload)
        } else {
            // Retain an unexpected native login without exporting a Keychain login to plaintext.
            let orphan = stashHome.deletingLastPathComponent().appendingPathComponent("orphaned-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: orphan, withIntermediateDirectories: true)
            try CodexAuthStorage(home: orphan, mode: live.mode).save(payload)
        }
    }

    static func authData(home: URL) throws -> Data? { try storage(at: home).load()?.data }
    static func hasAuth(home: URL) -> Bool { (try? storage(at: home))?.contains() ?? false }

    static func removeAuth(home: URL) throws {
        lock.lock()
        defer { lock.unlock() }
        let key = homeKey(home)
        try storage(at: home).delete()
        generations[key] = UUID()
        renewals[key] = nil
    }

    private static func storage(at home: URL) throws -> CodexAuthStorage {
        if home.standardizedFileURL == stashHome.standardizedFileURL {
            let saved = UserDefaults.standard.string(forKey: stashStoreKey) ?? "file"
            guard let mode = CodexAuthStorage.Mode(rawValue: saved) else { throw CodexAuthStorage.Failure.settings }
            return try CodexAuthStorage(home: home, mode: mode)
        }
        return try CodexAuthStorage(home: home)
    }

    private static func accountID(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tokens = root["tokens"] as? [String: Any] else { return nil }
        return tokens["account_id"] as? String
    }
}
