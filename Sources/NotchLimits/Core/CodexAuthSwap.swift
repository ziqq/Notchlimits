import Foundation

/// Чей вход сейчас лежит в `~/.codex/auth.json`.
///
/// Приложение Codex держит в CODEX_HOME и вход, и проекты с тредами, поэтому
/// аккаунт переключаем подменой одного `auth.json`, а не всей папки:
///
/// - основной аккаунт (колонка `codex:default`), пока он не в `~/.codex`,
///   ждёт в `NotchLimits/codex-app/default/auth.json`;
/// - вход доп. профиля, пока он в `~/.codex`, живёт там (приложение может
///   обновить токены), а при следующем свиче возвращается в папку профиля.
///
/// Колонки при этом не меняются: `liveHome` говорит, откуда читать вход
/// колонки прямо сейчас.
enum CodexAuthSwap {

    enum Failure: LocalizedError {
        case missingAuth

        var errorDescription: String? { L.t("appswitch.error.noAuth") }
    }

    static let defaultColumnID = "codex:default"

    private static let activeIDKey = "codexAppAccountID"
    private static let activeHomeKey = "codexAppAccountHome"

    /// Перестановка входов и запись продлённых токенов не должны пересечься:
    /// иначе в `~/.codex` уедет уже потраченный refresh-токен.
    private static let lock = NSLock()

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
        UserDefaults.standard.string(forKey: activeIDKey) ?? defaultColumnID
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
        url.standardizedFileURL.path == baseHome.standardizedFileURL.path
    }

    /// Положить в `~/.codex` вход колонки. Приложение должно быть закрыто.
    static func activate(columnID: String, home: URL) throws {
        lock.lock()
        defer { lock.unlock() }
        guard columnID != activeColumnID else { return }
        let incoming = columnID == defaultColumnID ? stashHome : home
        // Проверяем до всяких перестановок, чтобы не остаться на полпути.
        guard columnID == defaultColumnID || exists(auth(incoming)) else { throw Failure.missingAuth }

        try giveBackCurrent()
        if columnID == defaultColumnID {
            try move(auth(stashHome), to: auth(baseHome))
            UserDefaults.standard.removeObject(forKey: activeIDKey)
            UserDefaults.standard.removeObject(forKey: activeHomeKey)
        } else {
            try copy(auth(home), to: auth(baseHome))
            UserDefaults.standard.set(columnID, forKey: activeIDKey)
            UserDefaults.standard.set(home.path, forKey: activeHomeKey)
        }
    }

    /// Вернуть основной аккаунт в `~/.codex` (перед удалением аккаунта и т.п.).
    static func restoreDefault() throws {
        try activate(columnID: defaultColumnID, home: baseHome)
    }

    /// Записать продлённые токены туда, где вход колонки лежит сейчас.
    /// Пишем, только если в файле всё ещё тот refresh-токен, которым мы
    /// продлевали: иначе его уже обновил кто-то другой, и наш ответ устарел.
    static func storeRenewed(columnID: String, home: URL, usedRefreshToken: String,
                             tokens: CodexOAuth.Tokens) throws {
        lock.lock()
        defer { lock.unlock() }
        let file = auth(liveHome(columnID: columnID, home: home))
        guard let data = try? Data(contentsOf: file),
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var stored = root["tokens"] as? [String: Any],
              stored["refresh_token"] as? String == usedRefreshToken
        else { return }

        stored["access_token"] = tokens.accessToken
        if let idToken = tokens.idToken { stored["id_token"] = idToken }
        if let refreshToken = tokens.refreshToken { stored["refresh_token"] = refreshToken }
        root["tokens"] = stored
        root["last_refresh"] = timestamp.string(from: Date())

        let updated = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .withoutEscapingSlashes])
        try updated.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }

    /// Формат `last_refresh`, как у CLI: RFC 3339 с долями секунды.
    private static let timestamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    /// Вход, что сейчас в `~/.codex`, — обратно владельцу.
    private static func giveBackCurrent() throws {
        let live = auth(baseHome)
        guard isSwapped else {
            // Основной уходит в запас. Нет входа — и запасать нечего.
            try FileManager.default.createDirectory(at: stashHome, withIntermediateDirectories: true)
            if exists(live) { try copy(live, to: auth(stashHome)) } else { remove(auth(stashHome)) }
            return
        }
        guard exists(live),
              let path = UserDefaults.standard.string(forKey: activeHomeKey) else { return }
        let profile = auth(URL(fileURLWithPath: path))
        // Кладём обратно, только если это тот же аккаунт (приложение могло
        // обновить токены). Кто-то перелогинился в `~/.codex` иначе или папку
        // профиля удалили — не затираем профиль, а сохраняем копию рядом.
        if exists(profile), accountID(live) == accountID(profile) {
            try copy(live, to: profile)
        } else {
            let stamp = Int(Date().timeIntervalSince1970)
            try copy(live, to: stashHome.appendingPathComponent("orphaned-auth-\(stamp).json"))
        }
    }

    // MARK: - Файлы

    private static func auth(_ home: URL) -> URL { home.appendingPathComponent("auth.json") }

    private static func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

    private static func remove(_ url: URL) { try? FileManager.default.removeItem(at: url) }

    /// Отсутствующий источник = «нет входа»: цель удаляем.
    private static func move(_ source: URL, to target: URL) throws {
        if exists(source) {
            try copy(source, to: target)
            remove(source)
        } else {
            remove(target)
        }
    }

    /// Атомарно и с правами 0600: в файле токены.
    private static func copy(_ source: URL, to target: URL) throws {
        let data = try Data(contentsOf: source)
        try data.write(to: target, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    }

    private static func accountID(_ url: URL) -> String? {
        guard let data = try? Data(contentsOf: url),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tokens = root["tokens"] as? [String: Any]
        else { return nil }
        return tokens["account_id"] as? String
    }
}
