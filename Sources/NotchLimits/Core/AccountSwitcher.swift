import Foundation
import Security

/// Переключение активного аккаунта для обычных команд `codex` / `claude`.
///
/// Список для переключения — это ВСЕ известные аккаунты: текущий активный,
/// добавленные профили (колонки) и «библиотека» (снимки вытесненных аккаунтов).
/// Отдельного «Сохранить текущий» не нужно: при переключении текущий активный
/// сам уходит в библиотеку, поэтому вернуться к нему можно всегда.
///
/// Codex хранит вход в файле `~/.codex/auth.json` — работаем файлами. Claude —
/// в записи Keychain `Claude Code-credentials`, поэтому копии делаем
/// keychain→keychain, не выгружая токены на диск.
enum AccountSwitcher {

    enum Failure: LocalizedError {
        case noActive, notFound, io
        var errorDescription: String? {
            switch self {
            case .noActive: return L.t("switch.err.noActive")
            case .notFound: return L.t("switch.err.notFound")
            case .io:       return L.t("switch.err.io")
            }
        }
    }

    /// `ref` — источник учётных данных: путь к auth.json (Codex) или имя записи
    /// Keychain (Claude). Он же кладётся в пункт меню.
    struct Account: Equatable {
        let email: String?
        let isActive: Bool
        let ref: String
        var display: String { email ?? ref }
    }

    // MARK: - Активные сессии

    /// Сколько процессов `claude` запущено — обычно ≥ 1 (текущая сессия),
    /// поэтому переключение Claude только предупреждаем, не блокируем.
    static func runningClaudeSessions() -> Int {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "claude"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return 0 }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline).filter { !$0.isEmpty }.count
    }

    // MARK: - Общее

    static func slug(_ email: String?) -> String {
        let source = (email?.isEmpty == false) ? email!.lowercased() : "account"
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789")
        let cleaned = source.map { allowed.contains($0) ? $0 : "-" }
        let slug = String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String((slug.isEmpty ? "account" : slug).prefix(48))
    }

    private static var appSupport: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask, appropriateFor: nil, create: true))
            ?? ProfileDirectories.home.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("NotchLimits", isDirectory: true)
    }

    // MARK: - Codex (файлы)

    private static var codexHome: URL { ProfileDirectories.home.appendingPathComponent(".codex") }
    private static var codexAuth: URL { codexHome.appendingPathComponent("auth.json") }
    private static var codexLib: URL { appSupport.appendingPathComponent("codex", isDirectory: true) }

    static func codexActiveEmail() -> String? {
        CodexProvider.readAuth(codexHome: codexHome)?.email
    }

    /// Все аккаунты Codex: активный + профили + библиотека, без повторов по почте.
    static func codexAccounts() -> [Account] {
        let active = codexActiveEmail()
        var seen = Set<String>()
        var result: [Account] = []
        func add(authURL: URL) {
            guard FileManager.default.fileExists(atPath: authURL.path) else { return }
            let email = CodexProvider.readAuth(codexHome: authURL.deletingLastPathComponent())?.email
            let key = email ?? authURL.path
            guard seen.insert(key).inserted else { return }
            result.append(Account(email: email,
                                  isActive: email != nil && email == active,
                                  ref: authURL.path))
        }
        add(authURL: codexAuth)                                    // текущий активный
        for dir in ProfileDirectories.codexProfiles() {           // профили
            add(authURL: dir.appendingPathComponent("auth.json"))
        }
        let libDirs = (try? FileManager.default.contentsOfDirectory(at: codexLib,
                        includingPropertiesForKeys: nil)) ?? []    // библиотека
        for dir in libDirs { add(authURL: dir.appendingPathComponent("auth.json")) }
        return result
    }

    /// Снимок текущего активного Codex-аккаунта в библиотеку (для losslessness).
    @discardableResult
    static func saveCurrentCodex() throws -> Account {
        guard let auth = try? Data(contentsOf: codexAuth), !auth.isEmpty else { throw Failure.noActive }
        let email = codexActiveEmail()
        let dir = codexLib.appendingPathComponent(slug(email), isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let dest = dir.appendingPathComponent("auth.json")
        try auth.write(to: dest, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
        return Account(email: email, isActive: true, ref: dest.path)
    }

    /// Сделать активным аккаунт из `ref` (путь к auth.json).
    static func switchCodex(toRef path: String) throws {
        guard path != codexAuth.path else { return }              // уже активен
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), !data.isEmpty
        else { throw Failure.notFound }
        _ = try? saveCurrentCodex()                               // сохранить текущий
        do {
            try data.write(to: codexAuth, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: codexAuth.path)
        } catch { throw Failure.io }
    }

    // MARK: - Claude (keychain→keychain)

    private static let claudeBase = ClaudeKeychain.baseService
    private static let libPrefix = "NotchLimits.claude."
    private static let emailsKey = "switcherClaudeEmails"
    private static func claudeLibService(_ slug: String) -> String { libPrefix + slug }
    private static var claudeConfig: URL { ProfileDirectories.home.appendingPathComponent(".claude.json") }

    static func claudeActiveEmail() -> String? {
        (try? Data(contentsOf: claudeConfig)).flatMap { ClaudeProvider.parseEmail(fromConfig: $0) }
    }

    private static func storedEmails() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: emailsKey) as? [String: String] ?? [:]
    }

    /// Почта аккаунта по имени записи Keychain (для отображения и `~/.claude.json`).
    private static func email(forService service: String) -> String? {
        if service == claudeBase { return claudeActiveEmail() }
        if service.hasPrefix(libPrefix) {
            let value = storedEmails()[String(service.dropFirst(libPrefix.count))]
            return (value?.isEmpty == false) ? value : nil
        }
        // Профиль: почта лежит в <config-dir>/.claude.json.
        if let dir = ClaudeKeychain.configDirectory(for: service) {
            return (try? Data(contentsOf: dir.appendingPathComponent(".claude.json")))
                .flatMap { ClaudeProvider.parseEmail(fromConfig: $0) }
        }
        return nil
    }

    /// Все аккаунты Claude: активный (base) + профили (записи Keychain) +
    /// библиотека. Активный определяем по почте из `~/.claude.json`, без чтения
    /// секретов, чтобы открытие меню не вызывало запрос пароля.
    static func claudeAccounts() -> [Account] {
        let active = claudeActiveEmail()
        var seen = Set<String>()
        var result: [Account] = []
        func add(service: String, email: String?) {
            let key = email ?? service
            guard seen.insert(key).inserted else { return }
            result.append(Account(email: email,
                                  isActive: email != nil && email == active,
                                  ref: service))
        }
        add(service: claudeBase, email: active)                              // активный
        for service in ClaudeKeychain.services() where service != claudeBase {  // профили
            add(service: service, email: email(forService: service))
        }
        for (slug, mail) in storedEmails() {                                // библиотека
            add(service: claudeLibService(slug), email: mail.isEmpty ? nil : mail)
        }
        return result
    }

    /// Снимок текущего активного Claude-аккаунта в библиотеку (keychain→keychain).
    @discardableResult
    static func saveCurrentClaude() throws -> Account {
        guard let blob = ClaudeKeychain.rawData(service: claudeBase) else { throw Failure.noActive }
        let mail = claudeActiveEmail()
        let s = slug(mail)
        guard ClaudeKeychain.writeRaw(service: claudeLibService(s), data: blob) else { throw Failure.io }
        var emails = storedEmails(); emails[s] = mail ?? ""
        UserDefaults.standard.set(emails, forKey: emailsKey)
        return Account(email: mail, isActive: true, ref: claudeLibService(s))
    }

    /// Сделать активным аккаунт из `ref` (имя записи Keychain).
    static func switchClaude(toService service: String) throws {
        guard service != claudeBase else { return }                        // уже активен
        guard let blob = ClaudeKeychain.rawData(service: service) else { throw Failure.notFound }
        let targetEmail = email(forService: service)
        _ = try? saveCurrentClaude()                                       // сохранить текущий
        guard ClaudeKeychain.writeRaw(service: claudeBase, data: blob) else { throw Failure.io }
        if let targetEmail { updateClaudeConfigEmail(targetEmail) }        // чтобы claude/панель показывали верно
    }

    private static func updateClaudeConfigEmail(_ email: String) {
        guard let data = try? Data(contentsOf: claudeConfig),
              var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return }
        var account = (root["oauthAccount"] as? [String: Any]) ?? [:]
        account["emailAddress"] = email
        root["oauthAccount"] = account
        if let out = try? JSONSerialization.data(withJSONObject: root) {
            try? out.write(to: claudeConfig, options: .atomic)
        }
    }
}
