import Foundation
import Security

/// Переключение активного аккаунта для обычных команд `codex` / `claude`.
///
/// Модель как у codex-account-switcher: есть «библиотека» сохранённых аккаунтов
/// и один активный вход; «Сохранить текущий» кладёт активный в библиотеку,
/// «Переключить» ставит выбранный активным. Перед подменой активный всегда
/// сохраняется в библиотеку, чтобы ничего не потерять.
///
/// Codex хранит вход в файле `~/.codex/auth.json` — работаем файлами. Claude —
/// в записи Keychain `Claude Code-credentials`, поэтому копии делаем
/// keychain→keychain, не выгружая токены на диск. Библиотечные записи Claude
/// называем с префиксом `NotchLimits.claude.`, чтобы их не приняли за профиль.
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

    struct Account: Equatable {
        let slug: String
        let email: String?
        let isActive: Bool
        var display: String { email ?? slug }
    }

    // MARK: - Активные сессии

    /// Сколько процессов `claude` запущено. Обычно ≥ 1 — это и есть текущая
    /// сессия Claude Code, поэтому переключение Claude только предупреждаем.
    /// Для Codex счётчик не показываем: `pgrep -x codex` ловит десятки фоновых
    /// хелперов приложения ChatGPT (не «сессии»), да и подмена файла auth.json
    /// не ломает уже запущенные процессы — они читают его лишь при старте.
    static func runningClaudeSessions() -> Int { runningProcesses(named: "claude") }

    private static func runningProcesses(named name: String) -> Int {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", name]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return 0 }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .filter { !$0.isEmpty }.count
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

    static func codexAccounts() -> [Account] {
        let active = codexActiveEmail()
        let entries = (try? FileManager.default.contentsOfDirectory(at: codexLib,
                        includingPropertiesForKeys: nil)) ?? []
        return entries.compactMap { dir -> Account? in
            guard (try? dir.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else { return nil }
            let email = CodexProvider.readAuth(codexHome: dir)?.email
            return Account(slug: dir.lastPathComponent, email: email,
                           isActive: email != nil && email == active)
        }.sorted { $0.display < $1.display }
    }

    /// Снимок текущего активного Codex-аккаунта в библиотеку.
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
        return Account(slug: dir.lastPathComponent, email: email, isActive: true)
    }

    static func switchCodex(toSlug target: String) throws {
        let source = codexLib.appendingPathComponent(target).appendingPathComponent("auth.json")
        guard let data = try? Data(contentsOf: source), !data.isEmpty else { throw Failure.notFound }
        _ = try? saveCurrentCodex()  // сохранить текущий, чтобы не потерять
        do {
            try data.write(to: codexAuth, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: codexAuth.path)
        } catch { throw Failure.io }
    }

    // MARK: - Claude (keychain→keychain)

    private static let claudeBase = ClaudeKeychain.baseService
    private static let emailsKey = "switcherClaudeEmails"
    private static func claudeLibService(_ slug: String) -> String { "NotchLimits.claude.\(slug)" }
    private static var claudeConfig: URL { ProfileDirectories.home.appendingPathComponent(".claude.json") }

    static func claudeActiveEmail() -> String? {
        (try? Data(contentsOf: claudeConfig)).flatMap { ClaudeProvider.parseEmail(fromConfig: $0) }
    }

    private static func storedEmails() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: emailsKey) as? [String: String] ?? [:]
    }

    /// Активный определяем по e-mail из `~/.claude.json`, а не чтением blob'ов
    /// Keychain — иначе простое открытие меню вызвало бы запрос пароля на каждую
    /// запись. Keychain трогаем только при самом переключении.
    static func claudeAccounts() -> [Account] {
        let active = claudeActiveEmail()
        return storedEmails().map { slug, email in
            Account(slug: slug, email: email.isEmpty ? nil : email,
                    isActive: !email.isEmpty && email == active)
        }.sorted { $0.display < $1.display }
    }

    /// Снимок текущего активного Claude-аккаунта в библиотеку (keychain→keychain).
    @discardableResult
    static func saveCurrentClaude() throws -> Account {
        guard let blob = ClaudeKeychain.rawData(service: claudeBase) else { throw Failure.noActive }
        let email = claudeActiveEmail()
        let s = slug(email)
        guard ClaudeKeychain.writeRaw(service: claudeLibService(s), data: blob) else { throw Failure.io }
        var emails = storedEmails(); emails[s] = email ?? ""
        UserDefaults.standard.set(emails, forKey: emailsKey)
        return Account(slug: s, email: email, isActive: true)
    }

    static func switchClaude(toSlug target: String) throws {
        guard let blob = ClaudeKeychain.rawData(service: claudeLibService(target)) else { throw Failure.notFound }
        _ = try? saveCurrentClaude()  // сохранить текущий
        guard ClaudeKeychain.writeRaw(service: claudeBase, data: blob) else { throw Failure.io }
        // Подтянуть e-mail в ~/.claude.json, чтобы claude и панель показывали
        // верный аккаунт (это не токен, а отображаемое поле).
        if let email = storedEmails()[target], !email.isEmpty { updateClaudeConfigEmail(email) }
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
