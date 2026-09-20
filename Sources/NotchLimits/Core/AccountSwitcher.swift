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

    /// Сколько CLI-сессий `claude` запущено (без хелперов десктоп-приложения
    /// Claude.app). Обычно ≥ 1 — текущая сессия, поэтому переключение Claude
    /// только предупреждаем, не блокируем. Хелперы Claude.app отсеиваем по пути
    /// исполняемого файла (`comm`), а НЕ по всей строке: в окружении настоящего
    /// CLI тоже встречается `.app/` (PATH, entrypoint).
    static func runningClaudeSessions() -> Int {
        let pids = shell("/usr/bin/pgrep", ["-x", "claude"])
            .split(whereSeparator: \.isNewline).map(String.init).filter { !$0.isEmpty }
        guard !pids.isEmpty else { return 0 }
        return shell("/bin/ps", ["-o", "pid=,comm=", "-p", pids.joined(separator: ",")])
            .split(whereSeparator: \.isNewline)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty && !$0.contains(".app/") }
            .count
    }

    private static func shell(_ launchPath: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
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
    private static let emailsKey = "switcherClaudeEmails"       // slug → email (список)
    private static let accountsKey = "switcherClaudeAccounts"   // slug → JSON блока oauthAccount
    private static func claudeLibService(_ slug: String) -> String { libPrefix + slug }
    private static var claudeConfig: URL { ProfileDirectories.home.appendingPathComponent(".claude.json") }

    /// E-mail из базового `~/.claude.json` — это и есть активный аккаунт (что
    /// использует голая команда claude). Его помечаем галочкой; переключение
    /// меняет именно его.
    static func claudeActiveEmail() -> String? {
        (try? Data(contentsOf: claudeConfig)).flatMap { ClaudeProvider.parseEmail(fromConfig: $0) }
    }

    private static func storedEmails() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: emailsKey) as? [String: String] ?? [:]
    }

    private static func storedAccounts() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: accountsKey) as? [String: String] ?? [:]
    }

    /// Блок `oauthAccount` из `~/.claude.json` — это ПОЛНЫЕ метаданные аккаунта
    /// (почта, accountUuid, organizationUuid, план…). Переключение подменяет его
    /// целиком: подмена одной почты оставила бы токен нового аккаунта с UUID
    /// старого, и сервер ответил бы 401 → «re-auth».
    private static func oauthAccount(inConfig url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        return root["oauthAccount"] as? [String: Any]
    }

    /// Блок oauthAccount целевого аккаунта: профиль — из его `.claude.json`,
    /// библиотека — из сохранённого снимка, база — из активного конфига.
    private static func oauthAccount(forService service: String) -> [String: Any]? {
        if service == claudeBase { return oauthAccount(inConfig: claudeConfig) }
        if service.hasPrefix(libPrefix) {
            let slug = String(service.dropFirst(libPrefix.count))
            guard let json = storedAccounts()[slug],
                  let obj = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]
            else { return nil }
            return obj
        }
        if let dir = ClaudeKeychain.configDirectory(for: service) {
            return oauthAccount(inConfig: dir.appendingPathComponent(".claude.json"))
        }
        return nil
    }

    /// Почта аккаунта по имени записи Keychain (для отображения и `~/.claude.json`).
    private static func email(forService service: String) -> String? {
        if service == claudeBase { return claudeActiveEmail() }
        if let mail = oauthAccount(forService: service)?["emailAddress"] as? String, !mail.isEmpty {
            return mail
        }
        if service.hasPrefix(libPrefix) {                                   // старые записи без снимка
            let value = storedEmails()[String(service.dropFirst(libPrefix.count))]
            return (value?.isEmpty == false) ? value : nil
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
        add(service: claudeBase, email: active)                              // активный (базовый)
        for service in ClaudeKeychain.services() where service != claudeBase {  // профили
            add(service: service, email: email(forService: service))
        }
        for slug in Set(storedEmails().keys).union(storedAccounts().keys) {  // библиотека
            add(service: claudeLibService(slug), email: email(forService: claudeLibService(slug)))
        }
        return result
    }

    /// Снимок текущего активного Claude-аккаунта в библиотеку: токен (keychain→
    /// keychain) И полный блок oauthAccount — иначе вернуться на него без 401
    /// нельзя.
    @discardableResult
    static func saveCurrentClaude() throws -> Account {
        guard let blob = ClaudeKeychain.rawData(service: claudeBase) else { throw Failure.noActive }
        let mail = claudeActiveEmail()
        let s = slug(mail)
        guard ClaudeKeychain.writeRaw(service: claudeLibService(s), data: blob) else { throw Failure.io }
        var emails = storedEmails(); emails[s] = mail ?? ""
        UserDefaults.standard.set(emails, forKey: emailsKey)
        if let account = oauthAccount(inConfig: claudeConfig),
           let json = try? JSONSerialization.data(withJSONObject: account),
           let str = String(data: json, encoding: .utf8) {
            var accounts = storedAccounts(); accounts[s] = str
            UserDefaults.standard.set(accounts, forKey: accountsKey)
        }
        return Account(email: mail, isActive: true, ref: claudeLibService(s))
    }

    /// Сделать активным аккаунт из `ref` (имя записи Keychain). Полный обмен:
    /// токен → base keychain И весь блок oauthAccount → ~/.claude.json.
    static func switchClaude(toService service: String) throws {
        guard service != claudeBase else { return }                        // уже активен
        guard let blob = ClaudeKeychain.rawData(service: service) else { throw Failure.notFound }
        let targetAccount = oauthAccount(forService: service)              // снять ДО сохранения текущего
        let targetEmail = email(forService: service)
        _ = try? saveCurrentClaude()                                       // сохранить текущий
        guard ClaudeKeychain.writeRaw(service: claudeBase, data: blob) else { throw Failure.io }
        writeActiveOAuthAccount(targetAccount, fallbackEmail: targetEmail)
    }

    /// Пишет блок oauthAccount в `~/.claude.json` целиком, сохраняя остальные
    /// поля файла. Нет полного снимка (старая запись) — меняем хотя бы почту.
    private static func writeActiveOAuthAccount(_ account: [String: Any]?, fallbackEmail: String?) {
        guard let data = try? Data(contentsOf: claudeConfig),
              var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return }
        if let account {
            root["oauthAccount"] = account
        } else if let fallbackEmail {
            var acc = (root["oauthAccount"] as? [String: Any]) ?? [:]
            acc["emailAddress"] = fallbackEmail
            root["oauthAccount"] = acc
        } else {
            return
        }
        if let out = try? JSONSerialization.data(withJSONObject: root) {
            try? out.write(to: claudeConfig, options: .atomic)
        }
    }
}
