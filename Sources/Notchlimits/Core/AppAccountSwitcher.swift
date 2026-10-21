import AppKit

/// Переключение аккаунта в самом десктоп-приложении (не CLI!).
///
/// Подменить аккаунт у работающего приложения нельзя, поэтому свич всегда
/// один: закрыть приложение → подготовить аккаунт → открыть заново
/// (`DesktopApp.restart`). Чем «подготовить» — у каждого приложения своё:
///
/// - Claude: аккаунт — веб-сессия Electron в user-data-dir, у каждой колонки
///   своя папка данных (`AppSwitcher$Claude`).
/// - Codex: вход живёт в `~/.codex/auth.json`, а рядом — проекты, треды и
///   сайдбар. Отдельный CODEX_HOME на аккаунт терял бы их, поэтому приложение
///   всегда работает на `~/.codex`, а подменяется только `auth.json`
///   (`AppSwitcher$Codex`, `AuthSwap$Codex`).
///
/// Список аккаунтов — это колонки панели того же провайдера.
protocol AppAccountSwitcher {
    var bundleID: String { get }
    /// Имя для диалогов («Claude» / «Codex»).
    var appName: String { get }
    /// Открыт ли аккаунт колонки в приложении. nil — неизвестно (через нас
    /// ещё не переключались).
    func isOpenInApp(columnID: String) -> Bool?
    /// Приложение уже закрыто: подготовить аккаунт и вернуть параметры запуска.
    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration
    /// Приложение открылось под аккаунтом — запомнить это.
    func commit(_ account: DiscoveredAccount) throws
    func cancel()
}

extension AppAccountSwitcher {
    func cancel() {}

    var isInstalled: Bool { DesktopApp.url(bundleID: bundleID) != nil }

    /// Закрыть приложение, подготовить аккаунт, открыть заново. `completion`
    /// зовётся на главном потоке, когда приложение уже запущено (или не вышло).
    @MainActor
    func switchTo(_ account: DiscoveredAccount,
                  completion: @escaping (Result<Void, Error>) -> Void) {
        guard !AppSwitchState.inProgress.contains(account.provider) else {
            completion(.failure(AppSwitchState.Busy()))
            return
        }
        AppSwitchState.inProgress.insert(account.provider)
        DesktopApp.restart(bundleID: bundleID, appName: appName,
                           prepare: { try prepare(account) }) { result in
            defer { AppSwitchState.inProgress.remove(account.provider) }
            switch result {
            case .success:
                do {
                    try commit(account)
                    completion(result)
                } catch {
                    cancel()
                    completion(.failure(error))
                }
            case .failure:
                cancel()
                completion(result)
            }
        }
    }
}

@MainActor
enum AppSwitchState {
    static var inProgress: Set<Provider> = []
    struct Busy: LocalizedError {
        var errorDescription: String? { L.t("appswitch.error.inProgress") }
    }
}

func appAccountSwitcher(for provider: Provider) -> any AppAccountSwitcher {
    switch provider {
    case .claude: return AppSwitcher$Claude()
    case .codex: return AppSwitcher$Codex()
    }
}

// MARK: - Claude

/// Claude Desktop: своя папка данных (`--user-data-dir`) на колонку. Первый
/// свич на аккаунт открывает приложение в пустой папке — там нужно войти.
final class AppSwitcher$Claude: AppAccountSwitcher {
    private var cliChange: CLISelection$Claude.Prepared?
    private var preparedKey: String?
    let bundleID = "com.anthropic.claudefordesktop"
    let appName = "Claude"

    /// Ключ папки активного аккаунта; "" — ещё не переключались.
    private static let currentKey = "currentClaudeAppAccount"
    private static let generationsKey = "claudeAppAccountGenerations"
    private struct RetiredAccount: LocalizedError {
        var errorDescription: String? { L.t("error.cliProfile") }
    }

    private static var root: URL {
        DesktopApp.supportDirectory.appendingPathComponent("claude-app", isDirectory: true)
    }

    /// Стабильный ключ папки: из id колонки, не из имени (переименование
    /// колонки не должно осиротить папку данных).
    static func key(for columnID: String) -> String {
        let base = AccountSwitcher.slug(columnID)
        guard let generation = (UserDefaults.standard.dictionary(forKey: generationsKey) as? [String: String])?[columnID] else {
            return base
        }
        return base + "-" + generation
    }

    static func accountRemoved(columnID: String) {
        let previous = root.appendingPathComponent(key(for: columnID), isDirectory: true)
        var generations = UserDefaults.standard.dictionary(forKey: generationsKey) as? [String: String] ?? [:]
        generations[columnID] = UUID().uuidString
        UserDefaults.standard.set(generations, forKey: generationsKey)
        // A running Desktop may recreate its old path. Future switches use a new generation.
        try? FileManager.default.removeItem(at: previous)
    }

    func isOpenInApp(columnID: String) -> Bool? {
        let current = UserDefaults.standard.string(forKey: Self.currentKey) ?? ""
        return current.isEmpty ? nil : current == Self.key(for: columnID)
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        let key = Self.key(for: account.id)
        let dir = Self.root.appendingPathComponent(key, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        preparedKey = key
        if CLISelection$Claude.isEnabled { cliChange = try CLISelection$Claude.stage(account) }
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["--user-data-dir=\(dir.path)"]
        return config
    }

    func commit(_ account: DiscoveredAccount) throws {
        // Desktop has opened: keep its marker truthful even if an external
        // filesystem change prevents publishing the prepared CLI selection.
        let launchedKey = preparedKey ?? Self.key(for: account.id)
        defer { UserDefaults.standard.set(launchedKey, forKey: Self.currentKey) }
        if CLISelection$Claude.isEnabled {
            guard launchedKey == Self.key(for: account.id) else {
                throw RetiredAccount()
            }
            let change = try cliChange ?? CLISelection$Claude.stage(account)
            try change.commit()
        }
        cliChange = nil
        preparedKey = nil
    }

    func cancel() { cliChange = nil; preparedKey = nil }
}

// MARK: - Codex

/// Desktop and CLI share the base CODEX_HOME and its configured auth backend.
/// Swap credentials only, preserving the application's projects and threads.
struct AppSwitcher$Codex: AppAccountSwitcher {
    let bundleID = "com.openai.codex"
    let appName = "Codex"

    func isOpenInApp(columnID: String) -> Bool? {
        AuthSwap$Codex.activeColumnID == columnID
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        guard case .codexHome(let home) = account.source else { throw AuthSwap$Codex.Failure.missingAuth }
        try AuthSwap$Codex.activate(columnID: account.id, home: home)
        return NSWorkspace.OpenConfiguration()
    }

    /// Состояние меняет сама подмена в `prepare`.
    func commit(_ account: DiscoveredAccount) {}
}
