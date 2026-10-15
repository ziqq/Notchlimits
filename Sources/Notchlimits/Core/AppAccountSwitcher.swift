import AppKit

/// Переключение аккаунта в самом десктоп-приложении (не CLI!).
///
/// Подменить аккаунт у работающего приложения нельзя, поэтому свич всегда
/// один: закрыть приложение → подготовить аккаунт → открыть заново
/// (`DesktopApp.restart`). Чем «подготовить» — у каждого приложения своё:
///
/// - Claude: аккаунт — веб-сессия Electron в user-data-dir, у каждой колонки
///   своя папка данных (`ClaudeAppSwitcher`).
/// - Codex: вход живёт в `~/.codex/auth.json`, а рядом — проекты, треды и
///   сайдбар. Отдельный CODEX_HOME на аккаунт терял бы их, поэтому приложение
///   всегда работает на `~/.codex`, а подменяется только `auth.json`
///   (`CodexAppSwitcher`, `CodexAuthSwap`).
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
private enum AppSwitchState {
    static var inProgress: Set<Provider> = []
    struct Busy: LocalizedError {
        var errorDescription: String? { L.t("appswitch.error.inProgress") }
    }
}

func appAccountSwitcher(for provider: Provider) -> any AppAccountSwitcher {
    switch provider {
    case .claude: return ClaudeAppSwitcher()
    case .codex: return CodexAppSwitcher()
    }
}

// MARK: - Claude

/// Claude Desktop: своя папка данных (`--user-data-dir`) на колонку. Первый
/// свич на аккаунт открывает приложение в пустой папке — там нужно войти.
final class ClaudeAppSwitcher: AppAccountSwitcher {
    private var cliChange: ClaudeCLISelection.Prepared?
    let bundleID = "com.anthropic.claudefordesktop"
    let appName = "Claude"

    /// Ключ папки активного аккаунта; "" — ещё не переключались.
    private static let currentKey = "currentClaudeAppAccount"

    private static var root: URL {
        DesktopApp.supportDirectory.appendingPathComponent("claude-app", isDirectory: true)
    }

    /// Стабильный ключ папки: из id колонки, не из имени (переименование
    /// колонки не должно осиротить папку данных).
    static func key(for columnID: String) -> String {
        AccountSwitcher.slug(columnID)
    }

    func isOpenInApp(columnID: String) -> Bool? {
        let current = UserDefaults.standard.string(forKey: Self.currentKey) ?? ""
        return current.isEmpty ? nil : current == Self.key(for: columnID)
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        let dir = Self.root.appendingPathComponent(Self.key(for: account.id), isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if ClaudeCLISelection.isEnabled { cliChange = try ClaudeCLISelection.stage(account) }
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["--user-data-dir=\(dir.path)"]
        return config
    }

    func commit(_ account: DiscoveredAccount) throws {
        // Desktop has opened: keep its marker truthful even if an external
        // filesystem change prevents publishing the prepared CLI selection.
        defer { UserDefaults.standard.set(Self.key(for: account.id), forKey: Self.currentKey) }
        if ClaudeCLISelection.isEnabled { try cliChange?.commit() }
        cliChange = nil
    }

    func cancel() { cliChange = nil }
}

// MARK: - Codex

/// Codex (`ChatGPT.app`): приложение всегда на `~/.codex`, свич — подмена
/// `auth.json` (см. `CodexAuthSwap`). Голая `codex` в терминале при этом
/// работает под тем же аккаунтом, что и приложение.
struct CodexAppSwitcher: AppAccountSwitcher {
    let bundleID = "com.openai.codex"
    let appName = "Codex"

    func isOpenInApp(columnID: String) -> Bool? {
        CodexAuthSwap.activeColumnID == columnID
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        guard case .codexHome(let home) = account.source else { throw CodexAuthSwap.Failure.missingAuth }
        try CodexAuthSwap.activate(columnID: account.id, home: home)
        return NSWorkspace.OpenConfiguration()
    }

    /// Состояние меняет сама подмена в `prepare`.
    func commit(_ account: DiscoveredAccount) {}
}
