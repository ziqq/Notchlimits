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
    func commit(_ account: DiscoveredAccount)
}

extension AppAccountSwitcher {
    var isInstalled: Bool { DesktopApp.url(bundleID: bundleID) != nil }

    /// Закрыть приложение, подготовить аккаунт, открыть заново. `completion`
    /// зовётся на главном потоке, когда приложение уже запущено (или не вышло).
    @MainActor
    func switchTo(_ account: DiscoveredAccount,
                  completion: @escaping (Result<Void, Error>) -> Void) {
        DesktopApp.restart(bundleID: bundleID, appName: appName,
                           prepare: { try prepare(account) }) { result in
            if case .success = result { commit(account) }
            completion(result)
        }
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
struct ClaudeAppSwitcher: AppAccountSwitcher {
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
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["--user-data-dir=\(dir.path)"]
        return config
    }

    func commit(_ account: DiscoveredAccount) {
        UserDefaults.standard.set(Self.key(for: account.id), forKey: Self.currentKey)
    }
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
