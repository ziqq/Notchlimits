import AppKit

/// Переключение аккаунта в самом десктоп-приложении (не CLI!).
///
/// Аккаунт приложения — это его веб-сессия (Electron), она живёт в
/// user-data-dir. Подменить сессию у работающего приложения нельзя, поэтому
/// свич = закрыть приложение и открыть заново с нужной папкой данных
/// (`--user-data-dir`). Папку заводим по имени аккаунта той же колонки, что
/// видно в панели: отдельного «добавить аккаунт приложения» нет — список
/// целиком повторяет колонки. Первый свич на аккаунт открывает приложение в
/// пустой папке — там нужно один раз войти.
///
/// И Claude, и Codex (`ChatGPT.app`) — Electron, поэтому один и тот же приём
/// работает для обоих. Но у Codex вход живёт не в веб-сессии, а в
/// `$CODEX_HOME/auth.json`, поэтому ему дополнительно передаём `CODEX_HOME`
/// колонки (см. `switchTo(accountKey:codexHome:)`).
@MainActor
struct AppAccountSwitcher {

    /// bundle id десктоп-приложения.
    let bundleID: String
    /// Имя для диалогов («Claude» / «Codex»).
    let appName: String
    /// Подпапка в `~/Library/Application Support/NotchLimits`, где живут папки
    /// данных аккаунтов этого приложения.
    private let folderKey: String
    /// Ключ UserDefaults: ключ активного аккаунта, "" — ещё не переключались.
    private let currentKey: String

    /// Свитчер приложения Claude Desktop.
    static let claude = AppAccountSwitcher(
        bundleID: "com.anthropic.claudefordesktop",
        appName: "Claude",
        folderKey: "claude-app",
        currentKey: "currentClaudeAppAccount")

    /// Свитчер приложения Codex (`ChatGPT.app`).
    static let codex = AppAccountSwitcher(
        bundleID: "com.openai.codex",
        appName: "Codex",
        folderKey: "codex-app",
        currentKey: "currentCodexAppAccount")

    /// Установлено ли приложение (иначе подменю показывать незачем).
    var isInstalled: Bool {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) != nil
    }

    /// Ключ аккаунта, под которым приложение открывали последним. "" — ещё нет.
    var currentAccountKey: String {
        UserDefaults.standard.string(forKey: currentKey) ?? ""
    }

    private var root: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask, appropriateFor: nil, create: true))
            ?? ProfileDirectories.home.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("NotchLimits/\(folderKey)", isDirectory: true)
    }

    /// Стабильный ключ папки для колонки: из её id, не из имени (переименование
    /// колонки не должно осиротить папку данных приложения).
    static func key(for columnID: String) -> String {
        AccountSwitcher.slug(columnID)
    }

    /// Переключиться на аккаунт колонки: создать (при необходимости) папку данных
    /// и открыть приложение заново с ней.
    ///
    /// `codexHome` — папка codex-профиля колонки (`~/.codex`,
    /// `~/.codex-profiles/<имя>`). Приложение Codex берёт `CODEX_HOME` из
    /// окружения, только если задан и `CODEX_ELECTRON_USER_DATA_PATH` (иначе
    /// перетирает его окружением login-шелла) — так же оно само открывает
    /// второй экземпляр.
    func switchTo(accountKey: String, codexHome: URL? = nil) {
        let dir = root.appendingPathComponent(accountKey, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        UserDefaults.standard.set(accountKey, forKey: currentKey)
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return }
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        running.forEach { $0.terminate() }
        var environment: [String: String] = [:]
        if let codexHome {
            environment["CODEX_HOME"] = codexHome.path
            environment["CODEX_ELECTRON_USER_DATA_PATH"] = dir.path
        }
        relaunch(appURL: appURL, dataDir: dir, environment: environment, attempts: 25)   // ~10с максимум
    }

    private func relaunch(appURL: URL, dataDir: URL, environment: [String: String], attempts: Int) {
        let stillRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
        guard !stillRunning || attempts <= 0 else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                relaunch(appURL: appURL, dataDir: dataDir, environment: environment, attempts: attempts - 1)
            }
            return
        }
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = false
        config.arguments = ["--user-data-dir=\(dataDir.path)"]
        if !environment.isEmpty {
            config.environment = environment
        }
        NSWorkspace.shared.openApplication(at: appURL, configuration: config, completionHandler: nil)
    }
}
