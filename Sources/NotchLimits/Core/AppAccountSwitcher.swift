import AppKit

/// Переключение аккаунта в самом приложении Claude (не CLI!).
///
/// Аккаунт приложения — это его веб-сессия (Electron), она живёт в
/// user-data-dir. Подменить сессию у работающего приложения нельзя, поэтому
/// свич = закрыть Claude и открыть заново с нужной папкой данных
/// (`--user-data-dir`). Каждый аккаунт — отдельная папка; текущую (дефолтную)
/// папку `~/Library/Application Support/Claude` не трогаем.
@MainActor
enum AppAccountSwitcher {

    static let bundleID = "com.anthropic.claudefordesktop"
    private static let currentKey = "currentClaudeAppAccount"   // имя папки, "" = дефолт

    struct AppAccount: Equatable {
        let name: String
        /// Папка данных; nil — дефолтная (основной аккаунт приложения).
        let dir: URL?
        let isCurrent: Bool
    }

    private static var root: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask, appropriateFor: nil, create: true))
            ?? ProfileDirectories.home.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("NotchLimits/claude-app", isDirectory: true)
    }

    private static var currentName: String {
        UserDefaults.standard.string(forKey: currentKey) ?? ""
    }

    /// Список аккаунтов: основной (дефолтная папка) + добавленные папки.
    static func accounts() -> [AppAccount] {
        let current = currentName
        var result = [AppAccount(name: ProfileDirectories.primaryName, dir: nil, isCurrent: current.isEmpty)]
        let dirs = (try? FileManager.default.contentsOfDirectory(at: root,
                    includingPropertiesForKeys: [.isDirectoryKey])) ?? []
        for dir in dirs.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard (try? dir.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else { continue }
            let name = dir.lastPathComponent
            result.append(AppAccount(name: name, dir: dir, isCurrent: name == current))
        }
        return result
    }

    /// Уникальное ли имя (не «main», не занятая папка).
    static func isValidName(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != ProfileDirectories.primaryName else { return false }
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        guard trimmed.unicodeScalars.allSatisfy(allowed.contains), trimmed.first != "." else { return false }
        return !FileManager.default.fileExists(atPath: root.appendingPathComponent(trimmed).path)
    }

    /// Добавить аккаунт: создать папку и открыть в ней Claude для входа.
    static func add(name: String) throws {
        let dir = root.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        switchTo(name: name, dir: dir)
    }

    /// Переключиться: закрыть Claude и открыть заново с папкой аккаунта.
    static func switchTo(name: String, dir: URL?) {
        UserDefaults.standard.set(dir == nil ? "" : name, forKey: currentKey)
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return }
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        running.forEach { $0.terminate() }
        relaunch(appURL: appURL, dataDir: dir, attempts: 25)   // ~10с максимум
    }

    private static func relaunch(appURL: URL, dataDir: URL?, attempts: Int) {
        let stillRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
        guard !stillRunning || attempts <= 0 else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                relaunch(appURL: appURL, dataDir: dataDir, attempts: attempts - 1)
            }
            return
        }
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = false
        if let dataDir { config.arguments = ["--user-data-dir=\(dataDir.path)"] }
        NSWorkspace.shared.openApplication(at: appURL, configuration: config, completionHandler: nil)
    }
}
