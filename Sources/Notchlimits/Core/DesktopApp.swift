import AppKit

/// Перезапуск чужого десктоп-приложения: закрыть, дождаться выхода,
/// подготовить, открыть.
@MainActor
enum DesktopApp {

    enum Failure: LocalizedError {
        case notInstalled(String)
        case didNotQuit(String)

        var errorDescription: String? {
            switch self {
            case .notInstalled(let name): return L.t("appswitch.error.notInstalled", name)
            case .didNotQuit(let name): return L.t("appswitch.error.didNotQuit", name)
            }
        }
    }

    /// `~/Library/Application Support/Notchlimits` — здесь наши папки данных.
    nonisolated static var supportDirectory: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask, appropriateFor: nil, create: true))
            ?? ProfileDirectories.home.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Notchlimits", isDirectory: true)
    }

    /// Прежнее имя папки данных.
    nonisolated static let legacySupportName = "NotchLimits"

    /// Переименовать папку данных со старого имени. На обычном APFS (без учёта
    /// регистра) это та же папка и меняется только регистр в имени; на томе
    /// с учётом регистра без переноса пропали бы входы и папки приложений.
    /// `rename(2)`, а не `FileManager.moveItem`: смена одного регистра на томе
    /// без учёта регистра для него выглядит как «назначение уже существует».
    nonisolated static func migrateSupportDirectory() {
        let current = supportDirectory
        let base = current.deletingLastPathComponent()
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: base.path),
              names.contains(legacySupportName),
              !names.contains(current.lastPathComponent)
        else { return }
        let legacy = base.appendingPathComponent(legacySupportName, isDirectory: true)
        _ = rename(legacy.path, current.path)
    }

    nonisolated static func url(bundleID: String) -> URL? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
    }

    /// `prepare` выполняется, только когда приложение точно закрыто: до этого
    /// оно может ещё писать свои файлы (у Codex — тот самый auth.json).
    static func restart(bundleID: String,
                        appName: String,
                        prepare: @escaping () throws -> NSWorkspace.OpenConfiguration,
                        completion: @escaping (Result<Void, Error>) -> Void) {
        guard let appURL = url(bundleID: bundleID) else {
            completion(.failure(Failure.notInstalled(appName)))
            return
        }
        running(bundleID).forEach { $0.terminate() }
        waitForExit(bundleID: bundleID, attempts: 50) { exited in   // ~15с максимум
            guard exited else {
                completion(.failure(Failure.didNotQuit(appName)))
                return
            }
            let config: NSWorkspace.OpenConfiguration
            do { config = try prepare() } catch {
                completion(.failure(error))
                return
            }
            config.activates = true
            NSWorkspace.shared.openApplication(at: appURL, configuration: config) { _, error in
                DispatchQueue.main.async {
                    completion(error.map { .failure($0) } ?? .success(()))
                }
            }
        }
    }

    private static func running(_ bundleID: String) -> [NSRunningApplication] {
        NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
    }

    private static func waitForExit(bundleID: String, attempts: Int, done: @escaping (Bool) -> Void) {
        if running(bundleID).isEmpty { return done(true) }
        guard attempts > 0 else { return done(false) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            waitForExit(bundleID: bundleID, attempts: attempts - 1, done: done)
        }
    }
}
