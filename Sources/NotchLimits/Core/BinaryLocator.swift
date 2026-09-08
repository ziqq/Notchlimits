import Foundation

/// Поиск CLI-бинарников: PATH у GUI-приложения почти всегда пустой,
/// поэтому проверяем известные места установки руками.
enum BinaryLocator {

    private static var versionCache: [String: String] = [:]

    private static var home: URL { FileManager.default.homeDirectoryForCurrentUser }

    static func claude() -> URL? {
        var candidates: [URL] = [
            home.appendingPathComponent(".local/bin/claude"),
            home.appendingPathComponent(".claude/local/claude"),
            URL(fileURLWithPath: "/opt/homebrew/bin/claude"),
            URL(fileURLWithPath: "/usr/local/bin/claude")
        ]
        // Бинарь из расширения VS Code — берём самую свежую версию.
        let extensions = home.appendingPathComponent(".vscode/extensions")
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: extensions.path) {
            let matches = entries
                .filter { $0.hasPrefix("anthropic.claude-code-") }
                .sorted { $0.compare($1, options: .numeric) == .orderedAscending }
            if let latest = matches.last {
                candidates.append(extensions
                    .appendingPathComponent(latest)
                    .appendingPathComponent("resources/native-binary/claude"))
            }
        }
        return firstExecutable(candidates)
    }

    static func codex() -> URL? {
        firstExecutable([
            home.appendingPathComponent(".local/bin/codex"),
            URL(fileURLWithPath: "/opt/homebrew/bin/codex"),
            URL(fileURLWithPath: "/usr/local/bin/codex"),
            URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")
        ])
    }

    private static func firstExecutable(_ candidates: [URL]) -> URL? {
        candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    /// Версия Claude — из пути к бинарю, БЕЗ запуска самого CLI. Запускать
    /// `claude --version` нельзя: claude на старте читает свои креды через
    /// `/usr/bin/security` и вызывает диалог пароля Keychain. Версия и так лежит
    /// в пути: `~/.local/bin/claude` → симлинк на `.../versions/2.1.245`,
    /// либо каталог расширения VS Code `anthropic.claude-code-<версия>`.
    static func claudeVersion(fallback: String) -> String {
        guard let binary = claude() else { return fallback }
        return version(fromPath: binary) ?? fallback
    }

    /// Ищем «x.y.z» в компонентах пути и в цели симлинка. Чистая — под самотест.
    static func version(fromPath binary: URL) -> String? {
        let resolved = (try? FileManager.default.destinationOfSymbolicLink(atPath: binary.path))
            .map { URL(fileURLWithPath: $0, relativeTo: binary.deletingLastPathComponent()) }
            ?? binary.resolvingSymlinksInPath()
        let pattern = #"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.\-]+)?"#
        for component in (resolved.pathComponents + binary.pathComponents).reversed() {
            if let range = component.range(of: pattern, options: .regularExpression) {
                return String(component[range])
            }
        }
        return nil
    }

    /// `<cli> --version` один раз за запуск: строка нужна только для User-Agent.
    /// Годится для codex (он не лезет в Keychain); для claude — `claudeVersion`.
    static func version(of binary: URL, fallback: String) -> String {
        if let cached = versionCache[binary.path] { return cached }
        var result = fallback
        if let text = run(binary, arguments: ["--version"]),
           let match = text.range(of: #"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.\-]+)?"#,
                                   options: .regularExpression) {
            result = String(text[match])
        }
        versionCache[binary.path] = result
        return result
    }

    /// Запуск CLI с чтением stdout. Блокирующий — только вне главного потока.
    private static func run(_ binary: URL, arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}
