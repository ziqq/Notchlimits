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

    /// `<cli> --version` один раз за запуск: строка нужна только для User-Agent.
    static func version(of binary: URL, fallback: String) -> String {
        if let cached = versionCache[binary.path] { return cached }
        let process = Process()
        process.executableURL = binary
        process.arguments = ["--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        var result = fallback
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = String(data: data, encoding: .utf8) ?? ""
            if let match = text.range(of: #"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.\-]+)?"#,
                                      options: .regularExpression) {
                result = String(text[match])
            }
        } catch {
            result = fallback
        }
        versionCache[binary.path] = result
        return result
    }
}
