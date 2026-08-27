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
        var result = fallback
        if let text = run(binary, arguments: ["--version"]),
           let match = text.range(of: #"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.\-]+)?"#,
                                   options: .regularExpression) {
            result = String(text[match])
        }
        versionCache[binary.path] = result
        return result
    }

    /// Почта аккаунта Claude. API её не отдаёт, а CLI — да:
    /// `claude auth status --json`. Для доп. профиля выставляем CLAUDE_CONFIG_DIR.
    static func claudeEmail(configDir: URL?) -> String? {
        guard let binary = claude() else { return nil }
        var env: [String: String] = [:]
        if let configDir { env["CLAUDE_CONFIG_DIR"] = configDir.path }
        guard let output = run(binary, arguments: ["auth", "status", "--json"], env: env) else {
            return nil
        }
        return parseAuthEmail(output)
    }

    /// Разбор ответа `auth status`. Чистый — покрыт самопроверкой без CLI.
    static func parseAuthEmail(_ output: String) -> String? {
        // На случай посторонних строк вокруг JSON берём от первой «{» до последней «}».
        guard let start = output.firstIndex(of: "{"),
              let end = output.lastIndex(of: "}"), start < end,
              let data = String(output[start...end]).data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["loggedIn"] as? Bool == true,
              let email = root["email"] as? String, !email.isEmpty
        else { return nil }
        return email
    }

    /// Запуск CLI с чтением stdout. Блокирующий — только вне главного потока.
    /// PATH у GUI-приложения почти пуст, поэтому наследуем окружение процесса
    /// и лишь дополняем нужными переменными.
    private static func run(_ binary: URL, arguments: [String],
                            env: [String: String] = [:]) -> String? {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        if !env.isEmpty {
            var merged = ProcessInfo.processInfo.environment
            for (key, value) in env { merged[key] = value }
            process.environment = merged
        }
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
