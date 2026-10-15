import Foundation

/// Route new CLI invocations to existing profiles without copying credentials.
/// The shell reads a persistent selection, so Claude works when Notchlimits is closed.
enum ClaudeCLISelection {
    static let enabledKey = "switchClaudeCLI"

    static var isEnabled: Bool {
        get { UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    private static var root: URL {
        DesktopApp.supportDirectory.appendingPathComponent("claude-cli", isDirectory: true)
    }

    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    static func activate(_ account: DiscoveredAccount) throws {
        guard case .claudeKeychain(let service, _) = account.source else {
            throw Failure(errorDescription: L.t("error.unknownSource"))
        }
        let selection: String
        if service == ClaudeKeychain.baseService {
            selection = ""
        } else if let directory = ClaudeKeychain.configDirectory(for: service) {
            selection = directory.path
        } else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        let home = ProfileDirectories.home
        let shell = URL(fileURLWithPath: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh").lastPathComponent
        let startups: [URL]
        switch shell {
        case "zsh":
            let directory = ProcessInfo.processInfo.environment["ZDOTDIR"].map { URL(fileURLWithPath: $0) } ?? home
            startups = [directory.appendingPathComponent(".zshrc")]
        case "bash":
            let candidates = [".bash_profile", ".bash_login", ".profile"].map { home.appendingPathComponent($0) }
            let login = candidates.first { FileManager.default.fileExists(atPath: $0.path) } ?? candidates[0]
            startups = [login, home.appendingPathComponent(".bashrc")]
        default: throw Failure(errorDescription: L.t("error.cliShell"))
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let pointer = root.appendingPathComponent("selected-profile")
        let script = root.appendingPathComponent("profile.sh")
        let content = """
        # Managed by Notchlimits. No credentials are stored in this file.
        function claude {
            if [ "${CLAUDE_CONFIG_DIR+x}" = x ] || [ "${CLAUDE_SECURESTORAGE_CONFIG_DIR+x}" = x ]; then
                command claude "$@"
                return $?
            fi
            local notchlimits_profile
            if ! IFS= read -r notchlimits_profile < \(quote(pointer.path)); then
                printf '%s\\n' 'Notchlimits: cannot read the selected Claude profile.' >&2
                return 1
            fi
            if [ -z "$notchlimits_profile" ]; then
                (unset CLAUDE_CONFIG_DIR; command claude "$@")
            elif [ "${notchlimits_profile#/}" != "$notchlimits_profile" ] && [ -d "$notchlimits_profile" ]; then
                CLAUDE_CONFIG_DIR="$notchlimits_profile" command claude "$@"
            else
                printf '%s\\n' 'Notchlimits: the selected Claude profile is unavailable.' >&2
                return 1
            fi
        }
        """
        try Data((content + "\n").utf8).write(to: script, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: script.path)
        let source = ". \(quote(script.path))"
        for startup in startups {
            let existing = (try? String(contentsOf: startup, encoding: .utf8)) ?? ""
            if existing.components(separatedBy: .newlines).contains(source) { continue }
            if !FileManager.default.fileExists(atPath: startup.path) {
                FileManager.default.createFile(atPath: startup.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: startup)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(("\n# Notchlimits Claude profile selection\n" + source + "\n").utf8))
        }
        try Data((selection + "\n").utf8).write(to: pointer, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pointer.path)
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
