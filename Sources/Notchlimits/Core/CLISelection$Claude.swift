import Foundation
import Darwin

/// Route new CLI invocations to existing profiles without copying credentials.
/// The shell reads a persistent selection, so Claude works when Notchlimits is closed.
enum CLISelection$Claude {
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

    static func stage(_ account: DiscoveredAccount) throws -> Prepared {
        guard case .claudeKeychain(let service, _) = account.source else {
            throw Failure(errorDescription: L.t("error.unknownSource"))
        }
        let selection: String
        if service == AuthStorage$Claude.baseService {
            selection = ""
        } else if let path = AuthStorage$Claude.configPath(for: service) {
            selection = path
        } else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        guard !selection.contains("\n"), !selection.contains("\r") else {
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
        let wasIntegrated = FileManager.default.fileExists(atPath: script.path)
        if !wasIntegrated && !FileManager.default.fileExists(atPath: pointer.path) {
            // Installing the function must preserve default CLI routing until commit.
            try Data("\n".utf8).write(to: pointer, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pointer.path)
        }
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
        let staged = root.appendingPathComponent(".selected-profile-" + UUID().uuidString)
        do {
            try Data((selection + "\n").utf8).write(to: staged, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staged.path)
        } catch {
            try? FileManager.default.removeItem(at: staged)
            throw error
        }
        return Prepared(staged: staged, pointer: pointer, service: service, selection: selection)
    }

    final class Prepared {
        private let staged: URL
        private let pointer: URL
        private let service: String
        private let selection: String
        private var committed = false

        fileprivate init(staged: URL, pointer: URL, service: String, selection: String) {
            self.staged = staged
            self.pointer = pointer
            self.service = service
            self.selection = selection
        }

        func commit() throws {
            guard AuthStorage$Claude.contains(service: service),
                  service == AuthStorage$Claude.baseService || AuthStorage$Claude.configPath(for: service) == selection else {
                throw Failure(errorDescription: L.t("error.cliProfile"))
            }
            guard rename(staged.path, pointer.path) == 0 else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            committed = true
        }

        deinit {
            if !committed { try? FileManager.default.removeItem(at: staged) }
        }
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
