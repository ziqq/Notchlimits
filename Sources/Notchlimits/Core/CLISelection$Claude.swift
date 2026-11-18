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

    private static var pointer: URL { root.appendingPathComponent("selected-profile") }

    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    /// An old shell must refuse a retired extra profile even after its path is
    /// reused. Keep the native default and any other selected profile intact.
    static func withRetiredSelection(services: Set<String>,
                                     operation: (_ fileRestored: @escaping (Int32, Int32) -> Void) throws -> Void) throws {
        guard services.contains(where: { $0 != AuthStorage$Claude.baseService }) else {
            try operation { _, _ in }
            return
        }
        let pointer = self.pointer
        let contents: String
        do {
            contents = try String(contentsOf: pointer, encoding: .utf8)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            try operation { _, _ in }
            return
        }
        guard let selection = contents.split(separator: "\n", omittingEmptySubsequences: false).first,
              selection.hasPrefix("/") else {
            try operation { _, _ in }
            return
        }
        let service = AuthStorage$Claude.profileService(forConfigPath: String(selection))
        guard services.contains(service) else {
            try operation { _, _ in }
            return
        }
        let profile = URL(fileURLWithPath: String(selection))
        let owner = DirectoryIdentity.capture(profile)
        var credentials = AuthStorage$Claude.credentials(service: service, interactive: false, verifyingOwner: true)
        var restoredOwner: DirectoryIdentity?
        let retired = pointer.deletingLastPathComponent().appendingPathComponent(".retired-" + UUID().uuidString)
        try moveSelection(from: pointer, to: retired)
        do {
            try operation { source, destination in
                guard credentials?.backend == .file, let owner, credentials?.directory == owner,
                      let stagedOwner = DirectoryIdentity.capture(descriptor: source),
                      stagedOwner.isSameDirectory(as: owner) else { return }
                restoredOwner = DirectoryIdentity.capture(descriptor: destination)
            }
        } catch {
            // A failed deletion can leave a different login at the same path.
            if owner?.matches(profile) != true {
                credentials?.directory = restoredOwner
                guard let restoredOwner, let credentials, restoredOwner.matches(profile),
                      (try? AuthStorage$Claude.isCurrent(credentials, service: service)) == true,
                      restoredOwner.matches(profile) else {
                    _ = unlink(retired.path)
                    throw error
                }
            }
            // Preserve a route published by another switch.
            do { try moveSelection(from: retired, to: pointer) }
            catch let restore as POSIXError where restore.code == .EEXIST { _ = unlink(retired.path) }
            throw error
        }
        _ = unlink(retired.path)
    }

    private static func moveSelection(from source: URL, to destination: URL) throws {
        guard renameatx_np(AT_FDCWD, source.path, AT_FDCWD, destination.path, UInt32(RENAME_EXCL)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
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
        guard (service == AuthStorage$Claude.baseService
                ? AuthStorage$Claude.matchesPrimaryOwner(account)
                : account.claudeConfigOwner?.matches(URL(fileURLWithPath: selection)) == true) else {
            throw Failure(errorDescription: L.t("error.cliProfile"))
        }
        let home = ProfileDirectories.home
        let shell = URL(fileURLWithPath: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh").lastPathComponent
        let startups: [URL]
        switch shell {
        case "zsh":
            let interactive = try zshStartupDirectory(home: home, login: false)
            let login = try zshStartupDirectory(home: home, login: true)
            startups = (interactive == login ? [interactive] : [interactive, login]).map {
                $0.appendingPathComponent(".zshrc")
            }
        case "bash":
            let candidates = [".bash_profile", ".bash_login", ".profile"].map { home.appendingPathComponent($0) }
            let login = candidates.first { FileManager.default.fileExists(atPath: $0.path) } ?? candidates[0]
            startups = [login, home.appendingPathComponent(".bashrc")]
        default: throw Failure(errorDescription: L.t("error.cliShell"))
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
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
        return Prepared(staged: staged, pointer: pointer, service: service, selection: selection, account: account)
    }

    final class Prepared {
        private let staged: URL
        private let pointer: URL
        private let service: String
        private let selection: String
        private let account: DiscoveredAccount
        private var committed = false

        fileprivate init(staged: URL, pointer: URL, service: String, selection: String, account: DiscoveredAccount) {
            self.staged = staged
            self.pointer = pointer
            self.service = service
            self.selection = selection
            self.account = account
        }

        func commit(revisionIsCurrent: (() -> Bool)?) throws {
            func ownsProfile() -> Bool {
                (service == AuthStorage$Claude.baseService
                    ? AuthStorage$Claude.matchesPrimaryOwner(account)
                    : AuthStorage$Claude.configPath(for: service) == selection
                        && account.claudeConfigOwner?.matches(URL(fileURLWithPath: selection)) == true)
                    && AuthStorage$Claude.contains(service: service)
            }
            guard ownsProfile() else {
                throw Failure(errorDescription: L.t("error.cliProfile"))
            }
            guard revisionIsCurrent?() == true
                    || AuthStorage$Claude.validateSelectionLogin(service: service, ownsProfile: ownsProfile) else {
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

    private static func zshStartupDirectory(home: URL, login: Bool) throws -> URL {
        let probeDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("notchlimits-zsh-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: probeDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: probeDirectory) }
        let output = probeDirectory.appendingPathComponent("dotdir")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        // Resolve the .zshrc location without running the .zshrc itself.
        process.arguments = [login ? "-fil" : "-fi", "-c", #"""
            setopt rcs
            if [[ -r "${ZDOTDIR-$HOME}/.zshenv" ]]; then
                builtin source "${ZDOTDIR-$HOME}/.zshenv"
            fi
            if [[ -o login ]]; then
                if [[ -o rcs && -o globalrcs && -r /etc/zprofile ]]; then
                    builtin source /etc/zprofile
                fi
                if [[ -o rcs && -r "${ZDOTDIR-$HOME}/.zprofile" ]]; then
                    builtin source "${ZDOTDIR-$HOME}/.zprofile"
                fi
            fi
            unsetopt rcs
            builtin print -rn -- "${ZDOTDIR-$HOME}" >| "$1"
            """#, "notchlimits", output.path]
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        process.environment = environment
        process.currentDirectoryURL = home
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        try process.run()
        guard exited.wait(timeout: .now() + 2) == .success else {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            throw Failure(errorDescription: L.t("error.cliShell"))
        }
        guard process.terminationStatus == 0,
              let path = try? String(contentsOf: output, encoding: .utf8),
              path.hasPrefix("/") else { throw Failure(errorDescription: L.t("error.cliShell")) }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
