private enum DesktopFixture {
    static var running = true
    static var stops = 0
    static var opens = 0
    static var installed = true
    static var duringStop: (() -> Void)?
}

final class NSRunningApplication {
    static func runningApplications(withBundleIdentifier _: String) -> [NSRunningApplication] {
        DesktopFixture.running ? [NSRunningApplication()] : []
    }

    func terminate() {
        DesktopFixture.stops += 1
        DesktopFixture.duringStop?()
        DesktopFixture.running = false
    }
}

final class NSWorkspace {
    static let shared = NSWorkspace()

    final class OpenConfiguration {
        var activates = false
        var arguments: [String] = []
    }

    func urlForApplication(withBundleIdentifier _: String) -> URL? {
        DesktopFixture.installed ? Fixture.root.appendingPathComponent("Desktop.app") : nil
    }

    func openApplication(at _: URL, configuration _: OpenConfiguration,
                         completionHandler: (NSRunningApplication?, Error?) -> Void) {
        DesktopFixture.opens += 1
        DesktopFixture.running = true
        completionHandler(NSRunningApplication(), nil)
    }
}

@main
@MainActor
enum Switching$Authentication {
    private static let manager = Foundation.FileManager.default

    static func main() async {
        do {
            let scenario = CommandLine.arguments[1]
            if scenario.hasPrefix("codex-") { try await codex(scenario) }
            else { try await claude(scenario) }
        } catch {
            print("FAIL: \(error)")
            exit(1)
        }
    }

    private static func switchAccount(_ switcher: any AppAccountSwitcher,
                                      to account: DiscoveredAccount) async -> Bool {
        await withCheckedContinuation { continuation in
            switcher.switchTo(account) { result in
                switch result {
                case .success: continuation.resume(returning: true)
                case .failure: continuation.resume(returning: false)
                }
            }
        }
    }

    private static func claude(_ scenario: String) async throws {
        let account = Fixture.claudeAccount
        Fixture.keychain = Fixture.claudeLogin("selected", expired: false)
        let support = DesktopApp.supportDirectory.appendingPathComponent("claude-cli")
        let pointer = support.appendingPathComponent("selected-profile")
        let startup = Fixture.root.appendingPathComponent(".zshrc")
        let previous = "/previous-cli-profile\n"
        try manager.createDirectory(at: support, withIntermediateDirectories: true)
        try Data(previous.utf8).write(to: pointer)

        switch scenario {
        case "claude-shell": Fixture.shell = "/opt/homebrew/bin/fish"
        case "claude-startup": try manager.createDirectory(at: startup, withIntermediateDirectories: true)
        case "claude-toggle-off": DesktopFixture.duringStop = { CLISelection$Claude.isEnabled = false }
        case "claude-toggle-on":
            CLISelection$Claude.isEnabled = false
            DesktopFixture.duringStop = { CLISelection$Claude.isEnabled = true }
        case "claude-missing-desktop": DesktopFixture.installed = false
        default: throw Failure(description: "Unknown Claude scenario")
        }

        let switcher = AppSwitcher$Claude()
        let success = await switchAccount(switcher, to: account)
        let staged = try manager.contentsOfDirectory(atPath: support.path)
        try expect(!staged.contains { $0.hasPrefix(".selected-profile-") }
                   && AppSwitchState.inProgress.isEmpty, "Switch left pending CLI state")
        let selected = try String(contentsOf: pointer)
        switch scenario {
        case "claude-shell", "claude-startup":
            try expect(!success && DesktopFixture.running && DesktopFixture.stops == 0
                       && DesktopFixture.opens == 0 && selected == previous,
                       "CLI preparation failure stopped the outgoing Desktop")
            if scenario == "claude-startup" { try manager.removeItem(at: startup) }
            Fixture.shell = "/bin/zsh"
            let retry = await switchAccount(switcher, to: account)
            try expect(retry && DesktopFixture.stops == 1 && DesktopFixture.opens == 1
                       && (try String(contentsOf: pointer)) == "\n", "Corrected settings could not retry the switch")
        case "claude-missing-desktop":
            try expect(!success && DesktopFixture.stops == 0 && DesktopFixture.opens == 0
                       && !manager.fileExists(atPath: startup.path) && selected == previous,
                       "Missing Desktop modified shell configuration")
        default:
            try expect(success && DesktopFixture.stops == 1 && DesktopFixture.opens == 1
                       && selected == (scenario == "claude-toggle-on" ? "\n" : previous),
                       "The final CLI setting did not control publication")
        }
        try expect(Fixture.refreshCalls == 0 && Fixture.keychainWrites == 0,
                   "Desktop switch performed a renewal or wrote Claude credentials")
    }

    private static func codex(_ scenario: String) async throws {
        let native = AuthSwap$Codex.baseHome
        let selected = ProfileDirectories.codexRoot.appendingPathComponent("work")
        try Fixture.codexLogin(native, account: "primary", mode: "file")
        try Fixture.codexLogin(selected, account: "selected", mode: "file")
        let primary = try AuthSwap$Codex.authData(home: native)
        let selectedLogin = try AuthSwap$Codex.authData(home: selected)
        let selectedID = AuthSwap$Codex.profileColumnID("work")
        let defaultID = AuthSwap$Codex.defaultColumnID
        let replacesBackup = scenario == "codex-replaced-backup"
        let logsOutBackup = scenario == "codex-logged-out-backup"
        let missingPrimary = scenario == "codex-missing-primary"
        let restoresPrimary = missingPrimary || replacesBackup || logsOutBackup
        if restoresPrimary {
            try AuthSwap$Codex.activate(columnID: selectedID, home: selected)
            if missingPrimary { try manager.removeItem(at: native) }
        }
        let targetID = restoresPrimary ? defaultID : selectedID
        guard let account = Discovery$Real().discover().first(where: { $0.id == targetID }) else {
            throw Failure(description: "Real discovery did not find the switch target")
        }

        let replacesProfile = scenario == "codex-replaced-owner"
        if replacesProfile || replacesBackup {
            let target = replacesBackup ? AuthSwap$Codex.stashHome : selected
            DesktopFixture.duringStop = {
                try! manager.moveItem(at: target, to: target.appendingPathExtension("retired"))
                try! Fixture.codexLogin(target, account: "replacement", mode: "file")
            }
        } else if logsOutBackup {
            let credentials = AuthSwap$Codex.stashHome.appendingPathComponent("auth.json")
            DesktopFixture.duringStop = { try! manager.removeItem(at: credentials) }
        }
        let success = await switchAccount(AppSwitcher$Codex(), to: account)
        let current = try AuthSwap$Codex.authData(home: native)
        let refusesSwitch = replacesProfile || replacesBackup || logsOutBackup
        let expected = replacesProfile || missingPrimary ? primary : selectedLogin
        let expectedActive = replacesProfile || missingPrimary ? defaultID : selectedID
        try expect(DesktopFixture.stops == 1 && DesktopFixture.opens == (refusesSwitch ? 0 : 1)
                   && success == !refusesSwitch && current == expected
                   && AuthSwap$Codex.activeColumnID == expectedActive,
                   "Codex switch accepted a replaced or logged-out owner, or refused a valid owner")
        try expect(Fixture.refreshCalls == 0 && AppSwitchState.inProgress.isEmpty,
                   "Codex switch renewed credentials or left the switch gate held")
    }
}
