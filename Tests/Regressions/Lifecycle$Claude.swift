private actor ClaudeUsagePublicationProbe: UsageProvider {
    let provider = Provider$Claude()
    let service: String
    let mode: String

    init(service: String, mode: String) {
        self.service = service
        self.mode = mode
    }

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        await provider.fetch(account)
    }

    func fetchValidated(_ account: DiscoveredAccount) async -> UsageFetchResult {
        let result = await provider.fetchValidated(account)
        let expectedService = service
        if mode == "unavailable" {
            ClaudeLifecycleSignals.searchList = { _ in errSecNoSuchKeychain }
        }
        let replacement = mode == "replacement"
        Fixture.afterClaudeSecretRead = { key in
            guard key == expectedService else { return }
            Fixture.afterClaudeSecretRead = nil
            ClaudeLifecycleSignals.storeReached = true
            if replacement {
                Fixture.claudeEntries?[key] = Fixture.claudeLogin("different-login", expired: false)
                try! Data().write(to: Fixture.classicKeychainDatabase(), options: .atomic)
            }
        }
        return result
    }
}

private enum ClaudeLifecycleSignals {
    static var storeReached = false
    static var searchList: ((UnsafeMutablePointer<CFArray?>) -> OSStatus)?
    static var deniedSelection: String?

    static func selectionRenameRefused(_ path: String) -> Bool {
        guard path == deniedSelection else { return false }
        errno = EACCES
        return true
    }
}

@main
enum Lifecycle$Claude {
    @MainActor
    static func main() async {
        do {
            let args = CommandLine.arguments[1].split(separator: ":").map(String.init)
            switch args[0] {
            case "file-pointer":
                try filePointer(mode: args[1])
            case "cli-removed":
                try cliRemoved(mode: args[1])
            case "usage":
                try await usage(mode: args[1])
            default:
                throw Failure(description: "Unknown Claude lifecycle scenario")
            }
        } catch {
            print("FAIL:", error)
            exit(1)
        }
    }

    @MainActor
    private static func profile(file: Bool, name: String = "work", login: String? = nil) throws -> (DiscoveredAccount, URL) {
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent(name)
        let manager = Foundation.FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let suffix = SHA256.hash(data: Data(directory.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        let service = Fixture.service + "-" + suffix
        let json = Fixture.claudeLogin(login ?? name, expired: false)
        if file {
            try JSONSerialization.data(withJSONObject: json).write(to: directory.appendingPathComponent(".credentials.json"))
        } else {
            var entries = Fixture.claudeEntries ?? [:]
            entries[service] = json
            Fixture.claudeEntries = entries
        }
        guard let account = Discovery$Real().discover().first(where: { $0.id == "claude:" + service }) else {
            throw Failure(description: "Real discovery missed profile")
        }
        return (account, directory)
    }

    @MainActor
    private static func switchTo(_ account: DiscoveredAccount) throws {
        var result: Result<Void, Error>?
        AppSwitcher$Claude().switchTo(account) { result = $0 }
        guard let result else { throw Failure(description: "Fixture switch did not complete") }
        try result.get()
    }

    @MainActor
    private static func filePointer(mode: String) throws {
        Fixture.claudeEntries = [:]
        let (account, directory) = try profile(file: true)
        let file = directory.appendingPathComponent(".credentials.json")
        let pointer = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/selected-profile")
        let prior = "/previous/selection\n"
        let manager = Foundation.FileManager.default
        try manager.createDirectory(at: pointer.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(prior.utf8).write(to: pointer)
        if mode == "unavailable" {
            ClaudeLifecycleSignals.searchList = { _ in errSecNoSuchKeychain }
        }
        Fixture.holdDesktopCompletion = true
        var result: Result<Void, Error>?
        AppSwitcher$Claude().switchTo(account) { result = $0 }
        try expect(result == nil && Fixture.desktopCompletion != nil && String(contentsOf: pointer) == prior,
                   "CLI pointer published before Desktop completion or launch did not stage")
        var entered = false
        ClaudeLifecycleSignals.searchList = { resultPointer in
            ClaudeLifecycleSignals.searchList = nil
            entered = true
            switch mode {
            case "logout": try! manager.removeItem(at: file)
            case "stub":
                let stub = try! JSONSerialization.data(withJSONObject: ["trustedDeviceToken": "synthetic-stub"])
                try! stub.write(to: file, options: .atomic)
            default: break
            }
            if mode == "unavailable" {
                ClaudeLifecycleSignals.searchList = { _ in errSecNoSuchKeychain }
                return errSecNoSuchKeychain
            }
            return SecKeychainCopySearchList(resultPointer)
        }
        Fixture.desktopCompletion?(.success(()))
        try expect(entered && AppSwitcher$Claude().isOpenInApp(columnID: account.id) == true,
                   "Fixture missed late Classic Keychain search during commit or lost actual Desktop marker")
        let selected = try String(contentsOf: pointer)
        let refused: Bool
        if case .failure? = result { refused = true } else { refused = false }
        print("file-pointer", mode, "refused", refused, "prior retained", selected == prior)
        if ["stable", "unavailable"].contains(mode) {
            try expect(!refused && selected == directory.path + "\n", "Stable file login was refused")
        } else {
            try expect(refused && selected == prior, "CLI selected a file login retired during final Keychain validation")
        }
    }

    @MainActor
    private static func cliRemoved(mode: String) throws {
        Fixture.claudeEntries = [:]
        let (account, directory) = try profile(file: true)
        let old = try profile(file: true, name: "previous")
        try switchTo(mode == "previous" ? old.0 : account)
        let manager = Foundation.FileManager.default
        let script = DesktopApp.supportDirectory.appendingPathComponent("claude-cli/profile.sh")
        let fakeBin = Fixture.root.appendingPathComponent("bin")
        try manager.createDirectory(at: fakeBin, withIntermediateDirectories: true)
        let fake = fakeBin.appendingPathComponent("claude")
        try Data("#!/bin/sh\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\"\n".utf8).write(to: fake)
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        func invoke() throws -> (Int32, String) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/zsh")
            process.arguments = ["-f", "-c", ". \"$1\"; claude", "fixture", script.path]
            process.environment = ["PATH": fakeBin.path + ":/usr/bin:/bin"]
            let output = Pipe()
            process.standardOutput = output
            process.standardError = Pipe()
            try process.run()
            process.waitUntilExit()
            return (process.terminationStatus, String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        }
        let before = try invoke()
        let expected = (mode == "previous" ? old.1 : directory).path + "\n"
        try expect(before.0 == 0 && before.1 == expected, "Original selected route did not work")
        if mode == "refused" || mode == "pointer-refused" {
            Fixture.denyCredentialFileRemoval = mode == "refused"
            if mode == "pointer-refused" {
                ClaudeLifecycleSignals.deniedSelection = script.deletingLastPathComponent()
                    .appendingPathComponent("selected-profile").path
            }
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(refused && account.claudeConfigOwner?.matches(directory) == true
                       && manager.fileExists(atPath: directory.appendingPathComponent(".credentials.json").path),
                       "Refused route or credential deletion retired the profile")
        } else {
            if mode == "orphan" {
                try manager.removeItem(at: directory.appendingPathComponent(".credentials.json"))
                try AccountRemoval.removeIncompleteClaudeProfile(at: directory)
            } else {
                try AccountRemoval.remove(account)
            }
            try expect(!manager.fileExists(atPath: directory.path), "Production removal left the original directory")
            if mode != "previous" {
                let removed = try invoke()
                try expect(removed.0 != 0 && removed.1.isEmpty, "Removed target still ran while absent")
            }
            let (_, replacement) = try profile(file: true, login: "different-login")
            try expect(account.claudeConfigOwner?.matches(replacement) == false, "The replacement must use a new physical directory")
            // Desktop-only switches explicitly preserve the previous CLI choice.
            CLISelection$Claude.isEnabled = false
            try switchTo(old.0)
        }
        let after = try invoke()
        print("cli-removed", mode, "status", after.0, "routed into reusable path", after.1 == expected)
        if ["replacement", "orphan"].contains(mode) {
            try expect(after.0 != 0 && after.1.isEmpty, "The retired selection resumed under a replacement login without a CLI switch")
            CLISelection$Claude.isEnabled = true
            guard let replacement = Discovery$Real().discover().first(where: { $0.id == account.id }) else {
                throw Failure(description: "Real discovery missed the re-added profile")
            }
            try switchTo(replacement)
            let selected = try invoke()
            try expect(selected.0 == 0 && selected.1 == expected, "An explicit switch could not select the re-added profile")
        } else {
            try expect(after.0 == 0 && after.1 == expected, "An unchanged or independent selected profile stopped routing")
        }
    }

    @MainActor
    private static func usage(mode: String) async throws {
        Fixture.claudeEntries = [:]
        Fixture.manualPollingTimer = true
        let (account, _) = try profile(file: false)
        guard case .claudeKeychain(let service, _) = account.source else { fatalError() }
        let probe = ClaudeUsagePublicationProbe(service: service, mode: mode)
        let store = UsageStore(providers: [.claude: probe], discovery: Discovery$Real())
        store.start()
        for _ in 0..<300 {
            if ClaudeLifecycleSignals.storeReached { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        let column = store.columns.first { $0.id == account.id }
        let cache = UsageCache().load(id: account.id)
        try expect(ClaudeLifecycleSignals.storeReached && Fixture.usageCalls == 1,
                   "Fixture missed the final Keychain proof in the production UsageStore")
        print("store", mode, "column", column?.windows.first?.utilization as Any,
              "cache", cache?.windows.first?.utilization as Any)
        if mode == "replacement" {
            try expect(column?.windows.isEmpty == true && cache == nil,
                       "Production UsageStore published and cached limits of the previous Keychain login")
        } else {
            try expect(column?.windows.first?.utilization == 12 && cache?.windows.first?.utilization == 12,
                       "Current usage did not publish to the column and cache")
        }
    }
}
