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

func rmdir(_ path: UnsafePointer<CChar>) -> Int32 {
    ClaudeLifecycleSignals.replaceExpiredLock(at: AT_FDCWD, path: path)
    return Darwin.rmdir(path)
}

func unlinkat(_ parent: Int32, _ path: UnsafePointer<CChar>, _ flags: Int32) -> Int32 {
    if ClaudeLifecycleSignals.lateHeartbeat == "cleanup", String(cString: path).contains(".retiring-") {
        ClaudeLifecycleSignals.touchPublicLock(parent: parent)
    }
    return Darwin.unlinkat(parent, path, flags)
}

private enum ClaudeLifecycleSignals {
    static var storeReached = false
    static var searchList: ((UnsafeMutablePointer<CFArray?>) -> OSStatus)?
    static var deniedSelection: String?
    static var replacingLock: String?
    static var nativeLock: Int32 = -1
    static var crashOnSwap = false
    static var replaceOnRepair = false
    static var lateHeartbeat: String?
    static var heartbeatReached = false

    static func touchPublicLock(parent: Int32) {
        lateHeartbeat = nil
        let directory = Darwin.openat(parent, ".storage-write.lock", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directory >= 0 else { return }
        defer { _ = Darwin.close(directory) }
        heartbeatReached = Darwin.futimes(directory, nil) == 0
    }

    static func replaceAtRepairDestination(parent: Int32, path: UnsafePointer<CChar>) {
        guard replaceOnRepair else { return }
        replaceExpiredLock(at: parent, path: path)
    }

    static func beforeRename(_ flags: UInt32) {
        guard crashOnSwap, flags == UInt32(RENAME_SWAP) else { return }
        FileHandle.standardOutput.write(Data("ready-for-cli\n".utf8))
        _ = readLine()
    }

    static func afterRename(_ flags: UInt32, _ result: Int32, parent: Int32) {
        guard flags == UInt32(RENAME_SWAP), result == 0 else { return }
        if crashOnSwap { _exit(86) }
        if lateHeartbeat == "swap" { touchPublicLock(parent: parent) }
    }

    static func replaceExpiredLock(at parent: Int32, path: UnsafePointer<CChar>) {
        guard let replacingLock,
              String(cString: path) == (parent == AT_FDCWD ? replacingLock : URL(fileURLWithPath: replacingLock).lastPathComponent)
        else { return }
        self.replacingLock = nil
        if Darwin.unlinkat(parent, path, AT_REMOVEDIR) == 0 && Darwin.mkdirat(parent, path, 0o700) == 0 {
            nativeLock = Darwin.openat(parent, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        }
    }

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
            case "dotdir":
                try dotdir(configured: args[1] != "default", interactiveOnly: args[1] == "interactive")
            case "lock-syscall":
                try lockSyscall(recovering: args[1] == "recover")
            case "lock-crash-swap":
                try crashAfterLockSwap(recovering: args[1] == "recover")
            case "lock-native-owner":
                try preservesNativeLock(lifetime: args.count > 1 ? 1 : 15)
            case "lock-repair-race":
                try repairRace()
            case "lock-available":
                let lock = try StorageLock$Claude(path: lockPath, lifetime: 1)
                try expect(lock.isHeld, "The expired retirement blocked acquisition")
                lock.release()
            case "lock-late-heartbeat":
                ClaudeLifecycleSignals.lateHeartbeat = args[1]
                try preservesNativeLock(lifetime: 1)
                try expect(ClaudeLifecycleSignals.heartbeatReached, "Fixture did not renew the native lease")
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

    private static func lockSyscall(recovering: Bool) throws {
        let directory = Fixture.root.appendingPathComponent("claude-lock")
        let path = directory.appendingPathComponent(".storage-write.lock")
        var old: StorageLock$Claude? = try StorageLock$Claude(directory: directory)
        try expect(old?.isHeld == true, "Fixture did not acquire the original lock")
        if recovering { old = nil }
        try Foundation.FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1)],
                                                         ofItemAtPath: path.path)
        ClaudeLifecycleSignals.replacingLock = path.path
        var admitted = false
        if let old {
            old.release()
        } else if let recovered = try? StorageLock$Claude(directory: directory) {
            admitted = true
            recovered.release()
        }
        let native = ClaudeLifecycleSignals.nativeLock
        try expect(native >= 0, "CLI did not acquire its replacement lock at the syscall boundary")
        defer { _ = Darwin.close(native) }
        var owner = stat()
        try expect(Darwin.fstat(native, &owner) == 0,
                   "Could not read the native directory")
        let files = try Foundation.FileManager.default.contentsOfDirectory(atPath: directory.path)
        try expect(!admitted && files.contains(where: {
            var entry = stat()
            return Darwin.lstat(directory.appendingPathComponent($0).path, &entry) == 0
                && entry.st_dev == owner.st_dev && entry.st_ino == owner.st_ino
        }), "Notchlimits removed a fresh native lock or recovered while CLI owned it")
        try expect(Foundation.FileManager.default.fileExists(atPath: path.path), "The native lock path became vacant")
    }

    private static func crashAfterLockSwap(recovering: Bool) throws {
        let directory = Fixture.root.appendingPathComponent("claude-lock")
        let path = directory.appendingPathComponent(".storage-write.lock")
        var owner: StorageLock$Claude? = try StorageLock$Claude(directory: directory)
        try expect(owner?.isHeld == true, "Fixture did not acquire the original lock")
        try Foundation.FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1)],
                                                         ofItemAtPath: path.path)
        ClaudeLifecycleSignals.crashOnSwap = true
        if recovering {
            owner = nil
            _ = try StorageLock$Claude(directory: directory)
        } else {
            owner?.release()
        }
        throw Failure(description: "Fixture did not reach the swap")
    }

    private static var lockPath: URL {
        Fixture.root.appendingPathComponent("claude-lock/.storage-write.lock")
    }

    private static func preservesNativeLock(lifetime: TimeInterval = 15) throws {
        do {
            let owner = try StorageLock$Claude(path: lockPath, lifetime: lifetime)
            owner.release()
            throw Failure(description: "Restart acquired the lock while a native owner was still active")
        } catch StorageLock$Claude.Failure.busy {}
    }

    private static func repairRace() throws {
        ClaudeLifecycleSignals.replaceOnRepair = true
        ClaudeLifecycleSignals.replacingLock = lockPath.path
        try preservesNativeLock()
        let successor = ClaudeLifecycleSignals.nativeLock
        guard successor >= 0 else { return }
        defer { _ = Darwin.close(successor) }
        var held = stat(), publicInfo = stat()
        try expect(Darwin.fstat(successor, &held) == 0 && Darwin.lstat(lockPath.path, &publicInfo) == 0
                   && held.st_dev == publicInfo.st_dev && held.st_ino == publicInfo.st_ino,
                   "Recovery moved the new native lock from the public path")
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
        if mode == "rollback-replacement" || mode == "rollback-empty" {
            let replacesLogin = mode == "rollback-replacement"
            let credentials = directory.appendingPathComponent(".credentials.json")
            let original = try Data(contentsOf: credentials)
            let replacement = try JSONSerialization.data(
                withJSONObject: Fixture.claudeLogin("independent-new-login", expired: false))
            var reached = false
            Fixture.beforeCredentialDelete = {
                reached = true
                try! manager.createDirectory(at: directory, withIntermediateDirectories: true)
                if replacesLogin { try! replacement.write(to: credentials) }
            }
            Fixture.denyKeychainDelete = true
            var refused = false
            do { try AccountRemoval.remove(account) } catch { refused = true }
            try expect(reached && refused && !account.claudeConfigOwner!.matches(directory)
                       && (try Data(contentsOf: credentials)) == (replacesLogin ? replacement : original),
                       "Expected refused deletion to preserve an independent profile at the same path")
            CLISelection$Claude.isEnabled = false
            try switchTo(old.0)
            let invoked = try invoke()
            print("rollback collision reached=\(reached) refused=\(refused) CLI used replacement=\(invoked.0 == 0 && invoked.1 == expected)")
            try expect(replacesLogin ? invoked.0 != 0 && invoked.1.isEmpty : invoked.0 == 0 && invoked.1 == expected,
                       "Rollback did not retain the route matching the credentials after recovery")
            return
        } else if mode == "refused" || mode == "pointer-refused" {
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
    private static func dotdir(configured: Bool, interactiveOnly: Bool) throws {
        Fixture.claudeEntries = [:]
        let (account, profile) = try profile(file: true)
        let manager = Foundation.FileManager.default
        let dotfiles = Fixture.root.appendingPathComponent("dotfiles")
        try manager.createDirectory(at: dotfiles, withIntermediateDirectories: true)
        if configured {
            let assignment = interactiveOnly ? "if [[ -o interactive ]]; then ZDOTDIR=$HOME/dotfiles; fi\n" : "ZDOTDIR=$HOME/dotfiles\n"
            try Data(assignment.utf8).write(to: Fixture.root.appendingPathComponent(".zshenv"))
            try Data("# existing interactive setup\n".utf8).write(to: dotfiles.appendingPathComponent(".zshrc"))
        }
        try switchTo(account)
        let fake = dotfiles.appendingPathComponent("claude")
        try Data("#!/bin/sh\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\"\n".utf8).write(to: fake)
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-i", "-c", "claude"]
        process.environment = ["HOME": Fixture.root.path, "PATH": dotfiles.path + ":/usr/bin:/bin", "TERM": "dumb"]
        let out = Pipe()
        process.standardOutput = out
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        let result = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        print("Configured zsh dotdir=\(configured), Claude switch returned success, actual shell route matches=\(result == profile.path + "\n")")
        try expect(process.terminationStatus == 0 && result == profile.path + "\n",
                   "New interactive zsh ignored a CLI selection reported successful by the switch")
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
