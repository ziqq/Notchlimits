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
    static var cutAfterSelectionMove: String?
    static var cutAfterProfileMove: String?
    static var afterStagingForConfirmation: ((URL) -> Void)?
    static var cutBeforeProfileMove: String?
    static var cutAfterProfileCleanup: URL?
    static var cutAfterCredentialDelete: String?
    static var afterKeychainDeletion: ((String) -> Void)?
    static var cutAfterFallback = false
    static var cutAfterCredentialRollback = false
    static var opaqueService: String?
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

    static func afterSelectionRename(_ path: String, result: Int32) {
        if result == 0, path == cutAfterSelectionMove { _exit(86) }
    }

    static func afterProfileMove(from source: URL, to destination: URL) {
        if destination.lastPathComponent.hasPrefix(".removed-") { afterStagingForConfirmation?(source) }
        if source.path == cutAfterProfileMove, destination.lastPathComponent.hasPrefix(".removed-") {
            _exit(86)
        }
    }

    static func beforeProfileMove(from source: URL, to destination: URL) {
        if source.path == cutBeforeProfileMove, destination.lastPathComponent.hasPrefix(".removed-") {
            _exit(86)
        }
    }

    static func afterProfileCleanup(_ directory: URL) {
        let parent = directory.deletingLastPathComponent()
        if cutAfterFallback, directory.lastPathComponent == ".credentials.json",
           parent.lastPathComponent.hasPrefix(".removed-") || parent.path == Fixture.storageDirectory.path { _exit(86) }
        if parent.path == cutAfterProfileCleanup?.path,
           directory.lastPathComponent.hasPrefix(".removed-") { _exit(86) }
    }

    static func afterFallbackIsolation(from: String, to: String, result: Int32) {
        if cutAfterFallback, result == 0, from == ".credentials.json", to.hasSuffix(".removal") { _exit(86) }
    }

    static func afterCredentialDelete(_ service: String) {
        afterKeychainDeletion?(service)
        if service == cutAfterCredentialDelete { _exit(86) }
    }

    static func attributes(_ service: String, query: CFDictionary) -> [String: Any] {
        var attributes: [String: Any] = [kSecAttrService as String: service]
        if service == opaqueService, (query as NSDictionary)[kSecReturnPersistentRef as String] as? Bool == true {
            attributes[kSecValuePersistentRef as String] = Data(("fixture-claude-ref-" + service).utf8)
            attributes[kSecAttrModificationDate as String] = Date(timeIntervalSince1970: 1)
        }
        return attributes
    }

    static func ownsPersistentReference(_ reference: CFData) -> Bool {
        guard let service = opaqueService, Fixture.claudeEntries?[service] != nil else { return false }
        return (reference as Data) == Data(("fixture-claude-ref-" + service).utf8)
    }

    static func afterCredentialRollback(parent: Int32, name: String, result: Int32) {
        if cutAfterCredentialRollback, result == 0, parent != AT_FDCWD, name == ".credentials.json" { _exit(86) }
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
            case "cli-retirement-cut":
                try cliRetirementCut(phase: args[1], backend: args[2], selection: args[3])
            case "cli-retirement-replay":
                try cliRetirementReplay(phase: args[1], backend: args[2], selection: args[3], behavior: args[4])
            case "retirement-without-proof":
                try retirementWithoutProof()
            case "desktop-retirement-cut":
                try desktopRetirementCut(deleted: args[1] == "deleted")
            case "desktop-retirement-replay":
                try desktopRetirementReplay(deleted: args[1] == "deleted")
            case "desktop-stub-cut":
                try desktopStubCut(deleted: args[1] == "deleted")
            case "desktop-stub-replay":
                try desktopStubReplay(deleted: args[1] == "deleted")
            case "desktop-rollback-cut":
                try desktopRollbackCut(selected: args[1] != "restored")
            case "desktop-rollback-replay":
                try desktopRollbackReplay(mode: args[1])
            case "shared-primary-cut":
                try sharedPrimaryCut(phase: args[1])
            case "shared-primary-replay":
                try sharedPrimaryReplay(phase: args[1])
            case "native-primary-cut":
                try nativePrimaryCut(phase: args[1])
            case "native-primary-replay":
                try nativePrimaryReplay(phase: args[1])
            case "remove-confirmed":
                try removeConfirmed(backend: args[1], phase: args[2])
            case "dotdir":
                try dotdir(mode: args[1])
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
    private static func removeConfirmed(backend: String, phase: String) throws {
        Fixture.claudeEntries = [:]
        let service: String
        let directory: URL
        if backend == "primary" {
            service = Fixture.service
            directory = ProfileDirectories.home.appendingPathComponent(".claude")
            Fixture.claudeEntries?[service] = Fixture.claudeLogin("primary", expired: false)
            try expect(DirectoryIdentity.missingPath(directory) != nil, "Fixture primary home already exists")
        } else {
            let (account, home) = try profile(file: backend == "file")
            guard case .claudeKeychain(let namespace, _) = account.source else {
                throw Failure(description: "Fixture Claude profile was not discovered")
            }
            service = namespace
            directory = home
        }
        let id = "claude:" + service
        let store = UsageStore(providers: [:], discovery: Discovery$Real())
        store.rediscover(force: true)
        try expect(store.account(for: id) != nil, "Fixture removal menu has no account")
        let menu = RegressionProfileMenu(store: store)
        let replacement = Fixture.claudeLogin("new-owner", expired: false)
        if phase == "staged" {
            ClaudeLifecycleSignals.afterStagingForConfirmation = { source in
                guard source.path == directory.path else { return }
                Fixture.claudeEntries?[service] = replacement
                ClaudeLifecycleSignals.afterStagingForConfirmation = nil
            }
        } else if phase == "replacement" {
            menu.beforeConfirmation = {
                if backend == "file" {
                    try! JSONSerialization.data(withJSONObject: replacement)
                        .write(to: directory.appendingPathComponent(".credentials.json"), options: .atomic)
                } else {
                    Fixture.claudeEntries?[service] = replacement
                }
            }
        }
        menu.remove(column: id)
        let login = AuthStorage$Claude.credentials(service: service, interactive: false)?.accessToken
        if phase != "unchanged" {
            try expect(ClaudeLifecycleSignals.afterStagingForConfirmation == nil, "Fixture did not reach profile staging")
            try expect(menu.failure != nil && login == "synthetic-new-owner", "The previous confirmation retired the new login")
        } else {
            try expect(menu.failure == nil && login == nil, "The unchanged login did not remove successfully")
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

    private static var cliSupport: URL { DesktopApp.supportDirectory.appendingPathComponent("claude-cli") }
    private static var cliPointer: URL { cliSupport.appendingPathComponent("selected-profile") }
    private static let retiringProfileName = "retiring-claude"

    private static func desktopDirectory() throws -> URL {
        let prefix = "--user-data-dir="
        guard let argument = Fixture.desktopArguments.first(where: { $0.hasPrefix(prefix) }) else {
            throw Failure(description: "Desktop launch did not report its real data directory")
        }
        return URL(fileURLWithPath: String(argument.dropFirst(prefix.count)), isDirectory: true)
    }

    @MainActor
    private static func desktopRetirementCut(deleted: Bool) throws {
        Fixture.claudeEntries = [:]
        try switchTo(profile(file: true, name: "previous").0)
        CLISelection$Claude.isEnabled = false
        let (target, directory) = try profile(file: true, name: retiringProfileName)
        try switchTo(target)
        try Data("previous Desktop session".utf8).write(to: desktopDirectory().appendingPathComponent("session"))
        if deleted { ClaudeLifecycleSignals.cutAfterProfileCleanup = directory.deletingLastPathComponent() }
        else { ClaudeLifecycleSignals.cutBeforeProfileMove = directory.path }
        try AccountRemoval.remove(target)
        throw Failure(description: "The Desktop retirement cut was not reached")
    }

    @MainActor
    private static func desktopRetirementReplay(deleted: Bool, selectedName: String = "previous") throws {
        Fixture.claudeEntries = [:]
        CLISelection$Claude.isEnabled = false
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent(retiringProfileName)
        let id = "claude:" + AuthStorage$Claude.profileService(forConfigPath: directory.path)
        let priorDesktop = DesktopApp.supportDirectory.appendingPathComponent("claude-app/" + AccountSwitcher.slug(id))
        let marker = priorDesktop.appendingPathComponent("session")
        let manager = Foundation.FileManager.default
        try expect(manager.fileExists(atPath: directory.path) != deleted && manager.fileExists(atPath: marker.path),
                   "The interrupted child did not stop before changing the Desktop generation")
        let selected = deleted ? try profile(file: true, name: retiringProfileName, login: "replacement").0
            : Discovery$Real().discover().first(where: { $0.id == id })
        guard let selected else { throw Failure(description: "Replay could not find the Claude profile") }
        try switchTo(selected)
        try expect((try desktopDirectory().path == priorDesktop.path) == !deleted,
                   "Desktop reused the retired generation or discarded the unchanged generation")
        try expect(try String(contentsOf: marker, encoding: .utf8) == "previous Desktop session",
                   "An uncertain deletion destroyed the prior Desktop data")
        let expected = ProfileDirectories.claudeRoot.appendingPathComponent(selectedName).path + "\n"
        try expect(try String(contentsOf: cliPointer, encoding: .utf8) == expected,
                   "Desktop retirement changed the independently selected CLI route")
    }

    @MainActor
    private static func desktopStubCut(deleted: Bool) throws {
        let service = AuthStorage$Claude.baseService
        let id = "claude:" + service
        let directory = ProfileDirectories.home.appendingPathComponent(".claude")
        try Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        CLISelection$Claude.isEnabled = false
        Fixture.claudeEntries = [service: Fixture.claudeLogin("old-primary", expired: false)]
        guard let signedIn = Discovery$Real().discover().first(where: { $0.id == id }) else {
            throw Failure(description: "The main login was not discovered")
        }
        try switchTo(signedIn)
        try Data("previous Desktop session".utf8).write(to: desktopDirectory().appendingPathComponent("session"))

        Fixture.claudeEntries = [service: ["trustedDeviceToken": "synthetic-logged-out-primary"]]
        guard let stub = Discovery$Real().discover().first(where: { $0.id == id }), stub.claudePrimaryOwner == .keychain,
              AuthStorage$Claude.hasNoLogin(service: service, interactive: false) else {
            throw Failure(description: "Discovery did not present the main Keychain stub for removal")
        }
        if deleted { ClaudeLifecycleSignals.cutAfterCredentialDelete = service }
        else { Fixture.beforeCredentialDelete = { _exit(86) } }
        try AccountRemoval.remove(stub)
        throw Failure(description: "The synthetic Keychain stub deletion boundary was not reached")
    }

    @MainActor
    private static func desktopStubReplay(deleted: Bool) throws {
        let service = AuthStorage$Claude.baseService
        let id = "claude:" + service
        let previous = DesktopApp.supportDirectory.appendingPathComponent("claude-app/" + AccountSwitcher.slug(id))
        let manager = Foundation.FileManager.default
        let marker = previous.appendingPathComponent("session")
        try expect(manager.fileExists(atPath: marker.path), "Child did not stop before changing Desktop generation")
        Fixture.claudeEntries = deleted ? [:] : [service: ["trustedDeviceToken": "synthetic-logged-out-primary"]]
        _ = Discovery$Real().discover()
        CLISelection$Claude.isEnabled = false
        Fixture.claudeEntries = [service: Fixture.claudeLogin("new-primary", expired: false)]
        guard let signedIn = Discovery$Real().discover().first(where: { $0.id == id }) else {
            throw Failure(description: "The replacement main login was not discovered")
        }
        try switchTo(signedIn)
        try expect((try desktopDirectory().path == previous.path) == !deleted
                   && manager.fileExists(atPath: marker.path) == !deleted,
                   "Replaying stub removal reused a retired Desktop or discarded an unchanged session")
    }

    private static var sharedPrimaryCheckpoint: URL {
        Fixture.root.appendingPathComponent("shared-primary-defaults.plist")
    }

    @MainActor
    private static func sharedPrimaryCut(phase: String) throws {
        let fs = Foundation.FileManager.default
        let base = AuthStorage$Claude.baseService
        let directory = ProfileDirectories.home.appendingPathComponent(".claude")
        let alias = ProfileDirectories.claudeRoot.appendingPathComponent("shared-primary-owner")
        try fs.createDirectory(at: alias, withIntermediateDirectories: true)
        try fs.createSymbolicLink(at: directory, withDestinationURL: alias)
        let alternate = AuthStorage$Claude.profileService(forConfigPath: alias.path)
        Fixture.claudeEntries = [base: Fixture.claudeLogin("old-primary", expired: false),
                                 alternate: Fixture.claudeLogin("alternate", expired: false)]
        let file = directory.appendingPathComponent(".credentials.json")
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("alias-fallback", expired: false))
            .write(to: file)
        guard let account = Discovery$Real().discover().first(where: { $0.id == "claude:" + base }),
              AuthStorage$Claude.keychainServices(in: directory)?.contains(alternate) == true else {
            throw Failure(description: "Fixture did not attach both Keychain accounts to the shared directory")
        }
        if phase.hasPrefix("retry-") {
            ClaudeLifecycleSignals.opaqueService = base
            Fixture.denyClaudeRead = true
        }
        func cut() {
            let values = UserDefaults.standard.dictionaryRepresentation()
            try! PropertyListSerialization.data(fromPropertyList: values, format: .binary, options: 0)
                .write(to: sharedPrimaryCheckpoint)
            _exit(86)
        }
        if phase == "before" {
            Fixture.beforeCredentialDelete = cut
        } else {
            ClaudeLifecycleSignals.afterKeychainDeletion = { if $0 == base { cut() } }
        }
        try AccountRemoval.remove(account)
        throw Failure(description: "The shared primary did not reach the Keychain interruption boundary")
    }

    @MainActor
    private static func sharedPrimaryReplay(phase: String) throws {
        let values = try PropertyListSerialization.propertyList(from: Data(contentsOf: sharedPrimaryCheckpoint),
                                                                 options: [], format: nil) as! [String: Any]
        for (key, value) in values { UserDefaults.standard.set(value, forKey: key) }
        let base = AuthStorage$Claude.baseService
        let primaryID = "claude:" + base
        let directory = ProfileDirectories.home.appendingPathComponent(".claude")
        let alias = ProfileDirectories.claudeRoot.appendingPathComponent("shared-primary-owner")
        let alternate = AuthStorage$Claude.profileService(forConfigPath: alias.path)
        Fixture.claudeEntries = [alternate: Fixture.claudeLogin("alternate", expired: false)]
        if phase == "before" { Fixture.claudeEntries?[base] = Fixture.claudeLogin("old-primary", expired: false) }
        if phase == "keychain-replacement" || phase.hasPrefix("retry-") {
            Fixture.claudeEntries?[base] = Fixture.claudeLogin("replacement-primary", expired: false)
        }
        let file = directory.appendingPathComponent(".credentials.json")
        if phase.hasPrefix("retry-") {
            try sharedPrimaryRetry(file: file, sameFallback: phase == "retry-same")
            return
        }
        if phase == "replacement" {
            try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("new-native-file", expired: false))
                .write(to: file, options: .atomic)
        }
        if phase == "metadata-denied" {
            Fixture.denyClaudeMetadata = true
            try expect(!Discovery$Real().discover().contains(where: { $0.id == primaryID }),
                       "Metadata refusal promoted the retained alias fallback to primary")
            Fixture.denyClaudeMetadata = false
        }
        let accounts = Discovery$Real().discover()
        try expect(accounts.contains(where: { $0.id == "claude:" + alternate }),
                   "Recovery removed the independent Keychain alias")
        let wantedPrimary = ["before", "replacement", "keychain-replacement"].contains(phase)
        try expect(accounts.contains(where: { $0.id == primaryID }) == wantedPrimary,
                   "Restart reintroduced a deleted primary or hid an independent fresh login")
        if phase == "before" {
            Fixture.claudeEntries?[base] = nil
            try expect(Discovery$Real().discover().contains(where: { $0.id == primaryID }),
                       "An interrupted preparation suppressed the native file after an unrelated logout")
        }
        if phase == "keychain-replacement" {
            try expect(Fixture.claudeEntries?[base].flatMap(AuthStorage$Claude.parse)?.accessToken
                       == "synthetic-replacement-primary", "Recovery changed the independent primary Keychain login")
            Fixture.claudeEntries?[base] = nil
            try expect(!Discovery$Real().discover().contains(where: { $0.id == primaryID }),
                       "The replacement primary's later logout exposed the retained alias fallback")
        }
        let data = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        let expected = phase == "replacement" ? "new-native-file" : "alias-fallback"
        try expect(AuthStorage$Claude.parse(data)?.accessToken == "synthetic-" + expected,
                   "Recovery altered the native fallback file")
    }

    @MainActor
    private static func sharedPrimaryRetry(file: URL, sameFallback: Bool) throws {
        let key = "claudePendingPrimaryFallbackRemoval"
        let defaults = UserDefaults.standard
        let service = AuthStorage$Claude.baseService
        guard let previous = defaults.data(forKey: key),
              let account = Discovery$Real().discover().first(where: { $0.id == "claude:" + service }),
              defaults.data(forKey: key) == previous else {
            throw Failure(description: "The fixture did not retain the earlier unresolved shared-primary receipt")
        }
        if !sameFallback {
            try nativeFallbackBytes("another-alias-fallback").write(to: file, options: .atomic)
        }
        var prepared: Data?
        Fixture.beforeCredentialDelete = { prepared = defaults.data(forKey: key) }
        Fixture.denyKeychainDelete = true
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        try expect(refused && prepared != nil && Fixture.claudeEntries?[service] != nil,
                   "The retry did not reach the refused Keychain deletion")
        try expect((prepared == previous) == sameFallback,
                   "The retry changed the receipt for the same fallback or did not record a new fallback")
        try expect(defaults.data(forKey: key) == previous, "The refused retry discarded the earlier shared-primary receipt")
    }

    private static var nativeFallbackInode: URL {
        Fixture.root.appendingPathComponent("native-fallback-inode")
    }

    private static func nativeFallbackBytes(_ login: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: Fixture.claudeLogin(login, expired: true), options: .sortedKeys)
    }

    @MainActor
    private static func nativePrimaryCut(phase: String) throws {
        let manager = Foundation.FileManager.default
        let directory = Fixture.storageDirectory
        let service = AuthStorage$Claude.baseService
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent(".credentials.json")
        try nativeFallbackBytes("old-native-file").write(to: file)
        let attributes = try manager.attributesOfItem(atPath: file.path)
        let inode = (attributes[.systemFileNumber] as! NSNumber).stringValue
        try Data(inode.utf8).write(to: nativeFallbackInode)
        try Data("native-config".utf8).write(to: directory.appendingPathComponent("config-marker"))
        Fixture.claudeEntries = [service: Fixture.claudeLogin("old-native-keychain", expired: false)]
        guard let account = Discovery$Real().discover().first(where: { $0.id == "claude:" + service }),
              AuthStorage$Claude.keychainServices(in: directory) == [service] else {
            throw Failure(description: "The fixture did not discover an unshared native login")
        }
        if phase == "opaque" {
            ClaudeLifecycleSignals.opaqueService = service
            Fixture.denyClaudeRead = true
        }
        if phase == "deleted" { ClaudeLifecycleSignals.cutAfterCredentialDelete = service }
        else { ClaudeLifecycleSignals.cutAfterFallback = true }
        try AccountRemoval.remove(account)
        throw Failure(description: "Native removal did not reach the expected interruption boundary")
    }

    @MainActor
    private static func nativePrimaryReplay(phase: String) throws {
        let manager = Foundation.FileManager.default
        let directory = Fixture.storageDirectory
        let file = directory.appendingPathComponent(".credentials.json")
        let service = AuthStorage$Claude.baseService
        let deleted = phase == "deleted"
        Fixture.claudeEntries = deleted ? [:] : [service: Fixture.claudeLogin("old-native-keychain", expired: false)]
        if phase == "opaque" { ClaudeLifecycleSignals.opaqueService = service }
        try expect(!manager.fileExists(atPath: file.path), "The child stopped before isolating the native fallback")
        func checkpoints() throws -> [URL] {
            try manager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.lastPathComponent.hasPrefix(".credentials-") && $0.lastPathComponent.hasSuffix(".removal") }
        }
        let original = try nativeFallbackBytes("old-native-file")
        if phase == "keychain-replacement" || phase == "keychain-denied" {
            let replaced = phase == "keychain-replacement"
            if replaced {
                Fixture.claudeEntries?[service] = Fixture.claudeLogin("replacement-primary", expired: false)
            } else {
                Fixture.denyClaudeRead = true
                Fixture.denyClaudeMetadata = true
            }
            let accounts = Discovery$Real().discover()
            let pending = try checkpoints()
            try expect(!manager.fileExists(atPath: file.path) && pending.count == 1
                       && Data(contentsOf: pending[0]) == original,
                       "Recovery exposed or lost the native fallback without verifying Keychain ownership")
            if replaced {
                try expect(accounts.contains(where: { $0.id == "claude:" + service })
                           && Fixture.claudeEntries?[service].flatMap(AuthStorage$Claude.parse)?.accessToken
                                == "synthetic-replacement-primary",
                           "Recovery changed the replacement primary")
                return
            }
            Fixture.denyClaudeRead = false
            Fixture.denyClaudeMetadata = false
        }
        if phase == "replacement" {
            let replacement = try nativeFallbackBytes("replacement-native-file")
            try replacement.write(to: file)
            _ = Discovery$Real().discover()
            let pending = try checkpoints()
            try expect(try Data(contentsOf: file) == replacement && pending.count == 1
                       && Data(contentsOf: pending[0]) == original,
                       "Recovery did not preserve both the new native file and the original checkpoint")
            // Retry after the independent login no longer occupies the native path.
            try manager.removeItem(at: file)
        }
        let accounts = Discovery$Real().discover()
        try expect(try checkpoints().isEmpty, "Restart left a resolved native checkpoint behind")
        try expect(try String(contentsOf: directory.appendingPathComponent("config-marker"), encoding: .utf8) == "native-config",
                   "Native credential cleanup changed unrelated profile configuration")
        try expect(accounts.contains(where: { $0.id == "claude:" + service }) == !deleted,
                   "Restart changed the committed state of the native account")
        if deleted {
            try expect(!manager.fileExists(atPath: file.path), "Restart restored a committed removal's fallback")
        } else {
            try expect(manager.fileExists(atPath: file.path), "Restart did not restore the native fallback")
            let expectedInode = try String(contentsOf: nativeFallbackInode, encoding: .utf8)
            let attributes = try manager.attributesOfItem(atPath: file.path)
            let inode = (attributes[.systemFileNumber] as? NSNumber)?.stringValue
            try expect(try Data(contentsOf: file) == original && inode == expectedInode,
                       "Restart did not restore the original native fallback inode and bytes")
        }
    }

    @MainActor
    private static func desktopRollbackCut(selected: Bool) throws {
        Fixture.claudeEntries = [:]
        try switchTo(profile(file: true, name: "previous").0)
        CLISelection$Claude.isEnabled = selected
        let (target, directory) = try profile(file: true, name: retiringProfileName)
        try switchTo(target)
        try Data("previous Desktop session".utf8).write(to: desktopDirectory().appendingPathComponent("session"))
        Fixture.beforeCredentialDelete = {
            try! Foundation.FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        Fixture.denyKeychainDelete = true
        ClaudeLifecycleSignals.cutAfterCredentialRollback = true
        try AccountRemoval.remove(target)
        throw Failure(description: "Refused deletion did not reach the exclusive file restore")
    }

    @MainActor
    private static func desktopRollbackReplay(mode: String) throws {
        Fixture.claudeEntries = [:]
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent(retiringProfileName)
        let service = AuthStorage$Claude.profileService(forConfigPath: directory.path)
        try expect(AuthStorage$Claude.credentials(service: service, interactive: false, verifyingOwner: true)?.accessToken
                   == "synthetic-" + retiringProfileName,
                   "The child did not restore the original credential before it stopped")
        if mode == "restored" {
            try desktopRetirementReplay(deleted: false)
            return
        }

        let manager = Foundation.FileManager.default
        try expect(!manager.fileExists(atPath: cliPointer.path),
                   "The child had already published the old selection")
        if mode == "copied" {
            let file = directory.appendingPathComponent(".credentials.json")
            let original = try manager.attributesOfItem(atPath: file.path)[.systemFileNumber] as? NSNumber
            try Data(contentsOf: file).write(to: file, options: .atomic)
            let copy = try manager.attributesOfItem(atPath: file.path)[.systemFileNumber] as? NSNumber
            try expect(original != nil && copy != nil && original != copy,
                       "The matching credentials were not replaced by a different file")
            _ = Discovery$Real().discover()
            let invoked = try invokeCLI()
            try expect(!manager.fileExists(atPath: cliPointer.path) && invoked.0 != 0,
                       "The CLI restored a byte-identical copy without the recorded credential inode")
            return
        }

        if mode == "locked" {
            let native = directory.appendingPathComponent(".oauth_refresh.lock")
            try manager.createDirectory(at: native, withIntermediateDirectories: false)
            _ = Discovery$Real().discover()
            try expect(!manager.fileExists(atPath: cliPointer.path),
                       "Replay took over a live native OAuth lock")
            try manager.removeItem(at: native)
        }
        _ = Discovery$Real().discover()
        let expected = directory.path + "\n"
        try expect((try? String(contentsOf: cliPointer, encoding: .utf8)) == expected,
                   "Restart did not restore the selection for the exact rolled-back credential file")
        let invoked = try invokeCLI()
        try expect(invoked.0 == 0 && invoked.1 == expected, "The rebound selection could not route CLI")
        try desktopRetirementReplay(deleted: false, selectedName: retiringProfileName)
    }

    @MainActor
    private static func cliRetirementCut(phase: String, backend: String, selection: String) throws {
        Fixture.claudeEntries = [:]
        let (target, directory) = try profile(file: backend == "file", name: retiringProfileName)
        let service = AuthStorage$Claude.profileService(forConfigPath: directory.path)
        if backend == "both" {
            let file = directory.appendingPathComponent(".credentials.json")
            let bytes = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("file-fallback", expired: false))
            try bytes.write(to: file)
            let attrs = try Foundation.FileManager.default.attributesOfItem(atPath: file.path)
            let inode = (attrs[.systemFileNumber] as! NSNumber).stringValue
            try bytes.write(to: Fixture.root.appendingPathComponent("retirement-fallback.original"))
            try Data(inode.utf8).write(to: Fixture.root.appendingPathComponent("retirement-fallback.inode"))
        }
        if selection == "target" {
            try switchTo(target)
        } else if selection == "previous" {
            try switchTo(profile(file: true, name: "previous").0)
        }
        if phase == "pointer" {
            ClaudeLifecycleSignals.cutAfterSelectionMove = cliPointer.path
        } else if phase == "fallback" {
            ClaudeLifecycleSignals.cutAfterFallback = true
        } else if phase == "fallback-committed" {
            ClaudeLifecycleSignals.cutAfterCredentialDelete = service
        } else {
            ClaudeLifecycleSignals.cutAfterProfileMove = directory.path
        }
        if phase == "opaque" {
            ClaudeLifecycleSignals.opaqueService = service
            Fixture.denyClaudeRead = true
        }
        try AccountRemoval.remove(target)
        throw Failure(description: "The interrupted removal boundary was not reached")
    }

    @MainActor
    private static func retirementWithoutProof() throws {
        Fixture.claudeEntries = [:]
        let (account, directory) = try profile(file: false, name: retiringProfileName)
        try switchTo(account)
        Fixture.denyClaudeRead = true
        var refused = false
        do { try AccountRemoval.remove(account) } catch { refused = true }
        let manager = Foundation.FileManager.default
        let hidden = try manager.contentsOfDirectory(atPath: ProfileDirectories.claudeRoot.path)
            .contains(where: { $0.hasPrefix(".removed-") })
        let service = AuthStorage$Claude.profileService(forConfigPath: directory.path)
        try expect(refused && !hidden && manager.fileExists(atPath: directory.path)
                   && Fixture.claudeEntries?[service] != nil
                   && (try? String(contentsOf: cliPointer, encoding: .utf8)) == directory.path + "\n",
                   "Opaque removal without a durable proof changed the managed route or credentials")
    }

    @MainActor
    private static func cliRetirementReplay(phase: String, backend: String, selection: String, behavior: String) throws {
        let manager = Foundation.FileManager.default
        let directory = ProfileDirectories.claudeRoot.appendingPathComponent(retiringProfileName)
        let service = AuthStorage$Claude.profileService(forConfigPath: directory.path)
        let id = "claude:" + service
        let file = directory.appendingPathComponent(".credentials.json")
        let staged = try manager.contentsOfDirectory(at: ProfileDirectories.claudeRoot, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(".removed-") }
        try expect(staged.count == (phase == "pointer" ? 0 : 1)
                   && manager.fileExists(atPath: directory.path) == (phase == "pointer"),
                   "The child did not stop at the expected physical removal boundary")
        guard let originalOwner = DirectoryIdentity.capture(staged.first ?? directory) else {
            throw Failure(description: "Cannot capture the profile at the interrupted removal boundary")
        }
        let archivedFile = staged.first?.appendingPathComponent(".credentials.json")
        let originalFile = backend == "file" ? try Data(contentsOf: archivedFile ?? file) : nil
        Fixture.claudeEntries = backend == "file" || phase == "fallback-committed"
            ? [:] : [service: Fixture.claudeLogin(retiringProfileName, expired: false)]
        if phase == "opaque" { ClaudeLifecycleSignals.opaqueService = service }
        let prior = try? String(contentsOf: cliPointer, encoding: .utf8)
        let previous = ProfileDirectories.claudeRoot.appendingPathComponent("previous").path + "\n"
        try expect(prior == (selection == "previous" ? previous : nil),
                   "The cut unexpectedly changed a different profile's CLI route")

        if phase == "fallback-committed" {
            _ = Discovery$Real().discover()
            let names = try manager.contentsOfDirectory(atPath: staged[0].path)
            try expect(!names.contains(where: { $0 == ".credentials.json" || $0.hasSuffix(".removal") })
                       && !manager.fileExists(atPath: directory.path) && !manager.fileExists(atPath: cliPointer.path),
                       "The committed Keychain removal left an isolated fallback or restored the deleted profile")
            return
        }
        if behavior == "opaque-replaced" {
            Fixture.claudeEntries?[service] = Fixture.claudeLogin("replacement", expired: false)
            try Data("different classic Keychain generation".utf8).write(to: Fixture.classicKeychainDatabase(), options: .atomic)
            _ = Discovery$Real().discover()
            try expect(!manager.fileExists(atPath: directory.path) && !manager.fileExists(atPath: cliPointer.path),
                       "Recovery adopted a changed opaque Keychain item with the same modification date")
            return
        }
        if behavior == "replacement" || behavior == "replacement-before-discovery" {
            let replacement = try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("replacement", expired: false))
            try manager.createDirectory(at: directory, withIntermediateDirectories: true)
            try replacement.write(to: file, options: .atomic)
            if behavior == "replacement" { _ = Discovery$Real().discover() }
            try expect(try Data(contentsOf: file) == replacement
                       && !manager.fileExists(atPath: cliPointer.path),
                       "Replay overwrote or selected an independent same-path login")
            if let archivedFile {
                let replacementAccount = DiscoveredAccount(id: id, provider: .claude, profileName: retiringProfileName,
                                                           source: .claudeKeychain(service: service, configDir: directory))
                try AccountRemoval.remove(replacementAccount)
                _ = Discovery$Real().discover()
                try expect(!manager.fileExists(atPath: directory.path),
                           "Removing the replacement resurrected the original profile")
                try expect(try Data(contentsOf: archivedFile) == originalFile,
                           "Reoccupation destroyed the independently staged old login")
            }
            let rejected = try invokeCLI()
            try expect(rejected.0 != 0, "The CLI used a retired route after a replacement login")
            return
        }

        var newerSelection: String?
        if behavior == "denied" || behavior == "newer" {
            Fixture.denyClaudeRead = true
            _ = Discovery$Real().discover()
            try expect(!manager.fileExists(atPath: cliPointer.path)
                       && (phase == "pointer" || !manager.fileExists(atPath: directory.path)),
                       "Replay published an unreadable login")
            if behavior == "newer" {
                let (newer, newerDirectory) = try profile(file: true, name: "newer")
                try switchTo(newer)
                newerSelection = newerDirectory.path + "\n"
            }
            Fixture.denyClaudeRead = false
        }

        // Recovery is discovery-driven and restores the old choice independently
        // of whether future Desktop switches are allowed to change CLI.
        CLISelection$Claude.isEnabled = false
        let discovered = Discovery$Real().discover()
        try expect(DirectoryIdentity.capture(directory)?.isSameDirectory(as: originalOwner) == true
                   && discovered.contains(where: { $0.id == id })
                   && AuthStorage$Claude.credentials(service: service, interactive: false, verifyingOwner: true)?.accessToken
                        == "synthetic-" + retiringProfileName,
                   "A fresh discovery did not recover the original Claude login")
        if backend == "file" {
            try expect(try Data(contentsOf: file) == originalFile, "Replay changed the original file credential")
        } else if backend == "both" {
            let original = try Data(contentsOf: Fixture.root.appendingPathComponent("retirement-fallback.original"))
            let inode = try String(contentsOf: Fixture.root.appendingPathComponent("retirement-fallback.inode"), encoding: .utf8)
            let restored = try manager.attributesOfItem(atPath: file.path)[.systemFileNumber] as? NSNumber
            try expect(try Data(contentsOf: file) == original && restored?.stringValue == inode,
                       "Recovery did not restore the exact fallback inode and bytes")
        }
        let expectedRoute = newerSelection ?? (selection == "target" ? directory.path + "\n" : prior)
        try expect((try? String(contentsOf: cliPointer, encoding: .utf8)) == expectedRoute,
                   "Replay lost the verified prior CLI route or replaced a newer choice")
        if let expectedRoute {
            let invoked = try invokeCLI()
            try expect(invoked.0 == 0 && invoked.1 == expectedRoute, "The recovered CLI route did not work")
        }
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

    private static func invokeCLI() throws -> (Int32, String) {
        let manager = Foundation.FileManager.default
        let script = cliSupport.appendingPathComponent("profile.sh")
        let fakeBin = Fixture.root.appendingPathComponent("bin")
        try manager.createDirectory(at: fakeBin, withIntermediateDirectories: true)
        let fake = fakeBin.appendingPathComponent("claude")
        try Data("#!/bin/sh\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\"\n".utf8).write(to: fake)
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
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

    @MainActor
    private static func cliRemoved(mode: String) throws {
        Fixture.claudeEntries = [:]
        let (account, directory) = try profile(file: true)
        let old = try profile(file: true, name: "previous")
        try switchTo(mode == "previous" ? old.0 : account)
        let manager = Foundation.FileManager.default
        let before = try invokeCLI()
        let expected = (mode == "previous" ? old.1 : directory).path + "\n"
        try expect(before.0 == 0 && before.1 == expected, "Original selected route did not work")
        if mode == "rollback-replacement" || mode == "rollback-empty" {
            let replacesLogin = mode == "rollback-replacement"
            let credentials = directory.appendingPathComponent(".credentials.json")
            let original = try Data(contentsOf: credentials)
            let previousDesktop = try desktopDirectory()
            let savedSession = previousDesktop.appendingPathComponent("session")
            try Data("desktop session before refusal".utf8).write(to: savedSession)
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
            guard let rediscovered = Discovery$Real().discover().first(where: { $0.id == account.id }) else {
                throw Failure(description: "The profile was not rediscovered after refused removal")
            }
            try switchTo(rediscovered)
            try expect((try desktopDirectory().path == previousDesktop.path) == !replacesLogin
                       && (try String(contentsOf: savedSession, encoding: .utf8)) == "desktop session before refusal",
                       "Desktop rollback reused the retired owner or lost the verified restored session")
            try switchTo(old.0)
            let invoked = try invokeCLI()
            print("rollback collision reached=\(reached) refused=\(refused) CLI used replacement=\(invoked.0 == 0 && invoked.1 == expected)")
            try expect(replacesLogin ? invoked.0 != 0 && invoked.1.isEmpty : invoked.0 == 0 && invoked.1 == expected,
                       "Rollback did not retain the route matching the credentials after recovery")
            return
        } else if mode == "refused" || mode == "pointer-refused" {
            Fixture.denyCredentialFileRemoval = mode == "refused"
            if mode == "pointer-refused" {
                ClaudeLifecycleSignals.deniedSelection = cliPointer.path
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
                let removed = try invokeCLI()
                try expect(removed.0 != 0 && removed.1.isEmpty, "Removed target still ran while absent")
            }
            let (_, replacement) = try profile(file: true, login: "different-login")
            try expect(account.claudeConfigOwner?.matches(replacement) == false, "The replacement must use a new physical directory")
            // Desktop-only switches explicitly preserve the previous CLI choice.
            CLISelection$Claude.isEnabled = false
            try switchTo(old.0)
        }
        let after = try invokeCLI()
        print("cli-removed", mode, "status", after.0, "routed into reusable path", after.1 == expected)
        if ["replacement", "orphan"].contains(mode) {
            try expect(after.0 != 0 && after.1.isEmpty, "The retired selection resumed under a replacement login without a CLI switch")
            CLISelection$Claude.isEnabled = true
            guard let replacement = Discovery$Real().discover().first(where: { $0.id == account.id }) else {
                throw Failure(description: "Real discovery missed the re-added profile")
            }
            try switchTo(replacement)
            let selected = try invokeCLI()
            try expect(selected.0 == 0 && selected.1 == expected, "An explicit switch could not select the re-added profile")
        } else {
            try expect(after.0 == 0 && after.1 == expected, "An unchanged or independent selected profile stopped routing")
        }
    }

    @MainActor
    private static func dotdir(mode: String) throws {
        Fixture.claudeEntries = [:]
        let (account, profile) = try profile(file: true)
        let manager = Foundation.FileManager.default
        let dotfiles = Fixture.root.appendingPathComponent("dotfiles")
        try manager.createDirectory(at: dotfiles, withIntermediateDirectories: true)
        if mode != "default" {
            let assignment: String
            switch mode {
            case "interactive": assignment = "if [[ -o interactive ]]; then ZDOTDIR=$HOME/dotfiles; fi\n"
            case "login": assignment = "if [[ -o login ]]; then ZDOTDIR=$HOME/dotfiles; fi\n"
            default: assignment = "ZDOTDIR=$HOME/dotfiles\n"
            }
            let startup = mode == "login" ? ".zprofile" : ".zshenv"
            try Data(assignment.utf8).write(to: Fixture.root.appendingPathComponent(startup))
            try Data("# existing interactive setup\n".utf8).write(to: dotfiles.appendingPathComponent(".zshrc"))
        }
        try switchTo(account)
        let fake = dotfiles.appendingPathComponent("claude")
        try Data("#!/bin/sh\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\"\n".utf8).write(to: fake)
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        for flags in mode == "login" ? ["-il", "-i"] : ["-i"] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/zsh")
            process.arguments = [flags, "-c", "claude"]
            process.environment = ["HOME": Fixture.root.path, "PATH": dotfiles.path + ":/usr/bin:/bin", "TERM": "dumb"]
            let out = Pipe()
            process.standardOutput = out
            process.standardError = Pipe()
            try process.run()
            process.waitUntilExit()
            let result = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            try expect(process.terminationStatus == 0 && result == profile.path + "\n",
                       "New zsh \(flags) ignored a CLI selection reported successful by the switch")
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
