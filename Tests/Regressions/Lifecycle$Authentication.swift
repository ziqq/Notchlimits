// The harness prepends Authentication.swift's synthetic OS/network boundaries.
private struct QueuedCodexUsage: UsageProvider {
    let beforePublication: () throws -> Void

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        await Provider$Codex().fetch(account)
    }

    func fetchValidated(_ account: DiscoveredAccount) async -> UsageFetchResult {
        let result = await Provider$Codex().fetchValidated(account)
        guard case .success = result.outcome, let isCurrent = result.isCurrent else { return result }
        return UsageFetchResult(outcome: result.outcome, isCurrent: {
            try beforePublication()
            return try isCurrent()
        }, loginID: result.loginID)
    }
}

@main
enum Lifecycle$Authentication {
    static func main() async {
        do {
            let parts = CommandLine.arguments[1].split(separator: ":").map(String.init)
            switch parts[0] {
            case "usage-child": try await usageChild()
            case "create": try nativeCreation()
            case "switch": try await nativeSwitch(mode: parts[1], change: parts[2], late: parts[3] == "late")
            case "renew": try await nativeRenewal(mode: parts[1], change: parts[2])
            case "usage": try await usageLogin(codex: parts[1] == "codex", mode: parts[2], change: parts[3])
            case "usage-keychain-owner": try await queuedKeychainUsage(replaceOwner: parts[1] == "replace")
            default: throw Failure(description: "Unknown authentication lifecycle scenario")
            }
        } catch { print("FAIL: \(error)"); exit(1) }
    }

    private static func login(_ home: URL, account: String, mode: String, expired: Bool = false) throws {
        try Fixture.codexLogin(home, account: account, mode: mode == "auto-file" ? "auto" : mode, expired: expired)
        if mode == "auto-file" {
            guard let data = Fixture.codexKeychain.removeValue(forKey: Fixture.codexKey(home)) else {
                throw Failure(description: "Missing auto fallback fixture")
            }
            try data.write(to: home.appendingPathComponent("auth.json"))
        }
    }

    private static func pause(_ path: URL, afterCopyback: Bool = false) {
        Fixture.pauseAuthReadPath = path.appendingPathComponent("auth.json").path
        if afterCopyback {
            Fixture.authReadRequiresPath = AuthSwap$Codex.stashHome.appendingPathComponent("config.toml").path
        }
    }

    private static func waitForRead() async throws {
        for _ in 0..<400 {
            Fixture.lock.lock(); let paused = Fixture.authReadPaused; Fixture.lock.unlock()
            if paused { return }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        throw Failure(description: "The production auth read did not reach the OS gate")
    }

    private static func releaseRead() {
        Fixture.lock.lock(); Fixture.releaseAuthRead = true; Fixture.lock.unlock()
    }

    private static func changeNative(_ change: String, link: URL, old: URL, fresh: URL, source: URL) throws {
        let manager = Foundation.FileManager.default
        switch change {
        case "retarget", "promote":
            try manager.removeItem(at: link)
            try manager.createSymbolicLink(at: link, withDestinationURL: change == "promote" ? source : fresh)
        case "replace":
            try manager.moveItem(at: old, to: old.appendingPathExtension("retired"))
            try login(old, account: "replacement-native", mode: "file")
        case "mode": try Fixture.codexMode(old, "keyring")
        case "stable": break
        default: throw Failure(description: "Unknown native mutation")
        }
    }

    private static func setupNative(mode: String) throws -> (URL, URL, URL, URL) {
        Fixture.keychainExists = false
        let old = Fixture.root.appendingPathComponent("native-old")
        let fresh = Fixture.root.appendingPathComponent("native-new")
        let link = Fixture.root.appendingPathComponent("native-link")
        let source = ProfileDirectories.codexRoot.appendingPathComponent("incoming")
        try login(old, account: "old-native", mode: mode)
        try login(fresh, account: "new-native", mode: mode)
        try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
        Fixture.codexHome = link.path
        return (old, fresh, link, source)
    }

    private static func nativeSwitch(mode: String, change: String, late: Bool) async throws {
        let (old, fresh, link, source) = try setupNative(mode: mode)
        try login(source, account: "incoming", mode: "file")
        let original = try AuthSwap$Codex.authData(home: old)
        let newLogin = try AuthSwap$Codex.authData(home: fresh)
        let incoming = try AuthSwap$Codex.authData(home: source)
        pause(source, afterCopyback: late)
        let task = Task.detached { () -> Bool in
            do { try AuthSwap$Codex.activate(columnID: "codex:incoming", home: source); return true }
            catch { return false }
        }
        defer { releaseRead() }
        try await waitForRead()
        try changeNative(change, link: link, old: old, fresh: fresh, source: source)
        releaseRead()
        let succeeded = await task.value
        let previousHome = change == "replace" ? old.appendingPathExtension("retired") : old
        print("SWITCH mode=\(mode) change=\(change) late=\(late) succeeded=\(succeeded)")
        if change == "stable" {
            try expect(succeeded && AuthSwap$Codex.activeColumnID == "codex:incoming",
                       "An unchanged native owner could not switch")
            try expect(try AuthSwap$Codex.authData(home: old) == incoming
                       && AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) == original,
                       "A stable switch did not preserve the original login in its backup")
        } else {
            let previous = try change == "mode"
                ? AuthStorage$Codex(home: previousHome, mode: .file).load()?.data
                : AuthSwap$Codex.authData(home: previousHome)
            try expect(previous == original,
                       "A changed native context overwrote the original native credentials")
            try expect(!succeeded && AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                       "A changed native context published a stale switch or active marker")
            if change == "retarget" {
                try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) != newLogin,
                           "Copyback used an unrelated replacement native login")
            }
        }
        try expect(try AuthSwap$Codex.authData(home: fresh) == newLogin
                   && AuthSwap$Codex.authData(home: source) == incoming,
                   "Switching changed an independent native login or incoming profile")
        try expect(Fixture.refreshCalls == 0, "Switching issued a refresh POST")
        // A failed attempt releases the lock and leaves a later explicit switch usable.
        if change == "retarget" {
            try Foundation.FileManager.default.removeItem(at: link)
            try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
            try AuthSwap$Codex.activate(columnID: "codex:incoming", home: source)
            try expect(try AuthSwap$Codex.authData(home: AuthSwap$Codex.stashHome) == original,
                       "Retry lost the original native login or retained a failed reservation")
        }
    }

    private static func nativeCreation() throws {
        let (old, _, link, source) = try setupNative(mode: "file")
        try login(source, account: "incoming", mode: "file")
        let original = try AuthSwap$Codex.authData(home: old)
        let retired = old.appendingPathExtension("retired")
        var replacement: Data?
        Fixture.beforeDirectoryCreate = { url in
            guard url.path == old.path || url.path == link.path else { return }
            Fixture.beforeDirectoryCreate = nil
            try Foundation.FileManager.default.moveItem(at: old, to: retired)
            try login(old, account: "replacement-native", mode: "file")
            replacement = try Data(contentsOf: old.appendingPathComponent("auth.json"))
        }
        var succeeded = false
        do { try AuthSwap$Codex.activate(columnID: "codex:incoming", home: source); succeeded = true }
        catch {}
        try expect(replacement != nil, "The directory creation boundary was not reached")
        try expect(try AuthSwap$Codex.authData(home: old) == replacement
                   && AuthSwap$Codex.authData(home: retired) == original && !succeeded,
                   "Directory creation re-adopted a replacement native owner and overwrote its login")
        try expect(AuthSwap$Codex.activeColumnID == AuthSwap$Codex.defaultColumnID,
                   "A refused native creation published the active selection")
    }

    private static func nativeRenewal(mode: String, change: String) async throws {
        let (old, fresh, link, source) = try setupNative(mode: mode)
        try login(source, account: "sleeping", mode: "file", expired: true)
        let original = try AuthSwap$Codex.authData(home: source)
        pause(source)
        let task = Task {
            await Renewal$Codex.shared.renew(columnID: "codex:incoming", home: source, force: false)
        }
        defer { releaseRead() }
        try await waitForRead()
        try changeNative(change, link: link, old: old, fresh: fresh, source: source)
        releaseRead()
        let result = await task.value
        print("RENEW mode=\(mode) change=\(change) posts=\(Fixture.refreshCalls) result=\(result)")
        if change == "stable" {
            try expect(Fixture.refreshCalls == 1 && result == .renewed,
                       "A sleeping independent login no longer renews automatically")
        } else {
            try expect(Fixture.refreshCalls == 0 && result != .renewed,
                       "A changed native context admitted a refresh POST")
            try expect(try AuthSwap$Codex.authData(home: source) == original,
                       "A refused renewal changed the now-native or sleeping login")
            if change == "promote" || change == "retarget" {
                try Foundation.FileManager.default.removeItem(at: link)
                try Foundation.FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
                let retry = await Renewal$Codex.shared.renew(columnID: "codex:incoming", home: source, force: false)
                try expect(retry == .renewed && Fixture.refreshCalls == 1,
                           "Refused admission stranded a reservation or quarantined an unspent grant")
            }
        }
    }

    @MainActor
    private static func queuedKeychainUsage(replaceOwner: Bool) async throws {
        Fixture.keychainExists = false
        Fixture.manualPollingTimer = true
        let home = ProfileDirectories.codexRoot.appendingPathComponent("queued-keychain")
        let id = AuthSwap$Codex.profileColumnID(home.lastPathComponent)
        let window = "main.primary_window"
        try login(home, account: "queued-keychain", mode: "keyring")
        guard let original = try AuthSwap$Codex.authData(home: home), let owner = DirectoryIdentity.capture(home) else {
            throw Failure(description: "Missing initial Keychain login or profile directory")
        }
        Fixture.usageErrorBody = Data(#"{"rate_limit":{"primary_window":{"used_percent":85,"limit_window_seconds":18000}}}"#.utf8)
        var reachedPublication = false
        let provider = QueuedCodexUsage(beforePublication: {
            guard !reachedPublication else { return }
            if replaceOwner {
                try Foundation.FileManager.default.moveItem(at: home, to: Fixture.root.appendingPathComponent("old-queued-keychain"))
                try Fixture.codexMode(home, "keyring")
            }
            try expect(owner.matches(home) != replaceOwner && AuthSwap$Codex.authData(home: home) == original,
                       "The publication boundary did not preserve Keychain data while checking the physical owner")
            reachedPublication = true
        })
        let store = UsageStore(providers: [.codex: provider], discovery: RoutedUsageDiscovery(accountID: id))
        store.start()
        for _ in 0..<400 {
            if reachedPublication { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try expect(reachedPublication, "The successful usage response never reached its publication check")
        let published = try currentUsageColumn(store, id: id)
        let cached = UsageCache().load(id: id)
        if replaceOwner {
            try expect(!published.hasData && cached == nil && history(id, window).isEmpty && Fixture.notifications.isEmpty,
                       "Queued usage was published after its Keychain-backed directory was replaced")
            Fixture.usageErrorBody = Data(#"{"rate_limit":{"primary_window":{"used_percent":40,"limit_window_seconds":18000}}}"#.utf8)
            store.refreshAll()
            try await waitForUsage(store, id: id, value: 40)
            try expect(history(id, window) == [40] && Fixture.notifications.isEmpty,
                       "The new directory could not establish usage independently")
        } else {
            try expect(published.windows.first?.utilization == 85 && cached?.windows == published.windows
                       && history(id, window) == [85] && Fixture.notifications.count == 1,
                       "The unchanged Keychain owner did not publish its successful result")
        }
        try expect(Fixture.usageCalls == (replaceOwner ? 2 : 1) && Fixture.refreshCalls == 0,
                   "Publication caused an extra usage poll or refresh")
    }

    @MainActor
    private static func usageLogin(codex: Bool, mode: String, change requested: String) async throws {
        let restart = requested.hasPrefix("restart-")
        let change = restart ? String(requested.dropFirst("restart-".count)) : requested
        Fixture.manualPollingTimer = true
        let id: String
        let home: URL
        let provider: any UsageProvider
        let kind: Provider = codex ? .codex : .claude
        let window = codex ? "main.primary_window" : "five_hour"
        if codex {
            Fixture.keychainExists = false
            home = ProfileDirectories.codexRoot.appendingPathComponent("usage-login")
            id = "codex:usage-login"
            try login(home, account: "old-usage", mode: mode)
            guard let original = try AuthSwap$Codex.authData(home: home),
                  let epoch = AuthSwap$Codex.usageLogin(original) else {
                throw Failure(description: "Missing original Codex usage epoch")
            }
            Fixture.seedUsageEpoch(epoch, columnID: id)
            provider = Provider$Codex()
        } else {
            home = Fixture.storageDirectory
            id = "claude:" + Fixture.service
            try Foundation.FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            Fixture.keychainExists = mode == "keyring"
            if Fixture.keychainExists {
                Fixture.keychain = Fixture.claudeLogin("old-usage", expired: false)
                Fixture.discoveredClaudeService = Fixture.service
            } else {
                try JSONSerialization.data(withJSONObject: Fixture.claudeLogin("old-usage", expired: false))
                    .write(to: home.appendingPathComponent(".credentials.json"))
            }
            guard let original = AuthStorage$Claude.credentials(service: Fixture.service) else {
                throw Failure(description: "Missing original Claude usage epoch")
            }
            Fixture.seedClaudeUsageEpoch(original, columnID: id)
            provider = Provider$Claude()
        }
        let owner = DirectoryIdentity.capture(home)
        let seedWindow = LimitWindow(key: window, title: "Usage", utilization: 7, resetsAt: nil)
        _ = UsageHistory().record(columnID: id, window: seedWindow, now: Date().addingTimeInterval(-300))
        var seed = AccountColumn(id: id, provider: kind, profileName: "Usage")
        seed.windows = [LimitWindow(key: window, title: "Usage", utilization: 96, resetsAt: nil)]
        ThresholdNotifier().evaluate(column: seed)
        Fixture.notifications = []
        let store = UsageStore(providers: [kind: provider], discovery: RoutedUsageDiscovery(accountID: id))
        store.setCustomName("Preserved name", for: id)
        store.setHidden(id, hidden: true)
        store.start()
        try await waitForUsage(store, id: id, value: 12)
        try expect(history(id, window) == [7, 12] && Fixture.refreshCalls == 0,
                   "The first completed production poll did not establish the original usage epoch")

        if change.hasPrefix("warm-") {
            try await checkWarmUsage(store, id: id, window: window, home: home, mode: mode,
                                     codex: codex, phase: String(change.dropFirst("warm-".count)))
            return
        }

        if change == "denied" {
            // Even a readable fallback with the same tokens cannot prove who
            // owns the preferred Keychain login while selected reads are denied.
            if codex {
                guard let credentials = Fixture.codexKeychain[Fixture.codexKey(home)] else {
                    throw Failure(description: "Missing preferred Codex login")
                }
                try credentials.write(to: home.appendingPathComponent("auth.json"))
            } else {
                try JSONSerialization.data(withJSONObject: Fixture.keychain)
                    .write(to: home.appendingPathComponent(".credentials.json"))
            }
        } else if change == "unowned" {
            UserDefaults.standard.removeObject(forKey: "usageLoginEpochs")
        } else if change != "stable" {
            if codex {
                if change == "renew" {
                    let result = await Renewal$Codex.shared.renew(columnID: id, home: home, force: true)
                    try expect(result == .renewed, "The continuing Codex session did not renew")
                } else if change == "metadata" {
                    var root = try JSONSerialization.jsonObject(with: AuthSwap$Codex.authData(home: home)!) as! [String: Any]
                    root["last_refresh"] = "metadata-only"
                    let storage = try AuthStorage$Codex(home: home)
                    try storage.save(JSONSerialization.data(withJSONObject: root), backend: mode == "auto-file" ? .file : nil)
                } else {
                    try login(home, account: "new-usage", mode: mode, expired: change == "reauth")
                    if change == "reauth" {
                        var root = try JSONSerialization.jsonObject(with: AuthSwap$Codex.authData(home: home)!) as! [String: Any]
                        var tokens = root["tokens"] as! [String: Any]
                        tokens.removeValue(forKey: "refresh_token")
                        root["tokens"] = tokens
                        try AuthStorage$Codex(home: home).save(JSONSerialization.data(withJSONObject: root),
                                                              backend: mode == "auto-file" ? .file : nil)
                    }
                }
            } else {
                let name = change == "renew" || change == "metadata" ? "old-usage" : "new-usage"
                var credentials = Fixture.claudeLogin(name, expired: change == "renew" || change == "reauth")
                if change == "metadata" { credentials["unknown"] = "new-metadata" }
                if change == "reauth" {
                    var oauth = credentials["claudeAiOauth"] as! [String: Any]
                    oauth.removeValue(forKey: "refreshToken")
                    credentials["claudeAiOauth"] = oauth
                }
                if mode == "keyring" { Fixture.keychain = credentials }
                else {
                    try JSONSerialization.data(withJSONObject: credentials)
                        .write(to: home.appendingPathComponent(".credentials.json"))
                }
            }
        }
        try expect(DirectoryIdentity.capture(home) == owner, "Usage mutation replaced its physical directory")
        if !codex && change == "renew" {
            Fixture.usageStatus = 401
            store.refreshAll()
            for _ in 0..<400 {
                if case .reauth = store.columns.first?.status { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            try expect(Fixture.refreshCalls == 0, "Claude refreshed before its live token was rejected")
        }
        Fixture.usageErrorBody = Data(#"{"five_hour":{"utilization":85},"rate_limit":{"primary_window":{"used_percent":85,"limit_window_seconds":18000}}}"#.utf8)
        Fixture.usageStatus = change == "failure" ? 429 : 200
        if restart {
            let snapshot: [String: Any] = ["defaults": UserDefaults.standard.dictionaryRepresentation(),
                                           "claude": Fixture.keychain, "codex": Fixture.codexKeychain]
            let file = Fixture.root.appendingPathComponent("usage-restart.plist")
            try PropertyListSerialization.data(fromPropertyList: snapshot, format: .binary, options: 0).write(to: file)
            let child = Foundation.Process()
            child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            child.arguments = ["usage-child", Fixture.root.path, codex ? "codex" : "claude", mode, change]
            let output = Pipe()
            child.standardOutput = output
            child.standardError = output
            try child.run()
            child.waitUntilExit()
            let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            try expect(child.terminationStatus == 0, "A fresh process violated usage login ownership: " + text)
            return
        }
        store.rediscover(force: true)
        store.refreshAll()
        if change == "failure" || change == "reauth" {
            for _ in 0..<400 {
                if case .waiting = store.columns.first?.status { break }
                if case .reauth = store.columns.first?.status { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            try expect(store.columns.first?.windows.isEmpty == true
                       && UsageCache().load(id: id) == nil && history(id, window).isEmpty,
                       "A replacement login's error retained the old account's usage/cache/history")
        } else {
            try await waitForUsage(store, id: id, value: 85)
            let replaced = change == "replace"
            print("USAGE codex=\(codex) mode=\(mode) change=\(change) history=\(history(id, window)) notifications=\(Fixture.notifications.count)")
            try expect(history(id, window) == (replaced ? [85] : [7, 12, 85]),
                       "A new login inherited another account's history, or the same session lost its history")
            try expect(Fixture.notifications.count == (replaced ? 1 : 0),
                       "A new login inherited fired thresholds, or a continuing session notified twice")
            try expect(Fixture.refreshCalls == (change == "renew" ? 1 : 0),
                       "Usage issued an unexpected refresh POST")
        }
        try expect(store.customNames[id] == "Preserved name" && store.hidden.contains(id),
                   "Retiring usage removed the user's name or visibility preference")
    }

    @MainActor
    private static func checkWarmUsage(_ store: UsageStore, id: String, window: String, home: URL,
                                       mode: String, codex: Bool, phase: String) async throws {
        let replaced = ["replace", "replace-denied", "poll-denied"].contains(phase)
        let denied = phase.hasSuffix("-denied")
        let owner = DirectoryIdentity.capture(home)
        guard let profile = store.account(for: id) else {
            throw Failure(description: "Warm test did not start from a discovered profile")
        }
        let previous = try currentUsageColumn(store, id: id)
        let expectedRequests = Fixture.usageCalls
        let fallback: Data?
        if !denied { fallback = nil }
        else if codex { fallback = Fixture.codexKeychain[Fixture.codexKey(home)] }
        else { fallback = try JSONSerialization.data(withJSONObject: Fixture.keychain) }
        if replaced {
            if codex { try login(home, account: "new-warm-usage", mode: mode) }
            else {
                let credentials = Fixture.claudeLogin("new-warm-usage", expired: false)
                if mode == "keyring" { Fixture.keychain = credentials }
                else {
                    try JSONSerialization.data(withJSONObject: credentials)
                        .write(to: home.appendingPathComponent(".credentials.json"), options: .atomic)
                }
            }
        }
        if denied {
            guard let fallback else { throw Failure(description: "Missing older fallback for the denied owner") }
            try fallback.write(to: home.appendingPathComponent(codex ? "auth.json" : ".credentials.json"))
        }
        try expect(owner == DirectoryIdentity.capture(home),
                   "The same-path test changed the profile's physical owner")

        Fixture.denyCodexRead = denied && codex
        Fixture.denyClaudeRead = denied && !codex
        if phase == "busy" {
            try await rescanWithBusyKeychain(store)
        } else if phase == "poll-denied" {
            store.refreshAll()
            var finished = false
            for _ in 0..<400 {
                switch try currentUsageColumn(store, id: id).status {
                case .failed, .reauth: finished = true
                default: break
                }
                if finished { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            try expect(finished, "The polling path did not observe its denied credential proof")
        } else {
            store.rediscover(force: true)
        }
        try expect(store.account(for: id)?.source == profile.source,
                   "Warm discovery no longer points at the same profile route")
        let hidden = try currentUsageColumn(store, id: id)
        try expect(!hidden.hasData && hidden.subtitle == nil && hidden.updatedAt == nil && !hidden.fromCache,
                   "Warm usage exposed the previous owner without a current proof")
        if phase != "poll-denied" {
            try expect(Fixture.usageCalls == expectedRequests && Fixture.refreshCalls == 0,
                       "Rediscovery hid stale data only after calling a provider endpoint")
        }
        if denied || phase == "busy" {
            try expect(UsageCache().load(id: id)?.windows == previous.windows && history(id, window) == [7, 12],
                       "Temporary proof failure erased the last verified login's cache or history")
            Fixture.denyCodexRead = false
            Fixture.denyClaudeRead = false
            let requestsBeforeProof = Fixture.usageCalls
            store.rediscover(force: true)
            try expect(Fixture.usageCalls == requestsBeforeProof && Fixture.refreshCalls == 0,
                       "Restoring proof called a usage or refresh endpoint")
        }
        if replaced {
            let admitted = try currentUsageColumn(store, id: id)
            try expect(!admitted.hasData && UsageCache().load(id: id) == nil && history(id, window).isEmpty,
                       "Confirmed replacement inherited the old owner's cache or history")
            Fixture.usageErrorBody = Data(#"{"five_hour":{"utilization":85},"rate_limit":{"primary_window":{"used_percent":85,"limit_window_seconds":18000}}}"#.utf8)
            store.refreshAll()
            try await waitForUsage(store, id: id, value: 85)
            try expect(history(id, window) == [85] && Fixture.notifications.count == 1,
                       "Replacement usage reused history or notification thresholds")
        } else {
            let restored = try currentUsageColumn(store, id: id)
            try expect(restored.fromCache && restored.updatedAt == previous.updatedAt
                       && restored.windows == previous.windows && restored.stats == previous.stats
                       && restored.subtitle == previous.subtitle && history(id, window) == [7, 12]
                       && Fixture.notifications.isEmpty,
                       "The unchanged login did not recover its prior usage and notification state")
        }
        try expect(store.customNames[id] == "Preserved name" && store.hidden.contains(id),
                   "Warm ownership verification changed unrelated column preferences")
    }

    @MainActor
    private static func currentUsageColumn(_ store: UsageStore, id: String) throws -> AccountColumn {
        guard let column = store.columns.first(where: { $0.id == id }) else {
            throw Failure(description: "Warm discovery lost the profile")
        }
        return column
    }

    @MainActor
    private static func rescanWithBusyKeychain(_ store: UsageStore) async throws {
        let ready = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let holder = Task.detached {
            AuthStorage$Claude.access {
                ready.signal()
                return release.wait(timeout: .now() + 2) == .success ? errSecSuccess : errSecInteractionNotAllowed
            }
        }
        let entered = ready.wait(timeout: .now() + 2) == .success
        if entered { store.rediscover(force: true) }
        release.signal()
        let status = await holder.value
        try expect(entered, "The synthetic operation did not hold the real Keychain interaction lock")
        try expect(status == errSecSuccess, "Warm rediscovery waited behind an unrelated Keychain operation")
    }

    @MainActor
    private static func usageChild() async throws {
        let args = CommandLine.arguments
        let codex = args[3] == "codex"
        let mode = args[4]
        let change = args[5]
        let data = try Data(contentsOf: Fixture.root.appendingPathComponent("usage-restart.plist"))
        let snapshot = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        for (key, value) in snapshot["defaults"] as! [String: Any] { UserDefaults.standard.set(value, forKey: key) }
        Fixture.keychain = snapshot["claude"] as! [String: Any]
        Fixture.codexKeychain = snapshot["codex"] as! [String: Data]
        Fixture.keychainExists = !codex && mode == "keyring"
        Fixture.discoveredClaudeService = Fixture.keychainExists ? Fixture.service : nil
        Fixture.manualPollingTimer = true
        Fixture.usageErrorBody = Data(#"{"five_hour":{"utilization":85},"rate_limit":{"primary_window":{"used_percent":85,"limit_window_seconds":18000}}}"#.utf8)
        let id = codex ? "codex:usage-login" : "claude:" + Fixture.service
        let window = codex ? "main.primary_window" : "five_hour"
        let kind: Provider = codex ? .codex : .claude
        let provider: any UsageProvider = codex ? Provider$Codex() : Provider$Claude()
        let store = UsageStore(providers: [kind: provider], discovery: RoutedUsageDiscovery(accountID: id))
        let denied = change == "denied"
        let replaced = change == "replace" || change == "unowned"
        Fixture.denyCodexRead = codex && denied
        Fixture.denyClaudeRead = !codex && denied
        store.rediscover(force: true)
        guard let initial = store.columns.first(where: { $0.id == id }) else {
            throw Failure(description: "The restarted store did not discover the existing profile")
        }
        try expect(Fixture.usageCalls == 0 && Fixture.refreshCalls == 0,
                   "Startup verification issued a usage request or renewed credentials")
        print("COLD mode=\(mode) change=\(change) cached=\(initial.fromCache) usage=\(initial.windows.first?.utilization as Any)")
        if replaced || denied {
            try expect(initial.windows.isEmpty && initial.subtitle == nil && initial.stats.isEmpty
                       && initial.updatedAt == nil && !initial.fromCache && initial.status == .loading,
                       "Cold startup exposed usage before proving ownership of the cached login")
        } else {
            try expect(initial.fromCache && initial.windows.first?.utilization == 12 && initial.status == .ok,
                       "Cold startup hid the current owner's verified usage before polling")
        }
        if denied {
            try expect(UsageCache().load(id: id)?.windows.first?.utilization == 12 && history(id, window) == [7, 12],
                       "Temporary Keychain denial retired the continuing owner's persisted usage")
            Fixture.denyCodexRead = false
            Fixture.denyClaudeRead = false
            Fixture.usageStatus = 503
            store.start()
            for _ in 0..<400 {
                if case .failed = store.columns.first?.status { break }
                try await Task.sleep(nanoseconds: 5_000_000)
            }
            guard let restored = store.columns.first(where: { $0.id == id }), case .failed = restored.status else {
                throw Failure(description: "The continuing login did not reach the unavailable usage endpoint")
            }
            try expect(restored.fromCache && restored.windows.first?.utilization == 12 && Fixture.usageCalls == 1
                       && Fixture.refreshCalls == 0 && history(id, window) == [7, 12] && Fixture.notifications.isEmpty,
                       "A verified continuing login did not recover its cache after Keychain access returned")
            return
        }
        store.start()
        try await waitForUsage(store, id: id, value: 85)
        try expect(history(id, window) == (replaced ? [85] : [7, 12, 85]),
                   "A restarted process inherited another login's history or retired a continuing session")
        try expect(Fixture.notifications.count == (replaced ? 1 : 0),
                   "Restart mixed notification thresholds between login epochs")
        try expect(Fixture.refreshCalls == (!codex && change == "renew" ? 1 : 0),
                   "Restart replayed a refresh or failed to renew the continuing session")
        try expect(store.customNames[id] == "Preserved name" && store.hidden.contains(id),
                   "Restart lost unrelated usage preferences")
        for key in ["claudeUsageLogins", "codexUsageLogins"] {
            let epochs = UserDefaults.standard.dictionary(forKey: key) as? [String: String] ?? [:]
            try expect(epochs.keys.allSatisfy { $0.count == 64 && $0.allSatisfy { $0.isHexDigit } }
                       && epochs.values.allSatisfy { UUID(uuidString: $0) != nil },
                       "Persistent usage metadata contains raw credentials")
        }
    }

    private static func history(_ id: String, _ window: String) -> [Double] {
        guard let data = UserDefaults.standard.data(forKey: "usageHistory"),
              let values = try? JSONDecoder().decode([String: [UsageHistory.Sample]].self, from: data) else { return [] }
        return values[id + "|" + window]?.map(\.u) ?? []
    }

    @MainActor
    private static func waitForUsage(_ store: UsageStore, id: String, value: Double) async throws {
        for _ in 0..<400 {
            if store.columns.first(where: { $0.id == id })?.windows.first?.utilization == value { return }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        throw Failure(description: "The production usage scheduler did not publish \(value)")
    }
}
