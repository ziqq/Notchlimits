import AppKit
import CryptoKit
import Darwin

/// Switch the desktop application account and optionally route new Claude CLI sessions.
///
/// Подменить аккаунт у работающего приложения нельзя, поэтому свич всегда
/// один: закрыть приложение → подготовить аккаунт → открыть заново
/// (`DesktopApp.restart`). Чем «подготовить» — у каждого приложения своё:
///
/// - Claude: аккаунт — веб-сессия Electron в user-data-dir, у каждой колонки
///   своя папка данных (`AppSwitcher$Claude`).
/// - Codex: вход живёт в `~/.codex/auth.json`, а рядом — проекты, треды и
///   сайдбар. Отдельный CODEX_HOME на аккаунт терял бы их, поэтому приложение
///   всегда работает на `~/.codex`, а подменяется только `auth.json`
///   (`AppSwitcher$Codex`, `AuthSwap$Codex`).
///
/// Список аккаунтов — это колонки панели того же провайдера.
protocol AppAccountSwitcher {
    var bundleID: String { get }
    /// Имя для диалогов («Claude» / «Codex»).
    var appName: String { get }
    /// Открыт ли аккаунт колонки в приложении. nil — неизвестно (через нас
    /// ещё не переключались).
    func isOpenInApp(columnID: String) -> Bool?
    /// Bind the selected account before a confirmation can outlive it.
    func captureSelection(_ account: DiscoveredAccount)
    /// Prepare the switch before stopping the running application.
    func beginSwitch(_ account: DiscoveredAccount) throws
    /// Приложение уже закрыто: подготовить аккаунт и вернуть параметры запуска.
    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration
    /// Приложение открылось под аккаунтом — запомнить это.
    func commit(_ account: DiscoveredAccount) throws
    func cancel()
}

extension AppAccountSwitcher {
    func captureSelection(_ account: DiscoveredAccount) {}
    func beginSwitch(_ account: DiscoveredAccount) {}
    func cancel() {}

    var isInstalled: Bool { DesktopApp.url(bundleID: bundleID) != nil }

    /// Закрыть приложение, подготовить аккаунт, открыть заново. `completion`
    /// зовётся на главном потоке, когда приложение уже запущено (или не вышло).
    @MainActor
    func switchTo(_ account: DiscoveredAccount,
                  completion: @escaping (Result<Void, Error>) -> Void) {
        guard !AppSwitchState.inProgress.contains(account.provider) else {
            completion(.failure(AppSwitchState.Busy()))
            return
        }
        AppSwitchState.inProgress.insert(account.provider)
        DesktopApp.restart(bundleID: bundleID, appName: appName,
                           beforeStop: { try beginSwitch(account) },
                           prepare: { try prepare(account) }) { result in
            defer { AppSwitchState.inProgress.remove(account.provider) }
            switch result {
            case .success:
                do {
                    try commit(account)
                    completion(result)
                } catch {
                    cancel()
                    completion(.failure(error))
                }
            case .failure:
                cancel()
                completion(result)
            }
        }
    }
}

@MainActor
enum AppSwitchState {
    static var inProgress: Set<Provider> = []
    struct Busy: LocalizedError {
        var errorDescription: String? { L.t("appswitch.error.inProgress") }
    }
}

func appAccountSwitcher(for provider: Provider) -> (any AppAccountSwitcher)? {
    switch provider {
    case .claude: return AppSwitcher$Claude()
    case .codex: return AppSwitcher$Codex()
    case .kimi, .grok: return nil
    }
}

// MARK: - Claude

/// Claude Desktop: своя папка данных (`--user-data-dir`) на колонку. Первый
/// свич на аккаунт открывает приложение в пустой папке — там нужно войти.
final class AppSwitcher$Claude: AppAccountSwitcher {
    private var cliChange: CLISelection$Claude.Prepared?
    private var cliRevisionIsCurrent: (() -> Bool)?
    private var selectedKey: String?
    let bundleID = "com.anthropic.claudefordesktop"
    let appName = "Claude"

    /// Ключ папки активного аккаунта; "" — ещё не переключались.
    private static let currentKey = "currentClaudeAppAccount"
    private static let generationsKey = "claudeAppAccountGenerations"
    private struct RetiredAccount: LocalizedError {
        var errorDescription: String? { L.t("error.cliProfile") }
    }

    private static var root: URL {
        DesktopApp.supportDirectory.appendingPathComponent("claude-app", isDirectory: true)
    }

    private struct Retirement: Codable {
        struct Rollback: Codable {
            let directory: String
            let credentialFile: String
        }

        let columnID: String
        let service: String
        let directory: URL
        let keychainOnly: Bool
        let previousKey: String
        let previousLogin: AuthStorage$Claude.DesktopLoginProof?
        let generation: UUID
        var staged: URL?
        var rollback: Rollback?
        var nativeFallback: Rollback?
        var removed = false

        var nativeFallbackName: String { ".credentials-" + generation.uuidString + ".removal" }

        func currentLogin() -> AuthStorage$Claude.DesktopLoginProof? {
            AuthStorage$Claude.desktopLoginProof(service: service, directory: directory, keychainOnly: keychainOnly)
        }

        func matchesPreviousLogin(_ current: AuthStorage$Claude.DesktopLoginProof) -> Bool {
            guard let previousLogin, current.directory != nil else { return false }
            if current == previousLogin { return true }
            if let opaque = previousLogin.opaqueKeychain, current.directory == previousLogin.directory {
                return AuthStorage$Claude.removalKeychainProof(service: service) == opaque
            }
            guard let rollback, current.directory == rollback.directory,
                  current.login == previousLogin.login, current.stub == previousLogin.stub,
                  let owner = DirectoryIdentity.capture(directory) else { return false }
            let descriptor = open(owner.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { return false }
            defer { _ = close(descriptor) }
            guard let pinned = DirectoryIdentity.capture(descriptor: descriptor),
                  AuthStorage$Claude.desktopDirectoryProof(pinned) == rollback.directory,
                  AppSwitcher$Claude.credentialFileProof(descriptor) == rollback.credentialFile,
                  currentLogin() == current else { return false }
            return pinned.matches(directory) && AppSwitcher$Claude.credentialFileProof(descriptor) == rollback.credentialFile
        }
    }

    static func credentialFileProof(_ parent: Int32, name: String = ".credentials.json") -> String? {
        var info = stat()
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & S_IFMT == S_IFREG else { return nil }
        return "\(info.st_dev):\(info.st_ino):\(info.st_birthtimespec.tv_sec):\(info.st_birthtimespec.tv_nsec)"
    }

    private static var retirements: URL { root.appendingPathComponent(".retirements", isDirectory: true) }

    private static func receipt(for columnID: String) -> URL {
        let name = SHA256.hash(data: Data(columnID.utf8)).map { String(format: "%02x", $0) }.joined()
        return retirements.appendingPathComponent(name)
    }

    private static func save(_ retirement: Retirement) throws {
        try PropertyListEncoder().encode(retirement).write(to: receipt(for: retirement.columnID), options: .atomic)
    }

    private static func load(from file: URL) throws -> Retirement? {
        let retirement: Retirement
        do { retirement = try PropertyListDecoder().decode(Retirement.self, from: Data(contentsOf: file)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile { return nil }
        let base = AccountSwitcher.slug(retirement.columnID)
        guard file.path == receipt(for: retirement.columnID).path,
              retirement.previousKey == base || (retirement.previousKey.hasPrefix(base + "-")
                  && UUID(uuidString: String(retirement.previousKey.dropFirst(base.count + 1))) != nil)
        else { throw RetiredAccount() }
        return retirement
    }

    /// Стабильный ключ папки: из id колонки, не из имени (переименование
    /// колонки не должно осиротить папку данных).
    static func key(for columnID: String) -> String {
        let base = AccountSwitcher.slug(columnID)
        guard let generation = (UserDefaults.standard.dictionary(forKey: generationsKey) as? [String: String])?[columnID] else {
            return base
        }
        return base + "-" + generation
    }

    private static func finish(_ retirement: Retirement, removingOldData: Bool) throws {
        let defaults = UserDefaults.standard
        if key(for: retirement.columnID) == retirement.previousKey {
            var generations = defaults.dictionary(forKey: generationsKey) as? [String: String] ?? [:]
            generations[retirement.columnID] = retirement.generation.uuidString
            defaults.set(generations, forKey: generationsKey)
        }
        guard defaults.synchronize() else { throw RetiredAccount() }
        // A running Desktop may recreate this path. Its generation is retired.
        if removingOldData {
            try? FileManager.default.removeItem(at: root.appendingPathComponent(retirement.previousKey, isDirectory: true))
        }
        try FileManager.default.removeItem(at: receipt(for: retirement.columnID))
    }

    private static func finishRollback(_ retirement: Retirement) throws {
        if retirement.rollback != nil, CLISelection$Claude.requiresDesktopRollbackProof(service: retirement.service) {
            return
        }
        try FileManager.default.removeItem(at: receipt(for: retirement.columnID))
    }

    private static func recover(_ retirement: Retirement, underLease: (() throws -> Void)? = nil) throws {
        guard retirement.nativeFallback != nil else { try recoverDesktop(retirement); return }
        // The receipt is visible before the file moves. Keep preparation and
        // replay under the same native leases even when the checkpoint is absent.
        func reconcile(_ validate: () throws -> Void) throws {
            guard let saved = try load(from: receipt(for: retirement.columnID)),
                  saved.generation == retirement.generation else { return }
            try recoverNativeFallback(saved, validating: validate)
            try validate()
            try recoverDesktop(saved)
        }
        if let underLease { try reconcile(underLease) }
        else {
            try AuthStorage$Claude.withRemovalLock(directory: retirement.directory, validating: { _, validate in
                try reconcile(validate)
            })
        }
    }

    private static func recoverDesktop(_ retirement: Retirement) throws {
        if retirement.removed {
            try finish(retirement, removingOldData: true)
            return
        }
        guard let current = retirement.currentLogin() else { return }
        if retirement.matchesPreviousLogin(current) {
            try finishRollback(retirement)
            return
        }
        // A moved profile may still own the old credentials. Give the CLI
        // recovery a chance to restore it before deciding that deletion won.
        if !current.hasCredential, let staged = retirement.staged, DirectoryIdentity.missingPath(staged) == nil {
            guard let previous = retirement.previousLogin, previous.hasCredential,
                  let parked = AuthStorage$Claude.desktopLoginProof(service: retirement.service, directory: staged,
                                                                     keychainOnly: retirement.keychainOnly),
                  parked.directory == previous.directory, !parked.hasCredential else { return }
        }
        guard current.directory != nil || !current.hasCredential else { return }
        // An independently written login can use a fresh Desktop without
        // touching the previous session when deletion could not be proved.
        try finish(retirement, removingOldData: !current.hasCredential && retirement.previousLogin?.hasCredential == true)
    }

    private static func hasNativeFallbackCheckpoint(_ retirement: Retirement) -> Bool {
        retirement.nativeFallback != nil
            && DirectoryIdentity.missingPath(retirement.directory.appendingPathComponent(retirement.nativeFallbackName)) == nil
    }

    private static func recoverNativeFallback(_ retirement: Retirement, validating validate: () throws -> Void) throws {
        guard let fallback = retirement.nativeFallback, hasNativeFallbackCheckpoint(retirement) else { return }
        let directory = retirement.directory
        guard let owner = DirectoryIdentity.capture(directory),
              AuthStorage$Claude.desktopDirectoryProof(owner) == fallback.directory else { throw RetiredAccount() }
        func shouldRestore() throws -> Bool {
            if retirement.removed { return false }
            guard let current = AuthStorage$Claude.desktopLoginProof(service: retirement.service, directory: directory,
                                                                     keychainOnly: true),
                  current.directory == fallback.directory, owner.matches(directory) else { throw RetiredAccount() }
            if !current.hasCredential { return false }
            if retirement.matchesPreviousLogin(current) { return true }
            // A verified replacement can use a fresh Desktop generation. Only
            // the isolated fallback belongs to the earlier confirmed removal.
            guard let previous = retirement.previousLogin, previous.hasCredential,
                  previous.opaqueKeychain == nil, current.opaqueKeychain == nil else { throw RetiredAccount() }
            return false
        }
        let restore = try shouldRestore()
        try AccountRemoval.resolveClaudeFallback(in: directory, matching: fallback.credentialFile,
                                                   named: retirement.nativeFallbackName, restoring: restore) {
            guard try shouldRestore() == restore, owner.matches(directory) else { throw RetiredAccount() }
            try validate()
        }
        guard !hasNativeFallbackCheckpoint(retirement) else { throw RetiredAccount() }
    }

    static func recoverInterruptedRemovals() {
        AuthStorage$Claude.recoverSharedPrimaryRemoval()
        let files = (try? FileManager.default.contentsOfDirectory(at: retirements, includingPropertiesForKeys: nil)) ?? []
        for file in files {
            if let retirement = try? load(from: file) { try? recover(retirement) }
        }
    }

    static func verifiedFileRollback(service: String, previous: DirectoryIdentity, restored: DirectoryIdentity) -> Bool {
        guard let retirement = try? load(from: receipt(for: "claude:" + service)), retirement.service == service,
              !retirement.removed, let rollback = retirement.rollback,
              let oldOwner = AuthStorage$Claude.desktopDirectoryProof(previous), oldOwner == retirement.previousLogin?.directory,
              AuthStorage$Claude.desktopDirectoryProof(restored) == rollback.directory,
              restored.matches(retirement.directory), let current = retirement.currentLogin(),
              current.directory == rollback.directory, retirement.matchesPreviousLogin(current)
        else { return false }
        return restored.matches(retirement.directory)
    }

    static func withDesktopRetirement(services: Set<String>, directory: URL, keychainOnly: Bool = false,
                                      protectsNativeFallback: Bool = false,
                                      validating validate: @escaping () throws -> Void,
                                      operation: (_ recordMove: @escaping (URL) throws -> Void,
                                                  _ recordRollback: @escaping (Int32, Int32) -> Void,
                                                  _ nativeFallback: (name: String, proof: String)?) throws -> Void) throws {
        var pending: [Retirement] = []
        try FileManager.default.createDirectory(at: retirements, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        for service in services.sorted() {
            let columnID = "claude:" + service
            let file = receipt(for: columnID)
            if let existing = try load(from: file) { try recover(existing, underLease: validate) }
            guard try load(from: file) == nil else { throw RetiredAccount() }
            var retirement = Retirement(columnID: columnID, service: service, directory: directory,
                                        keychainOnly: keychainOnly, previousKey: key(for: columnID),
                                        previousLogin: AuthStorage$Claude.desktopLoginProof(service: service, directory: directory,
                                                                                            keychainOnly: keychainOnly || protectsNativeFallback),
                                        generation: UUID())
            if protectsNativeFallback,
               DirectoryIdentity.missingPath(directory.appendingPathComponent(".credentials.json")) == nil {
                guard let owner = DirectoryIdentity.capture(directory),
                      let directoryProof = AuthStorage$Claude.desktopDirectoryProof(owner) else { throw RetiredAccount() }
                let descriptor = open(owner.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard descriptor >= 0 else { throw RetiredAccount() }
                defer { close(descriptor) }
                guard DirectoryIdentity.capture(descriptor: descriptor) == owner, owner.matches(directory),
                      let file = credentialFileProof(descriptor) else { throw RetiredAccount() }
                retirement.nativeFallback = Retirement.Rollback(directory: directoryProof, credentialFile: file)
            }
            try save(retirement)
            pending.append(retirement)
        }
        do {
            try operation({ staged in
                for index in pending.indices {
                    pending[index].staged = staged
                    try save(pending[index])
                }
            }, { source, destination in
                guard let staged = DirectoryIdentity.capture(descriptor: source),
                      let file = credentialFileProof(source),
                      let restored = DirectoryIdentity.capture(descriptor: destination),
                      restored.matches(directory), let restoredProof = AuthStorage$Claude.desktopDirectoryProof(restored)
                else { return }
                for index in pending.indices {
                    let retirement = pending[index]
                    let archivedDirectory = URL(fileURLWithPath: staged.path, isDirectory: true)
                    guard let previous = retirement.previousLogin, previous.hasCredential,
                          AuthStorage$Claude.desktopLoginProof(service: retirement.service, directory: archivedDirectory,
                                                               keychainOnly: retirement.keychainOnly) == previous,
                          credentialFileProof(source) == file, restored.matches(directory) else { continue }
                    pending[index].rollback = Retirement.Rollback(directory: restoredProof, credentialFile: file)
                    try? save(pending[index])
                }
            }, pending.first.flatMap { retirement in
                retirement.nativeFallback.map { (retirement.nativeFallbackName, $0.credentialFile) }
            })
        } catch {
            for retirement in pending where !hasNativeFallbackCheckpoint(retirement) {
                if let current = retirement.currentLogin(), retirement.matchesPreviousLogin(current) {
                    try? finishRollback(retirement)
                }
            }
            throw error
        }
        for var retirement in pending {
            retirement.removed = true
            try save(retirement)
            if !hasNativeFallbackCheckpoint(retirement) {
                try finish(retirement, removingOldData: true)
            }
        }
    }

    private static func switchKey(for columnID: String) throws -> String {
        let file = receipt(for: columnID)
        if let retirement = try load(from: file) { try recover(retirement) }
        if let pending = try load(from: file) {
            // A verified rollback is usable while CLI still needs its proof.
            guard pending.rollback != nil, let current = pending.currentLogin(),
                  pending.matchesPreviousLogin(current) else { throw RetiredAccount() }
        }
        return key(for: columnID)
    }

    func isOpenInApp(columnID: String) -> Bool? {
        let current = UserDefaults.standard.string(forKey: Self.currentKey) ?? ""
        return current.isEmpty ? nil : current == Self.key(for: columnID)
    }

    func captureSelection(_ account: DiscoveredAccount) {
        selectedKey = Self.key(for: account.id)
    }

    func beginSwitch(_ account: DiscoveredAccount) throws {
        let current = try Self.switchKey(for: account.id)
        if selectedKey == nil { selectedKey = current }
        guard selectedKey == current else { throw RetiredAccount() }
        guard case .claudeKeychain(let service, _) = account.source else { return }
        // Cover the outgoing Desktop's shutdown and a setting change during launch.
        cliRevisionIsCurrent = AuthStorage$Claude.captureSelectionRevision(for: service)
        if CLISelection$Claude.isEnabled { cliChange = try CLISelection$Claude.stage(account) }
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        guard let key = selectedKey, key == (try Self.switchKey(for: account.id)) else {
            throw RetiredAccount()
        }
        let dir = Self.root.appendingPathComponent(key, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["--user-data-dir=\(dir.path)"]
        return config
    }

    func commit(_ account: DiscoveredAccount) throws {
        // Desktop has opened: keep its marker truthful even if an external
        // filesystem change prevents publishing the prepared CLI selection.
        guard let launchedKey = selectedKey else { throw RetiredAccount() }
        defer { UserDefaults.standard.set(launchedKey, forKey: Self.currentKey) }
        if CLISelection$Claude.isEnabled {
            guard launchedKey == (try Self.switchKey(for: account.id)) else {
                throw RetiredAccount()
            }
            let change = try cliChange ?? CLISelection$Claude.stage(account)
            try change.commit(revisionIsCurrent: cliRevisionIsCurrent)
        }
        cancel()
    }

    func cancel() {
        cliChange = nil
        cliRevisionIsCurrent = nil
        selectedKey = nil
    }
}

// MARK: - Codex

/// Desktop and CLI share the base CODEX_HOME and its configured auth backend.
/// Swap credentials only, preserving the application's projects and threads.
final class AppSwitcher$Codex: AppAccountSwitcher {
    private var primaryUsageOwner: AuthSwap$Codex.UsageOwner?
    private var selectedLogin: AuthSwap$Codex.ActionLogin?

    let bundleID = "com.openai.codex"
    let appName = "Codex"

    func isOpenInApp(columnID: String) -> Bool? {
        AuthSwap$Codex.activeColumnID == columnID
    }

    func captureSelection(_ account: DiscoveredAccount) {
        selectedLogin = AuthSwap$Codex.actionLogin(for: account)
    }

    func beginSwitch(_ account: DiscoveredAccount) {
        if selectedLogin == nil { captureSelection(account) }
        guard account.id == AuthSwap$Codex.defaultColumnID,
              case .codexHome(let home) = account.source else { return }
        primaryUsageOwner = AuthSwap$Codex.usageOwner(columnID: account.id, home: home)
    }

    func prepare(_ account: DiscoveredAccount) throws -> NSWorkspace.OpenConfiguration {
        guard case .codexHome(let home) = account.source else { throw AuthSwap$Codex.Failure.missingAuth }
        try AuthSwap$Codex.activate(columnID: account.id, home: home, expectedAccount: account,
                                    expectedPrimaryRoute: primaryUsageOwner, expectedLogin: selectedLogin)
        return NSWorkspace.OpenConfiguration()
    }

    /// Состояние меняет сама подмена в `prepare`.
    func commit(_ account: DiscoveredAccount) { cancel() }

    func cancel() {
        primaryUsageOwner = nil
        selectedLogin = nil
    }
}
