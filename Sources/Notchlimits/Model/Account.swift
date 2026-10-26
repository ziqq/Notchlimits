import Foundation
import Darwin

/// Откуда берутся учётные данные конкретной колонки.
enum AccountSource: Equatable {
    /// Запись generic password в Keychain: «Claude Code-credentials[-<hash>]».
    case claudeKeychain(service: String, configDir: URL?)
    /// Папка CODEX_HOME с auth.json внутри.
    case codexHome(URL)
    /// Только для отладки макета.
    case mock(seed: Int)
}

/// A path alone cannot distinguish a removed profile from its replacement.
struct DirectoryIdentity: Equatable {
    let path: String
    private let device: Int32
    private let inode: UInt64
    /// Keep the inode alive; timestamps can change without replacing its owner.
    private let handle: FileHandle

    static func capture(_ directory: URL) -> DirectoryIdentity? {
        let path = directory.resolvingSymlinksInPath().path
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFDIR else { return nil }
        return DirectoryIdentity(path: path, device: info.st_dev, inode: UInt64(info.st_ino), handle: handle)
    }

    /// Failed capture is not proof of absence: permissions and links can fail too.
    static func missingPath(_ directory: URL) -> String? {
        var info = stat()
        guard lstat(directory.path, &info) != 0, errno == ENOENT else { return nil }
        let path = directory.resolvingSymlinksInPath().path
        guard lstat(path, &info) != 0, errno == ENOENT else { return nil }
        return path
    }

    func matches(_ directory: URL) -> Bool {
        withExtendedLifetime(handle) { Self.capture(directory) == self }
    }

    func isSameDirectory(as other: DirectoryIdentity) -> Bool {
        device == other.device && inode == other.inode
    }

    static func == (lhs: DirectoryIdentity, rhs: DirectoryIdentity) -> Bool {
        lhs.path == rhs.path && lhs.isSameDirectory(as: rhs)
    }
}

/// The primary file fallback and the preferred Keychain service have different owners.
enum ClaudePrimaryOwner: Equatable {
    case keychain
    case file(DirectoryIdentity)
    case unavailable
}

struct DiscoveredAccount: Identifiable, Equatable {
    let id: String
    let provider: Provider
    let profileName: String
    let source: AccountSource
    /// Keep the discovered physical owner when a managed root is a symlink.
    let claudeConfigOwner: DirectoryIdentity?
    /// Discovery verifies the primary backend without reading its secret.
    let claudePrimaryOwner: ClaudePrimaryOwner?
    /// Removal must still address the directory captured by discovery.
    let codexHomeOwner: DirectoryIdentity?
    /// Primary credentials can remain in the backup while the native home is absent.
    let codexHomeMissingPath: String?
    /// Почта аккаунта (из конфигов, без Keychain). Для дедупа и подсветки.
    var email: String? = nil
    /// Аккаунт открыт в десктоп-приложении (Claude — по папке данных, Codex —
    /// чей вход в ~/.codex). Только его имя подсвечивается.
    var isActive: Bool = false

    init(id: String, provider: Provider, profileName: String, source: AccountSource,
         email: String? = nil, isActive: Bool = false,
         claudePrimaryOwner: ClaudePrimaryOwner? = nil) {
        self.id = id
        self.provider = provider
        self.profileName = profileName
        self.source = source
        self.email = email
        self.isActive = isActive
        self.claudePrimaryOwner = claudePrimaryOwner
        if case .claudeKeychain(_, let directory) = source {
            if let directory {
                claudeConfigOwner = DirectoryIdentity.capture(directory)
            } else if case .file(let owner)? = claudePrimaryOwner {
                claudeConfigOwner = owner
            } else if claudePrimaryOwner == nil {
                // Direct callers still capture the file boundary; discovery also
                // records whether the preferred Keychain namespace owns this login.
                claudeConfigOwner = DirectoryIdentity.capture(
                    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude"))
            } else {
                claudeConfigOwner = nil
            }
        } else {
            claudeConfigOwner = nil
        }
        if case .codexHome(let directory) = source {
            codexHomeOwner = DirectoryIdentity.capture(directory)
            codexHomeMissingPath = codexHomeOwner == nil ? DirectoryIdentity.missingPath(directory) : nil
        } else {
            codexHomeOwner = nil
            codexHomeMissingPath = nil
        }
    }
}

struct UsageSnapshot {
    var subtitle: String?
    var windows: [LimitWindow]
    var stats: [UsageStat] = []
}

enum FetchOutcome {
    case success(UsageSnapshot)
    /// The login changed while the request was in flight; poll its current owner.
    case superseded
    /// HTTP 429 — это не ошибка, а просьба подождать.
    case rateLimited(retryAfter: TimeInterval?)
    /// Нет токена / 401 / 403 — нужен новый вход в CLI.
    case reauth(String)
    /// В записи вообще нет входа — это не аккаунт (служебная запись CLI).
    case notAnAccount
    case failure(String)
}

protocol UsageProvider {
    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome
    func fetchValidated(_ account: DiscoveredAccount) async -> UsageFetchResult
}

/// Keep the observed login proof until the result reaches the UI actor.
struct UsageFetchResult {
    let outcome: FetchOutcome
    let isCurrent: (() throws -> Bool)?

    init(outcome: FetchOutcome, isCurrent: (() throws -> Bool)? = nil) {
        self.outcome = outcome
        self.isCurrent = isCurrent
    }
}

extension UsageProvider {
    func fetchValidated(_ account: DiscoveredAccount) async -> UsageFetchResult {
        UsageFetchResult(outcome: await fetch(account), isCurrent: nil)
    }
}
