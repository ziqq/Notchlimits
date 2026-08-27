import Foundation

/// Откуда берутся учётные данные конкретной колонки.
enum AccountSource: Equatable {
    /// Запись generic password в Keychain: «Claude Code-credentials[-<hash>]».
    case claudeKeychain(service: String, configDir: URL?)
    /// Папка CODEX_HOME с auth.json внутри.
    case codexHome(URL)
    /// Только для отладки макета.
    case mock(seed: Int)
}

struct DiscoveredAccount: Identifiable, Equatable {
    let id: String
    let provider: Provider
    let profileName: String
    let source: AccountSource
}

struct UsageSnapshot {
    var subtitle: String?
    var windows: [LimitWindow]
    var stats: [UsageStat] = []
}

enum FetchOutcome {
    case success(UsageSnapshot)
    /// HTTP 429 — это не ошибка, а просьба подождать.
    case rateLimited(retryAfter: TimeInterval?)
    /// Нет токена / 401 / 403 — нужен новый вход в CLI.
    case reauth(String)
    case failure(String)
}

protocol UsageProvider {
    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome
}
