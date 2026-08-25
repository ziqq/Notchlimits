import Foundation

enum Provider: String, Codable {
    case claude
    case codex

    var displayName: String {
        switch self {
        case .claude: return "CLAUDE"
        case .codex:  return "CODEX"
        }
    }
}

/// Одно окно лимита (5-часовое, недельное, произвольное — набор не фиксирован).
struct LimitWindow: Identifiable, Codable, Equatable {
    let key: String
    let title: String
    /// 0...100
    let utilization: Double
    let resetsAt: Date?

    var id: String { key }
}

enum ColumnStatus: Equatable {
    /// Данные актуальны.
    case ok
    /// Идёт первая загрузка, данных ещё нет.
    case loading
    /// HTTP 429 — ждём до указанного момента, это не ошибка.
    case waiting(until: Date)
    /// Токена нет / протух / 401 — нужно перелогиниться в CLI.
    case reauth(String)
    /// Всё остальное.
    case failed(String)
}

/// Колонка = один аккаунт одного провайдера.
struct AccountColumn: Identifiable, Equatable {
    /// Стабильный идентификатор: "claude:<profile>" / "codex:<profile>".
    let id: String
    let provider: Provider
    /// Имя профиля для заголовка: main / work / <имя папки>.
    let profileName: String
    /// Подпись (e-mail / план), если провайдер её отдал.
    var subtitle: String?
    var windows: [LimitWindow] = []
    /// Момент последнего успешного ответа.
    var updatedAt: Date?
    var status: ColumnStatus = .loading
    /// Данные подняты из кэша UserDefaults, свежего ответа в этой сессии ещё не было.
    var fromCache: Bool = false
    /// Имя, заданное вручную через меню. Пусто — берём имя профиля.
    var customName: String?

    var displayName: String { customName ?? profileName }
    var header: String { "\(provider.displayName) · \(displayName)" }

    /// Есть ли что показывать в колонке прямо сейчас.
    var hasData: Bool { !windows.isEmpty }

    /// Максимальная загрузка среди окон — цвет точки в свёрнутом состоянии.
    var peakUtilization: Double { windows.map(\.utilization).max() ?? 0 }
}

/// То, что кладём в UserDefaults: проценты и даты сброса, без единого токена.
struct CachedColumn: Codable {
    let id: String
    let provider: Provider
    let profileName: String
    let subtitle: String?
    let windows: [LimitWindow]
    let updatedAt: Date
}
