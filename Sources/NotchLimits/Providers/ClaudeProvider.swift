import Foundation

/// Лимиты Claude Code: GET https://api.anthropic.com/api/oauth/usage
///
/// Токен читается из Keychain и держится только в памяти — до `expiresAt`
/// или до первого 401. Обновлять его мы не пытаемся: за это отвечает сам CLI.
actor ClaudeProvider: UsageProvider {

    private struct CachedToken {
        let value: String
        let expiresAt: Date?
        let plan: String?

        var isUsable: Bool {
            guard let expiresAt else { return true }
            // Минута запаса, чтобы не улететь в 401 на границе.
            return expiresAt.timeIntervalSinceNow > 60
        }
    }

    private var tokens: [String: CachedToken] = [:]
    private let endpoint = URL(string: "https://api.anthropic.com/api/oauth/usage")!

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .claudeKeychain(let service, _) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }

        guard let token = await token(for: service) else {
            return .reauth(L.t("column.reauth.claude"))
        }

        let subtitle = token.plan.map { Self.humanized($0) }

        let headers = [
            "Authorization": "Bearer \(token.value)",
            "anthropic-beta": "oauth-2025-04-20",
            // Без «родного» User-Agent эндпоинт заметно чаще отвечает 429.
            "User-Agent": Self.userAgent(),
            "Accept": "application/json"
        ]

        switch await HTTPClient.shared.get(endpoint, headers: headers) {
        case .failure(let error):
            if case .transport(let message) = error { return .failure(message) }
            return .failure(L.t("error.network"))

        case .success(let response):
            switch response.status {
            case 200:
                guard let windows = Self.parse(response.data), !windows.isEmpty else {
                    return .failure(L.t("error.parse"))
                }
                return .success(UsageSnapshot(subtitle: subtitle,
                                              windows: windows,
                                              stats: Self.stats(response.data)))
            case 401, 403:
                tokens[service] = nil
                return .reauth(L.t("column.reauth.claude"))
            case 429:
                return .rateLimited(retryAfter: response.retryAfter)
            default:
                return .failure(L.t("error.http", response.status))
            }
        }
    }

    // MARK: - Токен

    private func token(for service: String) async -> CachedToken? {
        if let cached = tokens[service], cached.isUsable { return cached }
        tokens[service] = nil

        // SecItemCopyMatching блокирует поток, пока пользователь отвечает на диалог.
        let credentials = await Task.detached(priority: .utility) {
            ClaudeKeychain.credentials(service: service)
        }.value

        guard let credentials else { return nil }
        let cached = CachedToken(value: credentials.accessToken,
                                 expiresAt: credentials.expiresAt,
                                 plan: credentials.plan)
        guard cached.isUsable else { return nil }
        tokens[service] = cached
        return cached
    }

    /// Считается один раз за запуск: `static let` инициализируется лениво и потокобезопасно.
    private static let cachedUserAgent: String = {
        let version = BinaryLocator.claude().map {
            BinaryLocator.version(of: $0, fallback: "2.0.0")
        } ?? "2.0.0"
        return "claude-code/\(version)"
    }()

    private static func userAgent() -> String { cachedUserAgent }

    // MARK: - Разбор ответа

    /// Набор окон не фиксирован: рендерим любое поле-объект с числовым
    /// `utilization`, чтобы новые окна появлялись без правок кода.
    static func parse(_ data: Data) -> [LimitWindow]? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var windows: [LimitWindow] = []
        for (key, value) in root {
            guard key != "extra_usage",
                  let object = value as? [String: Any],
                  let utilization = (object["utilization"] as? NSNumber)?.doubleValue
            else { continue }

            var resetsAt: Date?
            if let raw = object["resets_at"] as? String { resetsAt = ISO8601.date(from: raw) }

            windows.append(LimitWindow(key: key,
                                       title: title(for: key),
                                       utilization: max(0, min(utilization, 100)),
                                       resetsAt: resetsAt))
        }

        return windows.sorted { lhs, rhs in
            let lhsRank = rank(lhs.key), rhsRank = rank(rhs.key)
            if lhsRank != rhsRank { return lhsRank < rhsRank }
            return lhs.key < rhs.key
        }
    }

    /// `extra_usage` — расход сверх лимита, оплачиваемый отдельно. В окна он не
    /// годится (это не процент от квоты), но цифру показать стоит.
    static func stats(_ data: Data) -> [UsageStat] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let extra = root["extra_usage"] as? [String: Any]
        else { return [] }

        // Поле называлось по-разному в разных версиях эндпоинта.
        let amount = ["used_credits", "credits_used", "amount", "used"]
            .lazy
            .compactMap { (extra[$0] as? NSNumber)?.doubleValue }
            .first
        guard let amount, amount > 0 else { return [] }
        return [UsageStat(key: "extraUsage",
                          label: L.t("stat.extraUsage"),
                          value: Format.compact(amount))]
    }

    private static func rank(_ key: String) -> Int {
        if key == "five_hour" { return 0 }
        if key == "seven_day" { return 1 }
        if key.hasPrefix("five_hour_") { return 2 }
        if key.hasPrefix("seven_day_") { return 3 }
        return 4
    }

    /// Набор окон не фиксирован, и ключи бывают кодовыми именами моделей
    /// («nimbus_quill»). Известные префиксы разворачиваем в понятное название,
    /// остальное показываем словами, а не сырым snake_case.
    private static func title(for key: String) -> String {
        if key == "five_hour" { return L.t("window.fiveHour") }
        if key == "seven_day" { return L.t("window.week") }
        if key.hasPrefix("five_hour_") {
            return L.t("window.fiveHour") + " · " + humanized(String(key.dropFirst("five_hour_".count)))
        }
        if key.hasPrefix("seven_day_") {
            return L.t("window.week") + " · " + humanized(String(key.dropFirst("seven_day_".count)))
        }
        return humanized(key)
    }

    /// «nimbus_quill» → «Nimbus Quill», «opus» → «Opus».
    static func humanized(_ key: String) -> String {
        let words = key.split(whereSeparator: { $0 == "_" || $0 == "-" })
        guard !words.isEmpty else { return key }
        return words
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

enum ISO8601 {
    private static let withFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let plain: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    static func date(from string: String) -> Date? {
        withFraction.date(from: string) ?? plain.date(from: string)
    }
}
