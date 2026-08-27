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
    /// Токены, отвергнутые сервером: брать их из Keychain повторно бессмысленно.
    private var rejected: [String: String] = [:]
    /// Почта из CLI, по одной на профиль. Пустое значение — «уже пробовали,
    /// не вышло»: подпроцесс на каждый цикл ради косметики гонять незачем.
    private var emails: [String: String] = [:]
    private let endpoint = URL(string: "https://api.anthropic.com/api/oauth/usage")!

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .claudeKeychain(let service, let configDir) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }

        guard let token = await token(for: service) else {
            return .reauth(L.t("column.reauth.claude"))
        }

        // Почту API не отдаёт, зато её знает CLI (`claude auth status`). Тянем
        // подпроцессом один раз за запуск и кэшируем — как у Codex: «Pro · почта».
        let email = await email(for: service, configDir: configDir)
        let subtitle = Self.subtitle(plan: token.plan, email: email)

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
                // Сервер отверг токен, хотя по сроку тот ещё жив — значит,
                // он отозван. Помечаем, чтобы следующий заход не взял его же
                // из Keychain снова, а сразу пошёл обновляться.
                rejected[service] = token.value
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

        guard let credentials = await read(service) else { return nil }
        // Тот самый токен, что сервер уже отверг, брать снова нельзя — только
        // обновлять. Если в записи оказался другой, значит CLI обновился сам.
        let isRejected = rejected[service] == credentials.accessToken
        if !isRejected {
            rejected[service] = nil
            if let cached = Self.cache(credentials) {
                tokens[service] = cached
                return cached
            }
        }

        // Токен протух. Раньше мы просто просили запустить claude; теперь
        // продлеваем сами — CLI мог не запускаться сутками.
        guard credentials.isRefreshable, let refreshToken = credentials.refreshToken else { return nil }

        // Убеждаемся, что запись нам поддаётся, до обращения к серверу: иначе
        // ротация отзовёт refresh-токен, а записать новый будет некуда.
        let writable = await Task.detached(priority: .utility) {
            ClaudeKeychain.isWritable(service: service)
        }.value
        guard writable else { return nil }

        switch await ClaudeOAuth.refresh(refreshToken: refreshToken, scopes: credentials.scopes) {
        case .success(let fresh):
            // Запись обязательна: при ротации прежний refresh-токен уже отозван,
            // и без записи вход сломается у самого CLI.
            // Если запись не удалась, работать всё равно можем — токен есть в
            // памяти. Но при ротации это значит, что CLI остался со старым
            // refresh-токеном, поэтому пробуем записать ещё раз.
            var saved = await Task.detached(priority: .utility) {
                ClaudeKeychain.save(service: service, tokens: fresh)
            }.value
            if !saved {
                saved = await Task.detached(priority: .utility) {
                    ClaudeKeychain.save(service: service, tokens: fresh)
                }.value
            }
            let cached = CachedToken(value: fresh.accessToken,
                                     expiresAt: fresh.expiresAt,
                                     plan: credentials.plan)
            rejected[service] = nil
            tokens[service] = cached
            return cached

        case .rejected:
            // Наш refresh-токен уже недействителен. Возможно, CLI успел
            // обновиться сам между нашим чтением и запросом — перечитываем.
            if let latest = await read(service), let cached = Self.cache(latest) {
                tokens[service] = cached
                return cached
            }
            return nil

        case .unavailable:
            return nil
        }
    }

    /// SecItemCopyMatching блокирует поток, пока пользователь отвечает на диалог.
    private func read(_ service: String) async -> ClaudeKeychain.Credentials? {
        await Task.detached(priority: .utility) {
            ClaudeKeychain.credentials(service: service)
        }.value
    }

    private static func cache(_ credentials: ClaudeKeychain.Credentials) -> CachedToken? {
        let cached = CachedToken(value: credentials.accessToken,
                                 expiresAt: credentials.expiresAt,
                                 plan: credentials.plan)
        return cached.isUsable ? cached : nil
    }

    // MARK: - Почта из CLI

    /// Почта профиля. Спрашиваем `claude auth status` один раз за запуск:
    /// раз получив, держим в памяти; неудачу тоже запоминаем (пустой строкой),
    /// чтобы не запускать подпроцесс каждые три минуты ради подписи.
    private func email(for service: String, configDir: URL?) async -> String? {
        if let cached = emails[service] { return cached.isEmpty ? nil : cached }
        let email = await Task.detached(priority: .utility) {
            BinaryLocator.claudeEmail(configDir: configDir)
        }.value
        emails[service] = email ?? ""
        return email
    }

    /// Подпись колонки: «Pro · user@example.com». Как у Codex — план и почта
    /// через разделитель, любая часть может отсутствовать.
    static func subtitle(plan: String?, email: String?) -> String? {
        let parts = [plan.map(humanized), email]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
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

    /// `extra_usage` — доплата за расход сверх лимитов плана (pay-as-you-go).
    ///
    /// Показываем только когда доплата **включена** (`is_enabled: true`): тогда
    /// `used_credits` — это живой счётчик потраченного за период. Когда выключена
    /// (`out_of_credits`, план без доплаты), `used_credits` — исторический остаток
    /// уже израсходованных кредитов, и как «расход прямо сейчас» он вводит в
    /// заблуждение. Сумма в минорных единицах: 10308 при `decimal_places: 2` —
    /// это 103.08 USD, сырое число показывать нельзя.
    static func stats(_ data: Data) -> [UsageStat] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let extra = root["extra_usage"] as? [String: Any],
              extra["is_enabled"] as? Bool == true,
              let minor = (extra["used_credits"] as? NSNumber)?.doubleValue, minor > 0
        else { return [] }

        let places = (extra["decimal_places"] as? NSNumber)?.intValue ?? 2
        let currency = (extra["currency"] as? String) ?? "USD"
        var value = Format.money(minor: minor, places: places, currency: currency)
        // Если задан месячный потолок — показываем «потрачено / потолок».
        if let cap = (extra["monthly_limit"] as? NSNumber)?.doubleValue, cap > 0 {
            value += " / " + Format.money(minor: cap, places: places, currency: currency)
        }
        return [UsageStat(key: "extraUsage",
                          label: L.t("stat.extraUsage"),
                          value: value)]
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
