import Foundation

/// Лимиты Claude Code: GET https://api.anthropic.com/api/oauth/usage
///
/// Токен читается из Keychain и держится только в памяти — до `expiresAt`
/// или до первого 401. Продление сохраняем только поверх того же входа.
actor Provider$Claude: UsageProvider {

    private struct CachedToken {
        let value: String
        let expiresAt: Date?
        let plan: String?
        let origin: AuthStorage$Claude.Credentials

        var isUsable: Bool {
            guard let expiresAt else { return true }
            // Минута запаса, чтобы не улететь в 401 на границе.
            return expiresAt.timeIntervalSinceNow > 60
        }
    }

    private var tokens: [String: CachedToken] = [:]
    private var origins: [String: AuthStorage$Claude.Credentials] = [:]
    private var terminating = false
    private var renewing: Set<String> = []
    private var removalGenerations: [String: UUID] = [:]
    private struct Resolution {
        let id = UUID()
        let generation: UUID?
        let task: Task<CachedToken?, Never>
    }
    private var inFlight: [String: Resolution] = [:]
    /// Токены, отвергнутые сервером: брать их из Keychain повторно бессмысленно.
    private var rejected: [String: String] = [:]
    /// Почта из CLI, по одной на профиль. Пустое значение — «уже пробовали,
    /// не вышло»: подпроцесс на каждый цикл ради косметики гонять незачем.
    private var emails: [String: String] = [:]
    /// Продлённые токены, которые не удалось записать в Keychain. Сервер уже
    /// отозвал прежний refresh-токен, так что это единственная живая копия:
    /// пробуем записать на каждом цикле, пока не выйдет.
    private struct Pending {
        let tokens: OAuth$Claude.Tokens
        let credentials: AuthStorage$Claude.Credentials
    }

    private var unsaved: [String: Pending] = [:]
    /// Почему токена нет, если дело не во входе (сеть, запись в Keychain).
    private var issues: [String: String] = [:]
    private let endpoint = URL(string: "https://api.anthropic.com/api/oauth/usage")!

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .claudeKeychain(let service, let configDir) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }

        let generation = removalGenerations[service]
        let resolved = await token(for: service)
        guard removalGenerations[service] == generation else { return .reauth(L.t("column.reauth")) }
        guard let token = resolved else {
            if let issue = issues[service] { return .failure(issue) }
            let noLogin = await Task.detached(priority: .utility) {
                AuthStorage$Claude.hasNoLogin(service: service, verifyingOwner: true)
            }.value
            guard removalGenerations[service] == generation else { return .reauth(L.t("column.reauth")) }
            return noLogin ? .notAnAccount : .reauth(L.t("column.reauth"))
        }

        let origin = token.origin
        // Почту API не отдаёт. Обычно берём из discovery (конфиг/снимок), иначе
        // читаем сами из конфига CLI. Так библиотечные колонки без папки конфига
        // тоже показывают верную почту.
        let resolvedEmail: String?
        if let discovered = account.email {
            resolvedEmail = discovered
        } else {
            resolvedEmail = await email(for: service, configDir: configDir,
                                        generation: generation, origin: origin)
        }
        guard isCurrent(service, generation: generation, origin: origin) else {
            return .reauth(L.t("column.reauth"))
        }
        let subtitle = Self.subtitle(plan: token.plan, email: resolvedEmail)

        let headers = [
            "Authorization": "Bearer \(token.value)",
            "anthropic-beta": "oauth-2025-04-20",
            // Без «родного» User-Agent эндпоинт заметно чаще отвечает 429.
            "User-Agent": Self.userAgent(),
            "Accept": "application/json"
        ]

        let response = await HTTPClient.shared.get(endpoint, headers: headers)
        // A late usage response belongs to the exact login that sent it. The
        // replacement may reuse its access token with a different refresh token.
        guard isCurrent(service, generation: generation, origin: origin) else {
            return .reauth(L.t("column.reauth"))
        }
        switch response {
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
            case 401:
                rejected[service] = token.value
                if tokens[service]?.value == token.value { tokens[service] = nil }
                return .reauth(L.t("column.reauth"))
            case 403:
                return .failure(L.t("error.http", response.status))
            case 429:
                return .rateLimited(retryAfter: response.retryAfter)
            default:
                return .failure(L.t("error.http", response.status))
            }
        }
    }

    // MARK: - Токен

    private func token(for service: String) async -> CachedToken? {
        let generation = removalGenerations[service]
        while removalGenerations[service] == generation {
            let running: Resolution
            if let current = inFlight[service] {
                running = current
            } else {
                running = Resolution(generation: generation, task: Task {
                    await resolveToken(for: service, generation: generation)
                })
                inFlight[service] = running
            }
            let token = await running.task.value
            if inFlight[service]?.id == running.id { inFlight[service] = nil }
            guard removalGenerations[service] == generation else { return nil }
            // Drain the removed generation before resolving the replacement login.
            if running.generation == generation { return token }
        }
        return nil
    }

    private func resolveToken(for service: String, generation: UUID?) async -> CachedToken? {
        guard removalGenerations[service] == generation else { return nil }
        issues[service] = nil
        if terminating && unsaved[service] == nil {
            issues[service] = L.t("error.keychainWrite")
            return nil
        }
        // Authorize interactive reads before taking a lease. A Keychain dialog
        // must not suspend the critical section beyond the CLI's lease timeout.
        let observed = await read(service)
        guard removalGenerations[service] == generation else { return nil }
        if let observed {
            if unsaved[service] == nil, let cached = adopt(observed, service: service) { return cached }
        } else if unsaved[service] == nil {
            return nil
        }
        guard AuthStorage$Claude.supportsStorageLock else { return nil }

        let acquired = await Task.detached(priority: .utility, operation: {
            AuthStorage$Claude.refreshLock(service: service)
        }).value
        defer { acquired?.release() }
        guard removalGenerations[service] == generation else { return nil }
        guard let lease = acquired else {
            issues[service] = L.t("error.keychainWrite")
            return nil
        }

        // Another process may have refreshed or signed in while we waited.
        guard lease.isHeld, removalGenerations[service] == generation else { return nil }
        if let pending = unsaved[service] {
            let result = await persist(pending, to: service, lease: lease, generation: generation)
            guard removalGenerations[service] == generation else { return nil }
            switch result {
            case .saved:
                unsaved[service] = nil
            case .changed:
                unsaved[service] = nil
                forget(service)
            case .failed:
                // Do not spend another refresh token until the rotated one is durable.
                issues[service] = L.t("error.keychainWrite")
                return nil
            }
        }
        let current = await read(service, interactive: false, verifyingOwner: true)
        guard removalGenerations[service] == generation else { return nil }
        guard let credentials = current else {
            issues[service] = L.t("error.keychainWrite")
            return nil
        }
        if let cached = adopt(credentials, service: service) { return cached }
        guard !terminating else { return nil }
        guard credentials.isRefreshable, let refreshToken = credentials.refreshToken else { return nil }

        let writable = await Task.detached(priority: .utility) {
            AuthStorage$Claude.canWrite(service: service, renewalLock: lease)
        }.value
        guard removalGenerations[service] == generation else { return nil }
        guard writable, lease.isHeld, !terminating else {
            issues[service] = L.t("error.keychainWrite")
            return nil
        }

        // Keep both native OAuth locks throughout the HTTP request and save.
        // A compromised lease cancels the request and forbids subsequent writes.
        renewing.insert(service)
        defer { renewing.remove(service) }
        let request = Task { await OAuth$Claude.refresh(refreshToken: refreshToken, scopes: credentials.scopes) }
        lease.onLost { request.cancel() }
        let response = await request.value
        guard removalGenerations[service] == generation else { return nil }
        switch response {
        case .success(let fresh):
            let pending = Pending(tokens: fresh, credentials: credentials)
            if fresh.refreshToken != nil {
                unsaved[service] = pending
                let result = await persist(pending, to: service, lease: lease, generation: generation)
                guard removalGenerations[service] == generation else { return nil }
                switch result {
                case .saved:
                    unsaved[service] = nil
                case .failed:
                    issues[service] = L.t("error.keychainWrite")
                    return nil
                case .changed:
                    unsaved[service] = nil
                    forget(service)
                    let latest = await read(service, interactive: false)
                    guard removalGenerations[service] == generation, let latest else { return nil }
                    return adopt(latest, service: service)
                }
            }
            let current = lease.isHeld ? await read(service, interactive: false) : nil
            guard removalGenerations[service] == generation else { return nil }
            guard lease.isHeld, let latest = current else {
                issues[service] = L.t("error.keychainWrite")
                return nil
            }
            let expectedAccess = fresh.refreshToken == nil ? credentials.accessToken : fresh.accessToken
            guard latest.accessToken == expectedAccess,
                  latest.refreshToken == (fresh.refreshToken ?? credentials.refreshToken) else {
                forget(service)
                return adopt(latest, service: service)
            }
            let cached = CachedToken(value: fresh.accessToken, expiresAt: fresh.expiresAt,
                                     plan: credentials.plan, origin: latest)
            rejected[service] = nil
            tokens[service] = cached
            origins[service] = latest
            return cached

        case .rejected:
            let latest = await read(service, interactive: false)
            guard removalGenerations[service] == generation, let latest else { return nil }
            return adopt(latest, service: service)

        case .unavailable:
            issues[service] = L.t("error.network")
            return nil
        }
    }

    private func isCurrent(_ service: String, generation: UUID?,
                           origin: AuthStorage$Claude.Credentials) -> Bool {
        removalGenerations[service] == generation
            && origins[service]?.hasSameTokens(as: origin) == true
    }

    private func forget(_ service: String) {
        tokens[service] = nil
        origins[service] = nil
        rejected[service] = nil
        emails[service] = nil
    }

    /// Only a successful explicit removal may discard an unsaved grant.
    /// Invalidate late refresh responses without blocking a later login to the same profile.
    func accountRemoved(_ account: DiscoveredAccount) {
        guard case .claudeKeychain(let service, _) = account.source else { return }
        removalGenerations[service] = UUID()
        unsaved[service] = nil
        issues[service] = nil
        forget(service)
    }

    private func adopt(_ credentials: AuthStorage$Claude.Credentials, service: String) -> CachedToken? {
        if let origin = origins[service], !origin.hasSameTokens(as: credentials) { forget(service) }
        guard rejected[service] != credentials.accessToken else { return nil }
        if let cached = tokens[service], cached.isUsable { return cached }
        let cached = Self.cache(credentials)
        tokens[service] = cached
        origins[service] = credentials
        return cached
    }

    /// Каким refresh-токеном продлевать. Не дописанный в Keychain новее того,
    /// что там лежит: старый сервер уже отозвал. Чистая функция — покрыта
    /// самопроверкой.
    static func refreshToken(pending: OAuth$Claude.Tokens?,
                             stored: AuthStorage$Claude.Credentials) -> String? {
        if let pending = pending?.refreshToken { return pending }
        guard stored.isRefreshable else { return nil }
        return stored.refreshToken
    }

    /// A rotated grant must reach the CLI's record before its OAuth locks are
    /// released. Retry persistence only; never issue another refresh request.
    private func persist(_ pending: Pending, to service: String,
                         lease: RefreshLock$Claude, generation: UUID?) async -> AuthStorage$Claude.SaveResult {
        var delay: UInt64 = 250_000_000
        while lease.isHeld && removalGenerations[service] == generation {
            let result = await write(pending, to: service, lease: lease)
            guard removalGenerations[service] == generation else { return .failed }
            switch result {
            case .saved, .changed:
                issues[service] = nil
                return result
            case .failed:
                issues[service] = L.t("error.keychainWrite")
                try? await Task.sleep(nanoseconds: delay)
                delay = min(delay * 2, 1_000_000_000)
            }
        }
        return .failed
    }

    /// Normal termination cannot abandon a refresh POST or an unsaved rotation.
    /// A failed drain leaves the app running so its heartbeat and retries survive.
    func prepareForTermination(timeout: TimeInterval = 25) async -> Bool {
        terminating = true
        let deadline = Date().addingTimeInterval(timeout)
        let recovery = unsaved.keys.filter { inFlight[$0] == nil }
        for service in recovery { Task { _ = await token(for: service) } }
        while !renewing.isEmpty || !unsaved.isEmpty {
            guard Date() < deadline else { terminating = false; return false }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return true
    }

    func cancelTermination() { terminating = false }

    private func write(_ pending: Pending, to service: String, lease: RefreshLock$Claude) async -> AuthStorage$Claude.SaveResult {
        await Task.detached(priority: .utility) {
            AuthStorage$Claude.save(service: service, tokens: pending.tokens,
                                expected: pending.credentials, renewalLock: lease)
        }.value
    }

    /// SecItemCopyMatching блокирует поток, пока пользователь отвечает на диалог.
    private func read(_ service: String, interactive: Bool = true,
                      verifyingOwner: Bool = false) async -> AuthStorage$Claude.Credentials? {
        await Task.detached(priority: .utility) {
            AuthStorage$Claude.credentials(service: service, interactive: interactive, verifyingOwner: verifyingOwner)
        }.value
    }

    private static func cache(_ credentials: AuthStorage$Claude.Credentials) -> CachedToken? {
        let cached = CachedToken(value: credentials.accessToken,
                                 expiresAt: credentials.expiresAt,
                                 plan: credentials.plan, origin: credentials)
        return cached.isUsable ? cached : nil
    }

    // MARK: - Почта из CLI

    /// Почта профиля. Читаем из конфига CLI `~/.claude.json`
    /// (`oauthAccount.emailAddress`) — обычный файл, без Keychain и подпроцессов,
    /// поэтому никаких диалогов пароля. Раз прочитав, держим в памяти.
    private func email(for service: String, configDir: URL?, generation: UUID?,
                       origin: AuthStorage$Claude.Credentials) async -> String? {
        if let cached = emails[service] { return cached.isEmpty ? nil : cached }
        let email = await Task.detached(priority: .utility) {
            Self.email(configDir: configDir)
        }.value
        guard isCurrent(service, generation: generation, origin: origin) else { return nil }
        emails[service] = email ?? ""
        return email
    }

    /// Конфиг основного профиля — `~/.claude.json`; доп. профиля —
    /// `<CLAUDE_CONFIG_DIR>/.claude.json`.
    static func email(configDir: URL?) -> String? {
        let base = configDir ?? FileManager.default.homeDirectoryForCurrentUser
        let url = base.appendingPathComponent(".claude.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return parseEmail(fromConfig: data)
    }

    /// Разбор конфига. Чистый — покрыт самопроверкой без файловой системы.
    static func parseEmail(fromConfig data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let account = root["oauthAccount"] as? [String: Any],
              let email = account["emailAddress"] as? String, !email.isEmpty
        else { return nil }
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
        // Версию берём из пути, НЕ запуская `claude`: его запуск читает креды
        // через `security` и вызывает диалог Keychain на каждом старте.
        "claude-code/\(BinaryLocator.claudeVersion(fallback: "2.0.0"))"
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

        // Инертные окна-заглушки не показываем: 0 % и без даты сброса — это
        // неизвестные кодовые имена (например `nimbus_quill`), которые сервер
        // отдаёт про запас. Но только неизвестные (rank 4): основные окна
        // (five_hour, seven_day и их производные) сразу после сброса тоже
        // приходят как 0 % без даты, и прятать их нельзя — иначе окно «исчезает»
        // до следующего обращения к Claude.
        let active = windows.filter { !($0.utilization == 0 && $0.resetsAt == nil && rank($0.key) == 4) }
        let visible = active.isEmpty ? windows : active

        return visible.sorted { lhs, rhs in
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
