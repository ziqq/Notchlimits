import Foundation

/// Лимиты Codex: GET https://chatgpt.com/backend-api/wham/usage
///
/// Запрос собран ровно как в codex-rs/backend-client (rate_limit_resets.rs):
/// Bearer-токен из auth.json, идентификатор аккаунта отдельным заголовком
/// и User-Agent вида codex_cli_rs/<версия>.
struct CodexProvider: UsageProvider {

    private let endpoint = URL(string: "https://chatgpt.com/backend-api/wham/usage")!

    struct Auth {
        let accessToken: String
        let accountID: String
        let email: String?
        let expiresAt: Date?
    }

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .codexHome(let home) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }

        guard let auth = Self.readAuth(codexHome: home) else {
            return .reauth(L.t("column.reauth.codex"))
        }
        if let expiresAt = auth.expiresAt, expiresAt.timeIntervalSinceNow < 60 {
            return .reauth(L.t("column.reauth.codex"))
        }

        let headers = [
            "Authorization": "Bearer \(auth.accessToken)",
            "ChatGPT-Account-ID": auth.accountID,
            "User-Agent": Self.userAgent,
            "Accept": "application/json"
        ]

        switch await HTTPClient.shared.get(endpoint, headers: headers) {
        case .failure(let error):
            if case .transport(let message) = error { return .failure(message) }
            return .failure(L.t("error.network"))

        case .success(let response):
            switch response.status {
            case 200:
                guard let windows = Self.parse(response.data) else {
                    return .failure(L.t("error.parse"))
                }
                let subtitle = Self.email(from: response.data) ?? auth.email
                return .success(UsageSnapshot(subtitle: subtitle, windows: windows))
            case 401, 403:
                return .reauth(L.t("column.reauth.codex"))
            case 429:
                return .rateLimited(retryAfter: response.retryAfter)
            default:
                return .failure(L.t("error.http", response.status))
            }
        }
    }

    // MARK: - auth.json

    static func readAuth(codexHome: URL) -> Auth? {
        let url = codexHome.appendingPathComponent("auth.json")
        guard let data = try? Data(contentsOf: url),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        // Режим apikey до usage-эндпоинта не дотягивается — нужен вход через ChatGPT.
        if let mode = root["auth_mode"] as? String, mode != "chatgpt" { return nil }

        guard let tokens = root["tokens"] as? [String: Any],
              let accessToken = tokens["access_token"] as? String, !accessToken.isEmpty,
              let accountID = tokens["account_id"] as? String, !accountID.isEmpty
        else { return nil }

        let email = (tokens["id_token"] as? String).flatMap(JWT.email)
        return Auth(accessToken: accessToken,
                    accountID: accountID,
                    email: email,
                    expiresAt: JWT.expiry(accessToken))
    }

    private static let userAgent: String = {
        let version = BinaryLocator.codex().map {
            BinaryLocator.version(of: $0, fallback: "0.0.0")
        } ?? "0.0.0"
        return "codex_cli_rs/\(version)"
    }()

    // MARK: - Разбор ответа

    static func email(from data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return root["email"] as? String
    }

    static func parse(_ data: Data) -> [LimitWindow]? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var windows: [LimitWindow] = []
        if let rateLimit = root["rate_limit"] as? [String: Any] {
            windows += self.windows(from: rateLimit, prefix: nil, keyPrefix: "main")
        }

        if let additional = root["additional_rate_limits"] as? [[String: Any]] {
            for (index, entry) in additional.enumerated() {
                let name = (entry["limit_name"] as? String)
                    ?? (entry["metered_feature"] as? String)
                guard let nested = entry["rate_limit"] as? [String: Any] else { continue }
                windows += self.windows(from: nested,
                                        prefix: name,
                                        keyPrefix: name ?? "extra\(index)")
            }
        }

        return windows
    }

    private static func windows(from rateLimit: [String: Any],
                                prefix: String?,
                                keyPrefix: String) -> [LimitWindow] {
        var result: [LimitWindow] = []
        for slot in ["primary_window", "secondary_window"] {
            guard let window = rateLimit[slot] as? [String: Any],
                  let used = (window["used_percent"] as? NSNumber)?.doubleValue
            else { continue }

            let seconds = (window["limit_window_seconds"] as? NSNumber)?.doubleValue
            var resetsAt: Date?
            if let reset = (window["reset_at"] as? NSNumber)?.doubleValue {
                resetsAt = Date(timeIntervalSince1970: reset)
            } else if let after = (window["reset_after_seconds"] as? NSNumber)?.doubleValue {
                resetsAt = Date().addingTimeInterval(after)
            }

            var title = self.title(forWindowSeconds: seconds)
            if let prefix, !prefix.isEmpty { title = "\(prefix) · \(title)" }

            result.append(LimitWindow(key: "\(keyPrefix).\(slot)",
                                      title: title,
                                      utilization: max(0, min(used, 100)),
                                      resetsAt: resetsAt))
        }
        return result
    }

    /// Имя окна выводим из его длительности — набор окон в ответе не фиксирован.
    static func title(forWindowSeconds seconds: Double?) -> String {
        guard let seconds, seconds > 0 else { return L.t("window.generic") }
        let hours = Int((seconds / 3_600).rounded())
        if hours == 5 { return L.t("window.fiveHour") }
        if hours == 168 { return L.t("window.week") }
        if hours % 24 == 0 { return L.t("window.days", hours / 24) }
        return L.t("window.hours", hours)
    }
}
