import Foundation

/// Продление доступа Claude по refresh-токену из Keychain.
///
/// Запрос собран ровно как в CLI: POST JSON на TOKEN_URL с grant_type,
/// refresh_token, client_id и правами через пробел. client_id — публичный
/// идентификатор клиента Claude Code, секрета в нём нет.
///
/// Токен обновления может ротироваться: если в ответе пришёл новый, прежний
/// перестаёт действовать, поэтому результат обязательно пишется обратно в
/// Keychain — иначе мы сломаем вход самого CLI.
enum ClaudeOAuth {

    static let tokenURL = URL(string: "https://platform.claude.com/v1/oauth/token")!
    static let clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

    /// Права по умолчанию — на случай записи без поля scopes.
    static let defaultScopes = ["user:inference", "user:profile"]

    struct Tokens {
        let accessToken: String
        let expiresAt: Date
        /// nil — сервер не ротировал токен обновления, прежний ещё годен.
        let refreshToken: String?
        let refreshTokenExpiresAt: Date?
        let scopes: [String]?
    }

    enum Outcome {
        case success(Tokens)
        /// Токен обновления отозван или протух — нужен вход через CLI.
        case rejected
        /// Сеть, таймаут, 5xx: не приговор, просто попробуем позже.
        case unavailable
    }

    static func refresh(refreshToken: String, scopes: [String]) async -> Outcome {
        let body: [String: Any] = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": clientID,
            "scope": (scopes.isEmpty ? defaultScopes : scopes).joined(separator: " ")
        ]

        switch await HTTPClient.shared.post(tokenURL, headers: ["Accept": "application/json"], json: body) {
        case .failure:
            return .unavailable
        case .success(let response):
            switch response.status {
            case 200:
                guard let tokens = parse(response.data, now: Date()) else { return .unavailable }
                return .success(tokens)
            // 400 invalid_grant приходит именно так, когда токен уже отозван.
            case 400, 401, 403:
                return .rejected
            default:
                return .unavailable
            }
        }
    }

    /// Разбор ответа. Чистая функция — покрыта самопроверкой без сети.
    static func parse(_ data: Data, now: Date) -> Tokens? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accessToken = root["access_token"] as? String, !accessToken.isEmpty,
              let expiresIn = (root["expires_in"] as? NSNumber)?.doubleValue, expiresIn > 0
        else { return nil }

        let refreshToken = (root["refresh_token"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        var refreshExpiry: Date?
        if let seconds = (root["refresh_token_expires_in"] as? NSNumber)?.doubleValue, seconds > 0 {
            refreshExpiry = now.addingTimeInterval(seconds)
        }
        // scope приходит одной строкой через пробел.
        let scopes = (root["scope"] as? String)?
            .split(separator: " ")
            .map(String.init)

        return Tokens(accessToken: accessToken,
                      expiresAt: now.addingTimeInterval(expiresIn),
                      refreshToken: refreshToken,
                      refreshTokenExpiresAt: refreshExpiry,
                      scopes: scopes?.isEmpty == true ? nil : scopes)
    }
}
