import Foundation

/// Разбор payload JWT без проверки подписи: нужен только `exp` и `email`.
/// Токен никуда не пишется и не логируется.
enum JWT {
    static func claims(_ token: String) -> [String: Any]? {
        let parts = token.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var base64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        guard let data = Data(base64Encoded: base64) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    static func expiry(_ token: String) -> Date? {
        guard let exp = claims(token)?["exp"] as? Double else { return nil }
        return Date(timeIntervalSince1970: exp)
    }

    /// E-mail из id_token: у ChatGPT он лежит либо в корне, либо в profile-клейме.
    static func email(_ token: String) -> String? {
        guard let claims = claims(token) else { return nil }
        if let email = claims["email"] as? String { return email }
        for value in claims.values {
            if let nested = value as? [String: Any], let email = nested["email"] as? String {
                return email
            }
        }
        return nil
    }
}
