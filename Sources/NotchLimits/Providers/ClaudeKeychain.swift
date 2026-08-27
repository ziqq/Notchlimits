import Foundation
import CryptoKit
import Security

/// Доступ к записям Claude Code в Keychain.
///
/// Перечисление профилей запрашивает только атрибуты — это не трогает ACL и не
/// вызывает диалог. Диалог macOS показывает один раз при первом чтении самого
/// секрета; в нём нужно нажать «Разрешать всегда».
enum ClaudeKeychain {

    static let baseService = "Claude Code-credentials"

    struct Credentials {
        let accessToken: String
        let expiresAt: Date?
        /// План подписки из записи Keychain («pro», «max»…). Почты Anthropic
        /// нигде не отдаёт, поэтому в подзаголовок кладём хотя бы план.
        let plan: String?
        /// Токен обновления и его срок — ими продлевается доступ, когда
        /// accessToken протух, а перезапускать CLI некому.
        let refreshToken: String?
        let refreshTokenExpiresAt: Date?
        /// Права из записи: их же отправляем при обновлении, чтобы не сузить
        /// набор молча.
        let scopes: [String]

        var isRefreshable: Bool {
            guard let refreshToken, !refreshToken.isEmpty else { return false }
            guard let refreshTokenExpiresAt else { return true }
            return refreshTokenExpiresAt.timeIntervalSinceNow > 60
        }
    }

    /// Имена всех generic password с нашим префиксом.
    static func services() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return [] }

        let names = items
            .compactMap { $0[kSecAttrService as String] as? String }
            .filter { $0 == baseService || $0.hasPrefix(baseService + "-") }
        return Array(Set(names)).sorted { lhs, rhs in
            if lhs == baseService { return true }
            if rhs == baseService { return false }
            return lhs < rhs
        }
    }

    /// Чтение секрета. Блокирующий вызов — только вне главного потока.
    static func credentials(service: String) -> Credentials? {
        guard let json = rawItem(service: service) else { return nil }
        return parse(json)
    }

    /// Сырой JSON записи. Нужен отдельно, чтобы при записи сохранить поля,
    /// про которые мы не знаем: их пишет CLI, и терять их нельзя.
    private static func rawItem(service: String) -> [String: Any]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return json
    }

    /// Разбор записи. Вынесен отдельно — так его покрывает самопроверка,
    /// не трогая Keychain.
    static func parse(_ json: [String: Any]) -> Credentials? {
        guard let oauth = json["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String, !token.isEmpty
        else { return nil }

        let plan = (oauth["subscriptionType"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let refresh = (oauth["refreshToken"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return Credentials(accessToken: token,
                           expiresAt: millis(oauth["expiresAt"]),
                           plan: plan,
                           refreshToken: refresh,
                           refreshTokenExpiresAt: millis(oauth["refreshTokenExpiresAt"]),
                           scopes: (oauth["scopes"] as? [String]) ?? [])
    }

    /// Сроки в записи хранятся в миллисекундах.
    private static func millis(_ value: Any?) -> Date? {
        guard let millis = (value as? NSNumber)?.doubleValue, millis > 0 else { return nil }
        return Date(timeIntervalSince1970: millis / 1000)
    }

    /// Можно ли вообще писать в эту запись: пишем в неё же то, что там лежит.
    ///
    /// Нужно до обновления, а не после: сервер вправе ротировать refresh-токен,
    /// и если записать новый мы не сможем, прежний окажется отозван, а CLI
    /// останется с мёртвым токеном. Проще не обновляться вовсе.
    static func isWritable(service: String) -> Bool {
        guard let json = rawItem(service: service),
              let data = try? JSONSerialization.data(withJSONObject: json)
        else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        return SecItemUpdate(query as CFDictionary,
                             [kSecValueData as String: data] as CFDictionary) == errSecSuccess
    }

    /// Записать обновлённые токены обратно в запись CLI.
    ///
    /// Читаем прямо перед записью и накладываем изменения на свежий JSON:
    /// между нашим чтением и записью CLI мог сам обновить токен, и затирать
    /// его целой старой копией нельзя. Все незнакомые поля сохраняются.
    /// Блокирующий вызов — только вне главного потока.
    @discardableResult
    static func save(service: String, tokens: ClaudeOAuth.Tokens) -> Bool {
        guard var json = rawItem(service: service) else { return false }
        var oauth = (json["claudeAiOauth"] as? [String: Any]) ?? [:]

        oauth["accessToken"] = tokens.accessToken
        oauth["expiresAt"] = tokens.expiresAt.timeIntervalSince1970 * 1000
        // Ротация необязательна: если сервер не прислал новый токен обновления,
        // прежний остаётся действующим и трогать его нельзя.
        if let refreshToken = tokens.refreshToken { oauth["refreshToken"] = refreshToken }
        if let refreshExpiry = tokens.refreshTokenExpiresAt {
            oauth["refreshTokenExpiresAt"] = refreshExpiry.timeIntervalSince1970 * 1000
        }
        if let scopes = tokens.scopes, !scopes.isEmpty { oauth["scopes"] = scopes }

        json["claudeAiOauth"] = oauth
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        return SecItemUpdate(query as CFDictionary,
                             [kSecValueData as String: data] as CFDictionary) == errSecSuccess
    }

    /// Папка профиля для записи с суффиксом-хэшем.
    /// claude хэширует путь CLAUDE_CONFIG_DIR, поэтому хэш не вычисляем «вперёд»,
    /// а сверяем известные папки профилей с суффиксом записи.
    static func profileName(for service: String) -> String {
        guard service != baseService else { return ProfileDirectories.primaryName }
        let suffix = String(service.dropFirst(baseService.count + 1))
        guard !suffix.isEmpty else { return ProfileDirectories.primaryName }
        if let directory = configDirectory(for: service) { return directory.lastPathComponent }
        return String(suffix.prefix(8))
    }

    /// Папка профиля, соответствующая записи (нужна для подписи и меню).
    static func configDirectory(for service: String) -> URL? {
        guard service != baseService else { return nil }
        let suffix = String(service.dropFirst(baseService.count + 1))
        guard !suffix.isEmpty else { return nil }
        for directory in ProfileDirectories.claudeProfiles() {
            for variant in pathVariants(directory) {
                let hex = sha256Hex(variant)
                if hex.hasPrefix(suffix) || suffix.hasPrefix(hex) { return directory }
            }
        }
        return nil
    }

    private static func pathVariants(_ url: URL) -> [String] {
        let path = url.path
        return Array(Set([path, path + "/",
                          url.standardizedFileURL.path,
                          url.resolvingSymlinksInPath().path]))
    }

    private static func sha256Hex(_ string: String) -> String {
        SHA256.hash(data: Data(string.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

/// Где живут дополнительные профили CLI.
enum ProfileDirectories {
    /// Как подписан основной профиль у обоих провайдеров: заголовки колонок
    /// не должны расходиться на «main» и «default».
    static let primaryName = "main"

    static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
    static var claudeRoot: URL { home.appendingPathComponent(".claude-profiles") }
    static var codexRoot: URL { home.appendingPathComponent(".codex-profiles") }

    static func claudeProfiles() -> [URL] { subdirectories(of: claudeRoot) }
    static func codexProfiles() -> [URL] { subdirectories(of: codexRoot) }

    static func subdirectories(of root: URL) -> [URL] {
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]
        ) else { return [] }
        return entries
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }
}
