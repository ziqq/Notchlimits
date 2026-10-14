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

        func hasSameTokens(as other: Credentials) -> Bool {
            accessToken == other.accessToken && refreshToken == other.refreshToken
        }
    }

    enum SaveResult {
        case saved, changed, failed
    }

    /// The secureStorage.mutate protocol was verified in Claude Code 2.1.278.
    /// Leave credential writes to older or unidentified CLI versions.
    static var supportsStorageLock: Bool {
        BinaryLocator.claudeVersion(fallback: "0").compare("2.1.278", options: .numeric) != .orderedAscending
    }

    /// Имена всех generic password с нашим префиксом.
    static func services() -> [String] { items().map(\.service) }

    /// Записи с датой последнего изменения. Только атрибуты — секрет не
    /// читается, диалога пароля не будет.
    static func items() -> [(service: String, modified: Date?)] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return [] }

        var found: [String: Date?] = [:]
        for item in items {
            guard let service = item[kSecAttrService as String] as? String,
                  service == baseService || service.hasPrefix(baseService + "-") else { continue }
            found[service] = item[kSecAttrModificationDate as String] as? Date
        }
        return found
            .map { (service: $0.key, modified: $0.value) }
            .sorted { lhs, rhs in
                if lhs.service == baseService { return true }
                if rhs.service == baseService { return false }
                return lhs.service < rhs.service
            }
    }

    /// Запись есть, но входа в ней нет. Голый `claude` пишет в базовую запись
    /// служебное (`trustedDeviceToken`) даже без логина — это не аккаунт.
    static func hasNoLogin(service: String) -> Bool {
        guard let json = rawItem(service: service) else { return false }
        return isNoLogin(json)
    }

    /// Запись, обнулённая самим CLI после `invalid_grant` (пустые токены),
    /// — это аккаунт, которому нужен вход, а не служебная запись.
    static func isNoLogin(_ json: [String: Any]) -> Bool {
        json["claudeAiOauth"] == nil
    }

    // MARK: - Записи без входа

    private static let stubsKey = "claudeKeychainStubs"

    /// Запомнить запись без входа вместе с датой изменения: пока запись та же,
    /// колонкой её не показываем. Войдут в неё — дата сменится, и она снова
    /// станет аккаунтом.
    static func markNoLogin(service: String) {
        guard let modified = items().first(where: { $0.service == service })?.modified else { return }
        var stubs = UserDefaults.standard.dictionary(forKey: stubsKey) as? [String: Double] ?? [:]
        stubs[service] = modified.timeIntervalSince1970
        UserDefaults.standard.set(stubs, forKey: stubsKey)
    }

    static func isKnownNoLogin(service: String, modified: Date?) -> Bool {
        guard let modified,
              let stubs = UserDefaults.standard.dictionary(forKey: stubsKey) as? [String: Double],
              let seen = stubs[service] else { return false }
        return seen == modified.timeIntervalSince1970
    }

    /// Чтение секрета. Блокирующий вызов — только вне главного потока.
    static func credentials(service: String) -> Credentials? {
        guard let json = rawItem(service: service) else { return nil }
        return parse(json)
    }

    /// Код ответа Keychain на чтение секрета — для диагностики (NOTCHLIMITS_PROBE).
    static func readStatus(service: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result)
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

    /// Записать обновлённые токены обратно в запись CLI.
    ///
    /// Hold the CLI's shared storage lock from read to write and merge into the
    /// current JSON. Discard a stale response if the login changed, preserving
    /// unknown fields. This blocking operation must run off the main thread.
    @discardableResult
    static func save(service: String, tokens: ClaudeOAuth.Tokens,
                     expected: Credentials) -> SaveResult {
        guard let storageLock = storageLock(service: service) else { return .failed }
        defer { storageLock.release() }
        guard var json = rawItem(service: service) else { return .failed }
        guard let current = parse(json), current.hasSameTokens(as: expected),
              var oauth = json["claudeAiOauth"] as? [String: Any] else { return .changed }

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
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return .failed }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        guard storageLock.isHeld else { return .failed }
        return SecItemUpdate(query as CFDictionary,
                             [kSecValueData as String: data] as CFDictionary) == errSecSuccess
            ? .saved : .failed
    }

    /// Можно ли писать в запись: перезаписываем её же содержимым. Проверяем
    /// ДО продления — сервер отзывает прежний refresh-токен, и если новый
    /// потом не записать, в Keychain останется мёртвый, а CLI, наткнувшись
    /// на него, обнулит вход. Блокирующий вызов — только вне главного потока.
    static func canWrite(service: String) -> Bool {
        guard let storageLock = storageLock(service: service) else { return false }
        defer { storageLock.release() }
        guard let data = rawData(service: service) else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        guard storageLock.isHeld else { return false }
        return SecItemUpdate(query as CFDictionary,
                             [kSecValueData as String: data] as CFDictionary) == errSecSuccess
    }

    private static func storageLock(service: String) -> ClaudeStorageLock? {
        guard supportsStorageLock else { return nil }
        let directory: URL
        if service == baseService {
            directory = ProfileDirectories.home.appendingPathComponent(".claude")
        } else if let profile = configDirectory(for: service) {
            directory = profile
        } else {
            // The CLI's secureStorage directory for this record is unknown.
            return nil
        }
        return try? ClaudeStorageLock(directory: directory)
    }

    /// Сырой blob записи Keychain — для копий keychain→keychain (свитчер
    /// аккаунтов), чтобы токены не попадали на диск.
    static func rawData(service: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return data
    }

    /// Записать сырой blob (создать запись или обновить существующую).
    @discardableResult
    static func writeRaw(service: String, data: Data) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let updated = SecItemUpdate(base as CFDictionary,
                                    [kSecValueData as String: data] as CFDictionary)
        if updated == errSecSuccess { return true }
        if updated == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
        }
        return false
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
