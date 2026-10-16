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
    enum Backend { case keychain, file }

    struct Credentials {
        var backend: Backend = .keychain
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
            backend == other.backend && accessToken == other.accessToken && refreshToken == other.refreshToken
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

    /// Check existence without reading the secret or requesting authorization.
    static func contains(service: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
            || credentialFile(service: service).map { FileManager.default.fileExists(atPath: $0.path) } == true
    }

    /// Записи с датой последнего изменения. Только атрибуты — секрет не
    /// читается, диалога пароля не будет.
    static func items() -> [(service: String, modified: Date?)] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let items = status == errSecSuccess ? (result as? [[String: Any]] ?? []) : []

        var found: [String: Date?] = [:]
        for item in items {
            guard let service = item[kSecAttrService as String] as? String,
                  service == baseService || service.hasPrefix(baseService + "-") else { continue }
            found[service] = item[kSecAttrModificationDate as String] as? Date
        }
        // Native macOS login falls back to this file when Keychain rejects a write.
        // Discovery inspects metadata only, just like Keychain enumeration.
        let directories = [ProfileDirectories.home.appendingPathComponent(".claude")] + ProfileDirectories.claudeProfiles()
        for directory in directories {
            let file = directory.appendingPathComponent(".credentials.json")
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: file.path) else { continue }
            let service = directory == directories[0] ? baseService
                : found.keys.first(where: { configDirectory(for: $0) == directory })
                    ?? baseService + "-" + String(sha256Hex(directory.path).prefix(8))
            if found[service] == nil { found[service] = attributes[.modificationDate] as? Date }
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
    static func credentials(service: String, interactive: Bool = true) -> Credentials? {
        let item = readItem(service: service, interactive: interactive)
        guard let json = item.json, var credentials = parse(json) else { return nil }
        credentials.backend = item.backend
        return credentials
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
        return access { SecItemCopyMatching(query as CFDictionary, &result) }
    }

    /// Сырой JSON записи. Нужен отдельно, чтобы при записи сохранить поля,
    /// про которые мы не знаем: их пишет CLI, и терять их нельзя.
    private static func rawItem(service: String, interactive: Bool = true) -> [String: Any]? {
        readItem(service: service, interactive: interactive).json
    }

    private static func readItem(service: String, interactive: Bool,
                                 backend: Backend? = nil) -> (json: [String: Any]?, status: OSStatus, backend: Backend) {
        if backend == .file { return readFile(service: service) }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        let status = access(interactive: interactive) { SecItemCopyMatching(query as CFDictionary, &result) }
        let json = (result as? Data).flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] }
        if backend == nil, status != errSecSuccess || json == nil {
            let file = readFile(service: service)
            if file.json != nil { return file }
        }
        return (status == errSecSuccess ? json : nil, status, .keychain)
    }

    static func credentialFile(service: String) -> URL? {
        storageDirectory(service: service)?.appendingPathComponent(".credentials.json")
    }

    private static func readFile(service: String) -> (json: [String: Any]?, status: OSStatus, backend: Backend) {
        guard let file = credentialFile(service: service), FileManager.default.fileExists(atPath: file.path) else {
            return (nil, errSecItemNotFound, .file)
        }
        guard let data = try? Data(contentsOf: file),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return (nil, errSecAuthFailed, .file)
        }
        return (json, errSecSuccess, .file)
    }

    private static let interactionLock = NSLock()

    /// Claude uses classic login Keychain items. LAContext's interaction flag
    /// does not govern their legacy ACL dialogs. Serialize the process-wide
    /// legacy interaction setting with all secret reads and restore it afterward.
    static func access(interactive: Bool = true, _ operation: () -> OSStatus) -> OSStatus {
        interactionLock.lock()
        defer { interactionLock.unlock() }
        guard !interactive else { return operation() }
        var allowed: DarwinBoolean = false
        guard SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess,
              SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else {
            return errSecInteractionNotAllowed
        }
        defer { _ = SecKeychainSetUserInteractionAllowed(allowed.boolValue) }
        return operation()
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
                     expected: Credentials, renewalLock: ClaudeRefreshLock? = nil) -> SaveResult {
        guard let storageLock = storageLock(service: service, createParent: renewalLock == nil) else { return .failed }
        defer { storageLock.release() }
        let item = readItem(service: service, interactive: renewalLock == nil, backend: expected.backend)
        guard var json = item.json else { return item.status == errSecItemNotFound ? .changed : .failed }
        guard var current = parse(json) else { return .changed }
        current.backend = item.backend
        guard current.hasSameTokens(as: expected),
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

        return write(data, service: service, backend: item.backend, storageLock: storageLock,
                     renewalLock: renewalLock) ? .saved : .failed
    }

    /// Можно ли писать в запись: перезаписываем её же содержимым. Проверяем
    /// ДО продления — сервер отзывает прежний refresh-токен, и если новый
    /// потом не записать, в Keychain останется мёртвый, а CLI, наткнувшись
    /// на него, обнулит вход. Блокирующий вызов — только вне главного потока.
    static func canWrite(service: String, renewalLock: ClaudeRefreshLock? = nil) -> Bool {
        guard let storageLock = storageLock(service: service, createParent: renewalLock == nil) else { return false }
        defer { storageLock.release() }
        let item = readItem(service: service, interactive: renewalLock == nil)
        guard let json = item.json,
              let data = try? JSONSerialization.data(withJSONObject: json) else { return false }
        return write(data, service: service, backend: item.backend, storageLock: storageLock, renewalLock: renewalLock)
    }

    private static func write(_ data: Data, service: String, backend: Backend,
                              storageLock: ClaudeStorageLock, renewalLock: ClaudeRefreshLock?) -> Bool {
        if backend == .file {
            guard storageLock.isHeld, renewalLock?.isHeld != false,
                  let file = credentialFile(service: service) else { return false }
            do {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                try data.write(to: file, options: .atomic)
                return true
            } catch { return false }
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        return access(interactive: false) {
            guard storageLock.isHeld, renewalLock?.isHeld != false else { return errSecInteractionNotAllowed }
            return SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        } == errSecSuccess
    }

    static func refreshLock(service: String) -> ClaudeRefreshLock? {
        guard supportsStorageLock, let directory = storageDirectory(service: service) else { return nil }
        return try? ClaudeRefreshLock(directory: directory, createParent: service == baseService)
    }

    static func withRemovalLock(service: String, configDir: URL?, operation: () throws -> Void) throws {
        // Never delete outside the native protocol when the directory is unknown.
        guard let directory = configDir ?? storageDirectory(service: service) else {
            throw UnknownRemovalDirectory()
        }
        try ClaudeRefreshLock.withRemovalLock(directory: directory, createParent: service == baseService) { lease in
            let storage = try ClaudeStorageLock(directory: directory, createParent: false)
            defer { storage.release() }
            guard lease.isHeld, storage.isHeld else { throw ClaudeStorageLock.Failure.lost }
            try operation()
        }
    }

    private struct UnknownRemovalDirectory: LocalizedError {
        var errorDescription: String? { L.t("error.cliProfile") }
    }

    private static func storageLock(service: String, createParent: Bool) -> ClaudeStorageLock? {
        guard supportsStorageLock, let directory = storageDirectory(service: service) else { return nil }
        // Renewal already owns this directory. Do not recreate it after removal.
        return try? ClaudeStorageLock(directory: directory, createParent: createParent && service == baseService)
    }

    private static func storageDirectory(service: String) -> URL? {
        service == baseService ? ProfileDirectories.home.appendingPathComponent(".claude")
                               : configDirectory(for: service)
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
        guard access({ SecItemCopyMatching(query as CFDictionary, &result) }) == errSecSuccess,
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
        let updated = access { SecItemUpdate(base as CFDictionary,
                                             [kSecValueData as String: data] as CFDictionary) }
        if updated == errSecSuccess { return true }
        if updated == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            return access { SecItemAdd(add as CFDictionary, nil) } == errSecSuccess
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
        profileLocation(for: service)?.directory
    }

    /// Preserve the exact config string: the CLI hashes it before resolving paths.
    static func configPath(for service: String) -> String? {
        guard let path = profileLocation(for: service)?.path,
              service == baseService + "-" + String(sha256Hex(path).prefix(8)) else { return nil }
        return path
    }

    private static func profileLocation(for service: String) -> (directory: URL, path: String)? {
        guard service.hasPrefix(baseService + "-") else { return nil }
        let suffix = String(service.dropFirst(baseService.count + 1))
        guard !suffix.isEmpty else { return nil }
        for directory in ProfileDirectories.claudeProfiles() {
            for variant in pathVariants(directory) {
                let hex = sha256Hex(variant)
                if hex.hasPrefix(suffix) || suffix.hasPrefix(hex) {
                    return (directory, variant.precomposedStringWithCanonicalMapping)
                }
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
        SHA256.hash(data: Data(string.precomposedStringWithCanonicalMapping.utf8)).map { String(format: "%02x", $0) }.joined()
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

    static func claudeProfiles() -> [URL] {
        // Foundation enumeration can reject a symlink as its root. Enumerate
        // the physical directory but retain the original CLI config spelling.
        subdirectories(of: claudeRoot.resolvingSymlinksInPath()).map {
            claudeRoot.appendingPathComponent($0.lastPathComponent, isDirectory: true)
        }
    }
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
