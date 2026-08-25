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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let oauth = json["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String, !token.isEmpty
        else { return nil }

        var expiresAt: Date?
        if let millis = oauth["expiresAt"] as? Double {
            expiresAt = Date(timeIntervalSince1970: millis / 1000)
        }
        return Credentials(accessToken: token, expiresAt: expiresAt)
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
