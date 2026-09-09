import Foundation
import Security

/// Полное удаление аккаунта: стираем учётные данные, по которым он вообще
/// обнаруживается. Claude находится по записи в Keychain, Codex — по папке с
/// `auth.json`, поэтому и удаляем именно их.
///
/// Основной аккаунт и доп. профиль трогаем по-разному: у доп. профиля сносим
/// всю папку (её целиком создавали мы), у основного — только вход
/// (запись Keychain / `auth.json`), не задевая остальной конфиг CLI.
enum AccountRemoval {

    enum Failure: Error { case keychain(OSStatus) }

    /// Доп. профиль (папку создавали мы) или основной аккаунт CLI.
    static func isExtraProfile(_ account: DiscoveredAccount) -> Bool {
        switch account.source {
        case .claudeKeychain(_, let configDir):
            return configDir != nil
        case .codexHome(let url):
            return url.path.hasPrefix(ProfileDirectories.codexRoot.path + "/")
        case .mock:
            return false
        }
    }

    static func remove(_ account: DiscoveredAccount) throws {
        let fileManager = FileManager.default
        switch account.source {
        case .claudeKeychain(let service, let configDir):
            try deleteKeychainEntry(service: service)
            // Папку доп. профиля сносим целиком; основной (configDir == nil)
            // не трогаем — там живёт сам CLI пользователя.
            if let configDir,
               configDir.path.hasPrefix(ProfileDirectories.claudeRoot.path + "/") {
                try? fileManager.removeItem(at: configDir)
            }

        case .codexHome(let url):
            if url.path.hasPrefix(ProfileDirectories.codexRoot.path + "/") {
                try fileManager.removeItem(at: url)           // доп. профиль — вся папка
            } else {
                let auth = url.appendingPathComponent("auth.json")
                if fileManager.fileExists(atPath: auth.path) {
                    try fileManager.removeItem(at: auth)      // основной — только выход
                }
            }

        case .mock:
            break
        }
    }

    private static func deleteKeychainEntry(service: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.keychain(status)
        }
    }
}
