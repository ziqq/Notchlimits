import Foundation
import Security
import CryptoKit
import TOMLDecoder

/// The native Codex auth payload, stored under the selected CODEX_HOME.
struct CodexAuthStorage {
    enum Mode: String { case file, keyring, auto, ephemeral }
    enum Backend { case file, keyring }
    struct Record { let data: Data; let backend: Backend }
    enum Failure: LocalizedError {
        case settings, ephemeral, keychain(OSStatus)
        var errorDescription: String? {
            switch self {
            case .settings: return L.t("error.codexStorage")
            case .ephemeral: return L.t("error.codexEphemeral")
            case .keychain(let status): return SecCopyErrorMessageString(status, nil) as String?
            }
        }
    }

    let home: URL
    let mode: Mode
    private var file: URL { home.appendingPathComponent("auth.json") }
    private let account: String
    private var query: [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "Codex Auth",
                kSecAttrAccount as String: account]
    }

    init(home: URL, mode: Mode? = nil) throws {
        self.home = home
        self.mode = try mode ?? Self.configuredMode(home: home)
        let hash = SHA256.hash(data: Data(home.resolvingSymlinksInPath().path.utf8))
            .map { String(format: "%02x", $0) }.joined()
        account = "cli|" + hash.prefix(16)
    }

    func load(backend: Backend? = nil, verifyingOwner: Bool = false) throws -> Record? {
        if let backend {
            return try backend == .keyring ? loadKeyring() : loadFile()
        }
        switch mode {
        case .ephemeral: return nil // Another process's memory is not an auth cache.
        case .file: return try loadFile()
        case .keyring: return try loadKeyring()
        case .auto:
            // Native reads may fall back on errors. A switch must distinguish
            // an unavailable owner from a confirmed missing or different login.
            if verifyingOwner { return try loadKeyring() ?? loadFile() }
            if let record = try? loadKeyring() { return record }
            return try loadFile()
        }
    }

    func contains() -> Bool {
        switch mode {
        case .ephemeral: return false
        case .file: return FileManager.default.fileExists(atPath: file.path)
        case .keyring: return keyringStatus() == errSecSuccess
        case .auto:
            return keyringStatus() == errSecSuccess || FileManager.default.fileExists(atPath: file.path)
        }
    }

    /// Renewal persists back to the backend that supplied its current grant.
    /// A denied Keychain update must not hide rotated tokens behind a stale entry.
    func save(_ data: Data, backend: Backend? = nil) throws {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        if backend == .file || backend == nil && mode == .file {
            try saveFile(data)
            return
        }
        do {
            var status = ClaudeKeychain.access(interactive: false) {
                SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            }
            if status == errSecItemNotFound {
                var item = query
                item[kSecValueData as String] = data
                status = ClaudeKeychain.access(interactive: false) { SecItemAdd(item as CFDictionary, nil) }
            }
            guard status == errSecSuccess else { throw Failure.keychain(status) }
            try? removeFile()
        } catch {
            guard backend == nil, mode == .auto, keyringStatus() == errSecItemNotFound else { throw error }
            try saveFile(data)
        }
    }

    func delete(fileHome: URL? = nil) throws {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        let file = (fileHome ?? home).appendingPathComponent("auth.json")
        if mode == .file { try removeFile(at: file); return }
        let backup = FileManager.default.fileExists(atPath: file.path) ? try Data(contentsOf: file) : nil
        try removeFile(at: file)
        do {
            let status = ClaudeKeychain.access(interactive: false) { SecItemDelete(query as CFDictionary) }
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
        } catch {
            if let backup,
               !FileManager.default.createFile(atPath: file.path, contents: backup, attributes: [.posixPermissions: 0o600]) {
                throw CocoaError(.fileWriteUnknown)
            }
            throw error
        }
    }

    private func loadFile() throws -> Record? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        return Record(data: try Data(contentsOf: file), backend: .file)
    }

    private func loadKeyring() throws -> Record? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = ClaudeKeychain.access(interactive: false) { SecItemCopyMatching(request as CFDictionary, &result) }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
        guard let data = result as? Data,
              (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { throw Failure.settings }
        return Record(data: data, backend: .keyring)
    }

    private func keyringStatus() -> OSStatus {
        var request = query
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        return ClaudeKeychain.access(interactive: false) { SecItemCopyMatching(request as CFDictionary, nil) }
    }

    private func saveFile(_ data: Data) throws {
        let prepared = home.appendingPathComponent(".auth-" + UUID().uuidString + ".json")
        guard FileManager.default.createFile(atPath: prepared.path, contents: nil,
                                              attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? FileManager.default.removeItem(at: prepared) }
        // Finish every fallible preparation before publishing credentials. A
        // chmod failure must not change the login while its owner marker stays old.
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: prepared.path)
        try data.write(to: prepared)
        guard rename(prepared.path, file.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private func removeFile(at destination: URL? = nil) throws {
        let file = destination ?? self.file
        if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
    }

    private static func configuredMode(home: URL) throws -> Mode {
        var values: [String: String] = [:]
        for path in ["/etc/codex/config.toml", home.appendingPathComponent("config.toml").path,
                     "/etc/codex/managed_config.toml"] {
            try mergeFile(path, into: &values)
        }
        if let text = try managed("config_toml_base64") { values.merge(try settings(text)) { _, new in new } }
        try mergeFile("/etc/codex/requirements.toml", into: &values)
        if let text = try managed("requirements_toml_base64") { values.merge(try settings(text)) { _, new in new } }
        // The opt-in encrypted secrets backend has a different on-disk format.
        // Never mistake its absence in the direct Keychain backend for a file login.
        guard let mode = Mode(rawValue: values["cli_auth_credentials_store"] ?? "file"),
              mode == .file || mode == .ephemeral || values["features.secret_auth_storage"] != "true" else { throw Failure.settings }
        return mode
    }

    private static func mergeFile(_ path: String, into values: inout [String: String]) throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8) else {
            throw Failure.settings
        }
        values.merge(try settings(text)) { _, new in new }
    }

    private static func managed(_ name: String) throws -> String? {
        let key = name as CFString, domain = "com.openai.codex" as CFString
        guard CFPreferencesAppValueIsForced(key, domain) else { return nil }
        let value = CFPreferencesCopyAppValue(key, domain)
        guard CFPreferencesAppValueIsForced(key, domain), let encoded = value as? String,
              let data = Data(base64Encoded: encoded), let text = String(data: data, encoding: .utf8) else {
            throw Failure.settings
        }
        return text
    }

    /// Decode native TOML syntax, including quoted/dotted keys and inline tables.
    /// Only root auth settings participate; model profiles cannot override them.
    private static func settings(_ text: String) throws -> [String: String] {
        struct Settings: Decodable {
            struct Features: Decodable { let secret_auth_storage: Bool? }
            let cli_auth_credentials_store: String?
            let features: Features?
        }
        do {
            let settings = try TOMLDecoder(isLenient: false).decode(Settings.self, from: text)
            var values: [String: String] = [:]
            values["cli_auth_credentials_store"] = settings.cli_auth_credentials_store
            values["features.secret_auth_storage"] = settings.features?.secret_auth_storage.map(String.init)
            return values
        } catch {
            throw Failure.settings
        }
    }
}
