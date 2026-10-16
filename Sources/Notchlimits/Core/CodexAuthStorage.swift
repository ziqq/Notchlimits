import Foundation
import Security
import CryptoKit

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
    private var query: [String: Any] {
        let path = home.resolvingSymlinksInPath().path
        let hash = SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined()
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "Codex Auth",
                kSecAttrAccount as String: "cli|" + hash.prefix(16)]
    }

    init(home: URL, mode: Mode? = nil) throws {
        self.home = home
        self.mode = try mode ?? Self.configuredMode(home: home)
    }

    func load() throws -> Record? {
        switch mode {
        case .ephemeral: return nil // Another process's memory is not an auth cache.
        case .file: return try loadFile()
        case .keyring: return try loadKeyring()
        case .auto:
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

    func delete() throws {
        guard mode != .ephemeral else { throw Failure.ephemeral }
        if mode != .file {
            let status = ClaudeKeychain.access(interactive: false) { SecItemDelete(query as CFDictionary) }
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
        }
        try removeFile()
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
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }

    private func removeFile() throws {
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

    /// Read only auth bootstrap scalars, preserving TOML string/comment boundaries.
    /// Other tables (including model profiles) cannot override root auth settings.
    private static func settings(_ text: String) throws -> [String: String] {
        let chars = Array(text)
        var statements: [String] = [], current = "", quote: Character?, triple = false
        var depth = 0, index = 0
        while index < chars.count {
            let ch = chars[index]
            if let delimiter = quote {
                current.append(ch)
                if delimiter == "\"", ch == "\\", index + 1 < chars.count {
                    index += 1; current.append(chars[index])
                } else if ch == delimiter {
                    if !triple { quote = nil }
                    else if index + 2 < chars.count, chars[index + 1] == delimiter, chars[index + 2] == delimiter {
                        current.append(delimiter); current.append(delimiter); index += 2; quote = nil; triple = false
                    }
                }
            } else if ch == "#" {
                while index < chars.count && chars[index] != "\n" { index += 1 }
                continue
            } else if ch == "\"" || ch == "'" {
                quote = ch; current.append(ch)
                if index + 2 < chars.count, chars[index + 1] == ch, chars[index + 2] == ch {
                    triple = true; current.append(ch); current.append(ch); index += 2
                }
            } else if ch == "\n" && depth == 0 {
                statements.append(current); current = ""
            } else {
                current.append(ch)
                if ch == "[" || ch == "{" { depth += 1 }
                if ch == "]" || ch == "}" { depth -= 1 }
            }
            index += 1
        }
        guard quote == nil, depth == 0 else { throw Failure.settings }
        statements.append(current)
        var section = "", values: [String: String] = [:]
        for statement in statements {
            let line = statement.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("[") { section = line; continue }
            guard let equal = line.firstIndex(of: "=") else { continue }
            var key = String(line[..<equal]).trimmingCharacters(in: .whitespaces)
            if key.hasPrefix("\"") || key.hasPrefix("'") { key = String(key.dropFirst().dropLast()) }
            if section == "[features]" { key = "features." + key }
            else if !section.isEmpty { continue }
            guard key == "cli_auth_credentials_store" || key == "features.secret_auth_storage" else { continue }
            guard values[key] == nil else { throw Failure.settings }
            let raw = String(line[line.index(after: equal)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            if key == "features.secret_auth_storage" {
                guard raw == "true" || raw == "false" else { throw Failure.settings }
                values[key] = raw
            } else if raw.hasPrefix("'") && raw.hasSuffix("'") && raw.count >= 2 {
                values[key] = String(raw.dropFirst().dropLast())
            } else {
                guard let data = raw.data(using: .utf8),
                      let value = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String else {
                    throw Failure.settings
                }
                values[key] = value
            }
        }
        return values
    }
}
