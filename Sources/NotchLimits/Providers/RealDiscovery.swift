import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
struct RealDiscovery: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts()
    }

    private func claudeAccounts() -> [DiscoveredAccount] {
        ClaudeKeychain.services().map { service in
            let name = ClaudeKeychain.profileName(for: service)
            return DiscoveredAccount(
                id: "claude:\(service)",
                provider: .claude,
                profileName: name,
                source: .claudeKeychain(service: service,
                                        configDir: ClaudeKeychain.configDirectory(for: service))
            )
        }
    }

    private func codexAccounts() -> [DiscoveredAccount] {
        // key — стабильный идентификатор колонки, name — подпись в заголовке.
        // Переименование основного профиля не должно ронять кэш и уведомления.
        var homes: [(key: String, name: String, url: URL)] = []

        let environment = ProcessInfo.processInfo.environment
        let defaultHome = environment["CODEX_HOME"].map { URL(fileURLWithPath: $0) }
            ?? ProfileDirectories.home.appendingPathComponent(".codex")
        if FileManager.default.fileExists(atPath: defaultHome.appendingPathComponent("auth.json").path) {
            homes.append((key: "default", name: ProfileDirectories.primaryName, url: defaultHome))
        }

        for directory in ProfileDirectories.codexProfiles() {
            guard FileManager.default.fileExists(
                atPath: directory.appendingPathComponent("auth.json").path
            ) else { continue }
            let folder = directory.lastPathComponent
            homes.append((key: folder, name: folder, url: directory))
        }

        return homes.map { home in
            DiscoveredAccount(id: "codex:\(home.key)",
                              provider: .codex,
                              profileName: home.name,
                              source: .codexHome(home.url))
        }
    }
}
