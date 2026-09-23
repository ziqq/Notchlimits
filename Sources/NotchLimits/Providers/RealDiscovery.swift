import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
struct RealDiscovery: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts()
    }

    private func claudeAccounts() -> [DiscoveredAccount] {
        ClaudeKeychain.items()
            // Записи без входа (их пишет голый `claude`) — не аккаунты.
            .filter { !ClaudeKeychain.isKnownNoLogin(service: $0.service, modified: $0.modified) }
            .map(\.service)
            .map { service in
                let name = ClaudeKeychain.profileName(for: service)
                return DiscoveredAccount(
                    id: "claude:\(service)",
                    provider: .claude,
                    profileName: name,
                    source: .claudeKeychain(service: service,
                                            configDir: ClaudeKeychain.configDirectory(for: service)),
                    // Активен аккаунт, открытый в приложении Claude. Пока через нас
                    // не переключались — тот, что берёт голая `claude` (базовая
                    // запись Keychain без суффикса-хэша).
                    isActive: ClaudeAppSwitcher().isOpenInApp(columnID: "claude:\(service)")
                        ?? (service == ClaudeKeychain.baseService)
                )
            }
    }

    private func codexAccounts() -> [DiscoveredAccount] {
        // key — стабильный идентификатор колонки, name — подпись в заголовке.
        // Переименование основного профиля не должно ронять кэш и уведомления.
        var homes: [(key: String, name: String, url: URL)] = []

        let defaultHome = CodexAuthSwap.baseHome
        let defaultLive = CodexAuthSwap.liveHome(columnID: CodexAuthSwap.defaultColumnID, home: defaultHome)
        if FileManager.default.fileExists(atPath: defaultLive.appendingPathComponent("auth.json").path) {
            homes.append((key: "default", name: ProfileDirectories.primaryName, url: defaultHome))
        }

        for directory in ProfileDirectories.codexProfiles() {
            let folder = directory.lastPathComponent
            let live = CodexAuthSwap.liveHome(columnID: "codex:\(folder)", home: directory)
            guard FileManager.default.fileExists(
                atPath: live.appendingPathComponent("auth.json").path
            ) else { continue }
            homes.append((key: folder, name: folder, url: directory))
        }

        return homes.map { home in
            DiscoveredAccount(id: "codex:\(home.key)",
                              provider: .codex,
                              profileName: home.name,
                              source: .codexHome(home.url),
                              // Активен тот, чей вход сейчас в ~/.codex: под ним
                              // и приложение Codex, и голая `codex`.
                              isActive: "codex:\(home.key)" == CodexAuthSwap.activeColumnID)
        }
    }
}
