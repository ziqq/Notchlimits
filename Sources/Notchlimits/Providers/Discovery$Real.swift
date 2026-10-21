import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
struct Discovery$Real: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts()
    }

    private func claudeAccounts() -> [DiscoveredAccount] {
        AuthStorage$Claude.items()
            // Записи без входа (их пишет голый `claude`) — не аккаунты.
            .filter { !AuthStorage$Claude.isKnownNoLogin(service: $0.service, modified: $0.modified) }
            .map(\.service)
            .map { service in
                let name = AuthStorage$Claude.profileName(for: service)
                return DiscoveredAccount(
                    id: "claude:\(service)",
                    provider: .claude,
                    profileName: name,
                    source: .claudeKeychain(service: service,
                                            configDir: AuthStorage$Claude.configDirectory(for: service)),
                    // Активен аккаунт, открытый в приложении Claude. Пока через нас
                    // не переключались — тот, что берёт голая `claude` (базовая
                    // запись Keychain без суффикса-хэша).
                    isActive: AppSwitcher$Claude().isOpenInApp(columnID: "claude:\(service)")
                        ?? (service == AuthStorage$Claude.baseService)
                )
            }
    }

    private func codexAccounts() -> [DiscoveredAccount] {
        // id — стабильный идентификатор колонки, name — подпись в заголовке.
        // Переименование основного профиля не должно ронять кэш и уведомления.
        var homes: [(id: String, name: String, url: URL)] = []

        let defaultHome = AuthSwap$Codex.baseHome
        let defaultLive = AuthSwap$Codex.liveHome(columnID: AuthSwap$Codex.defaultColumnID, home: defaultHome)
        if AuthSwap$Codex.hasAuth(home: defaultLive) {
            homes.append((id: AuthSwap$Codex.defaultColumnID,
                          name: ProfileDirectories.primaryName, url: defaultHome))
        }

        for directory in ProfileDirectories.codexProfiles() {
            // A native base home inside the managed root is still the primary
            // account, with projects and threads that profile removal must preserve.
            guard !AuthSwap$Codex.isBaseHome(directory) else { continue }
            let folder = directory.lastPathComponent
            let id = AuthSwap$Codex.profileColumnID(folder)
            let live = AuthSwap$Codex.liveHome(columnID: id, home: directory)
            guard AuthSwap$Codex.hasAuth(home: live) else { continue }
            homes.append((id: id, name: folder, url: directory))
        }

        return homes.map { home in
            DiscoveredAccount(id: home.id,
                              provider: .codex,
                              profileName: home.name,
                              source: .codexHome(home.url),
                              // Активен тот, чей вход сейчас в ~/.codex: под ним
                              // и приложение Codex, и голая `codex`.
                              isActive: home.id == AuthSwap$Codex.activeColumnID)
        }
    }
}
