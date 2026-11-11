import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
struct RealDiscovery: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts() + kimiAccounts() + grokAccounts()
    }

    private func kimiAccounts() -> [DiscoveredAccount] {
        let home = ProfileDirectories.home
        let primary = environmentPath("KIMI_CODE_HOME") ?? home.appendingPathComponent(".kimi-code")
        let profiles = profileDirectories(home.appendingPathComponent(".kimi-code-profiles"))
        return cliAccounts(provider: .kimi, primary: primary, profiles: profiles,
                           source: AccountSource.kimiHome) { directory in
            let credentials = directory.appendingPathComponent("credentials")
            let entries = try? FileManager.default.contentsOfDirectory(atPath: credentials.path)
            return entries?.contains { $0 == "kimi-code.json" || ($0.hasPrefix("kimi-code-") && $0.hasSuffix(".json")) } ?? false
        }
    }

    private func grokAccounts() -> [DiscoveredAccount] {
        let home = ProfileDirectories.home
        let grokHome = environmentPath("GROK_HOME") ?? home.appendingPathComponent(".grok")
        let primary = environmentPath("GROK_AUTH_PATH") ?? grokHome.appendingPathComponent("auth.json")
        let profiles = profileDirectories(home.appendingPathComponent(".grok-profiles"))
            .map { ($0.name, $0.url.appendingPathComponent("auth.json")) }
        return cliAccounts(provider: .grok, primary: primary, profiles: profiles,
                           source: AccountSource.grokAuth) { auth in
            (try? auth.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
        }
    }

    private func cliAccounts(provider: Provider, primary: URL, profiles: [(name: String, url: URL)],
                             source: (URL) -> AccountSource, exists: (URL) -> Bool) -> [DiscoveredAccount] {
        var seen: Set<URL> = []
        return ([(ProfileDirectories.primaryName, primary)] + profiles).compactMap { name, url in
            let path = url.standardizedFileURL
            guard exists(path), seen.insert(path.resolvingSymlinksInPath()).inserted else { return nil }
            return DiscoveredAccount(id: "\(provider.rawValue):\(path.path)", provider: provider,
                                     profileName: name, source: source(path))
        }
    }

    private func environmentPath(_ key: String) -> URL? {
        guard let path = ProcessInfo.processInfo.environment[key], path.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: path)
    }

    private func profileDirectories(_ root: URL) -> [(name: String, url: URL)] {
        let entries = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey],
                                                                    options: .skipsHiddenFiles)
        return (entries ?? [])
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { ($0.lastPathComponent, $0) }
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
        // id — стабильный идентификатор колонки, name — подпись в заголовке.
        // Переименование основного профиля не должно ронять кэш и уведомления.
        var homes: [(id: String, name: String, url: URL)] = []

        let defaultHome = CodexAuthSwap.baseHome
        let defaultLive = CodexAuthSwap.liveHome(columnID: CodexAuthSwap.defaultColumnID, home: defaultHome)
        if FileManager.default.fileExists(atPath: defaultLive.appendingPathComponent("auth.json").path) {
            homes.append((id: CodexAuthSwap.defaultColumnID,
                          name: ProfileDirectories.primaryName, url: defaultHome))
        }

        for directory in ProfileDirectories.codexProfiles() {
            let folder = directory.lastPathComponent
            let id = CodexAuthSwap.profileColumnID(folder)
            let live = CodexAuthSwap.liveHome(columnID: id, home: directory)
            guard FileManager.default.fileExists(
                atPath: live.appendingPathComponent("auth.json").path
            ) else { continue }
            homes.append((id: id, name: folder, url: directory))
        }

        return homes.map { home in
            DiscoveredAccount(id: home.id,
                              provider: .codex,
                              profileName: home.name,
                              source: .codexHome(home.url),
                              // Активен тот, чей вход сейчас в ~/.codex: под ним
                              // и приложение Codex, и голая `codex`.
                              isActive: home.id == CodexAuthSwap.activeColumnID)
        }
    }
}
