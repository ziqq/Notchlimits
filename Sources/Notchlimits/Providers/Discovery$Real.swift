import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
struct Discovery$Real: AccountDiscovery {

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
                        ?? (service == AuthStorage$Claude.baseService),
                    claudePrimaryOwner: service == AuthStorage$Claude.baseService
                        ? AuthStorage$Claude.primaryOwner() : nil
                )
            }
    }

    private func codexAccounts() -> [DiscoveredAccount] {
        // id — стабильный идентификатор колонки, name — подпись в заголовке.
        // Переименование основного профиля не должно ронять кэш и уведомления.
        var homes: [(id: String, name: String, url: URL, login: AuthStorage$Codex.LoginSelection)] = []

        let defaultHome = AuthSwap$Codex.baseHome
        if let login = AuthSwap$Codex.discoveredLogin(columnID: AuthSwap$Codex.defaultColumnID, home: defaultHome) {
            homes.append((id: AuthSwap$Codex.defaultColumnID,
                          name: ProfileDirectories.primaryName, url: defaultHome, login: login))
        }

        let managedDirectories = ProfileDirectories.codexProfiles()
        let recovered = AuthSwap$Codex.recoveredBackupDiscovery(managedDirectories: managedDirectories)
        let managed = managedDirectories.filter {
            !recovered.reservedPaths.contains(AuthStorage$Codex.canonicalPath($0))
        }.map { directory in
            (id: AuthSwap$Codex.profileColumnID(directory.lastPathComponent), home: directory)
        }
        for (id, directory) in recovered.profiles + managed {
            // A native base home inside the managed root is still the primary
            // account, with projects and threads that profile removal must preserve.
            guard !AuthSwap$Codex.isBaseHome(directory),
                  !AuthSwap$Codex.isPrimaryBackup(directory) else { continue }
            let folder = directory.lastPathComponent
            guard let login = AuthSwap$Codex.discoveredLogin(columnID: id, home: directory) else { continue }
            homes.append((id: id, name: folder, url: directory, login: login))
        }

        return homes.map { home in
            DiscoveredAccount(id: home.id,
                              provider: .codex,
                              profileName: home.name,
                              source: .codexHome(home.url),
                              // Активен тот, чей вход сейчас в ~/.codex: под ним
                              // и приложение Codex, и голая `codex`.
                              isActive: home.id == AuthSwap$Codex.activeColumnID,
                              codexLogin: home.login)
        }
    }
}
