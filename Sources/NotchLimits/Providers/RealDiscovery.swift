import Foundation

/// Поиск живых аккаунтов: записи Claude Code в Keychain + папки CODEX_HOME.
/// Вызывается на каждом цикле обновления, поэтому новый профиль появляется
/// в панели сам, без перезапуска.
///
/// Аккаунты дедуплицируются по почте: базовый аккаунт (то, что использует голая
/// команда) и профиль с тем же аккаунтом — это одна колонка. Так после
/// переключения базовый не задваивает профиль. Активный — тот, чья почта
/// совпадает с базовой; почту читаем из конфигов, Keychain не трогаем.
struct RealDiscovery: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts()
    }

    private func claudeAccounts() -> [DiscoveredAccount] {
        let baseConfig = ProfileDirectories.home.appendingPathComponent(".claude.json")
        let baseEmail = configEmail(baseConfig)
        var seen = Set<String>()
        var result: [DiscoveredAccount] = []
        // services() отдаёт базовую запись первой — она и остаётся при дедупе.
        for service in ClaudeKeychain.services() {
            let configDir = ClaudeKeychain.configDirectory(for: service)
            let email: String? = (service == ClaudeKeychain.baseService)
                ? baseEmail
                : configEmail((configDir ?? ProfileDirectories.home).appendingPathComponent(".claude.json"))
            if let email, !seen.insert(email).inserted { continue }   // тот же аккаунт — пропускаем
            result.append(DiscoveredAccount(
                id: "claude:\(service)",
                provider: .claude,
                profileName: ClaudeKeychain.profileName(for: service),
                source: .claudeKeychain(service: service, configDir: configDir),
                email: email,
                isActive: email != nil && email == baseEmail))
        }
        return result
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

        // Базовый (~/.codex) идёт первым — он и остаётся при дедупе.
        let baseEmail = CodexProvider.readAuth(codexHome: defaultHome)?.email
        var seen = Set<String>()
        var result: [DiscoveredAccount] = []
        for home in homes {
            let email = CodexProvider.readAuth(codexHome: home.url)?.email
            if let email, !seen.insert(email).inserted { continue }
            result.append(DiscoveredAccount(id: "codex:\(home.key)",
                                            provider: .codex,
                                            profileName: home.name,
                                            source: .codexHome(home.url),
                                            email: email,
                                            isActive: email != nil && email == baseEmail))
        }
        return result
    }

    /// Почта из `.claude.json` — обычный файл, без Keychain и подпроцессов.
    private func configEmail(_ url: URL) -> String? {
        (try? Data(contentsOf: url)).flatMap { ClaudeProvider.parseEmail(fromConfig: $0) }
    }
}
