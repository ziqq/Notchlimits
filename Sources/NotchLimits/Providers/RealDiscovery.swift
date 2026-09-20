import Foundation

/// Поиск живых аккаунтов для колонок панели. Источник истины — `AccountSwitcher`:
/// он уже отдаёт ВСЕ аккаунты (активный/базовый + профили + библиотека снимков),
/// дедуплицированные по почте, с флагом активного. Так ни один аккаунт не
/// пропадает после переключения (вытесненный из базы уходит в библиотеку, а её
/// мы тоже показываем), и активный подсвечивается корректно.
///
/// Почту и активность берём из конфигов/UserDefaults, Keychain при построении
/// списка не читаем — открытие меню/панели не вызывает запрос пароля.
struct RealDiscovery: AccountDiscovery {

    func discover() -> [DiscoveredAccount] {
        claudeAccounts() + codexAccounts()
    }

    private func claudeAccounts() -> [DiscoveredAccount] {
        AccountSwitcher.claudeAccounts().map { account in
            let service = account.ref
            return DiscoveredAccount(
                // id по аккаунту (почте), а не по слоту: имя-колонки, кэш и
                // расписание следуют за аккаунтом, даже когда он переезжает
                // между базой и библиотекой при переключении.
                id: "claude:\(account.email ?? service)",
                provider: .claude,
                profileName: claudeName(service: service, email: account.email),
                source: .claudeKeychain(service: service,
                                        configDir: ClaudeKeychain.configDirectory(for: service)),
                email: account.email,
                isActive: account.isActive)
        }
    }

    private func codexAccounts() -> [DiscoveredAccount] {
        AccountSwitcher.codexAccounts().map { account in
            let home = URL(fileURLWithPath: account.ref).deletingLastPathComponent()
            return DiscoveredAccount(
                id: "codex:\(account.email ?? codexKey(home: home))",
                provider: .codex,
                profileName: codexName(home: home, email: account.email),
                source: .codexHome(home),
                email: account.email,
                isActive: account.isActive)
        }
    }

    // MARK: - Имена колонок

    private func claudeName(service: String, email: String?) -> String {
        if service == ClaudeKeychain.baseService { return ProfileDirectories.primaryName }
        if let dir = ClaudeKeychain.configDirectory(for: service) { return dir.lastPathComponent }
        return localPart(email)   // библиотека: папки нет — локальная часть почты
    }

    private var defaultCodexHome: URL {
        ProcessInfo.processInfo.environment["CODEX_HOME"].map { URL(fileURLWithPath: $0) }
            ?? ProfileDirectories.home.appendingPathComponent(".codex")
    }

    private func codexKey(home: URL) -> String {
        if home.standardizedFileURL == defaultCodexHome.standardizedFileURL { return "default" }
        return home.lastPathComponent
    }

    private func codexName(home: URL, email: String?) -> String {
        if home.standardizedFileURL == defaultCodexHome.standardizedFileURL {
            return ProfileDirectories.primaryName
        }
        if home.deletingLastPathComponent().standardizedFileURL
            == ProfileDirectories.codexRoot.standardizedFileURL {
            return home.lastPathComponent   // профиль под ~/.codex-profiles
        }
        return localPart(email)             // библиотека
    }

    private func localPart(_ email: String?) -> String {
        guard let email, let at = email.firstIndex(of: "@") else { return email ?? "saved" }
        return String(email[..<at])
    }
}
