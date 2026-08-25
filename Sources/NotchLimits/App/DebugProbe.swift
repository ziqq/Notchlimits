import AppKit
import Foundation

/// Проверка провайдеров без GUI: `NOTCHLIMITS_PROBE=1 ./NotchLimits`.
/// Печатает то же, что увидит панель. Токены не печатаются никогда.
enum DebugProbe {

    /// Диалог добавления аккаунта: собран ли он и что в нём лежит.
    /// Снять с него картинку из процесса нельзя — NSAlert рисует window server,
    /// поэтому проверяем состав и геометрию.
    @MainActor
    private static func checkAddAccountDialog() {
        let alert = AccountSetup.alertForRendering()
        alert.layout()
        print("диалог: «\(alert.messageText)»")
        for line in alert.informativeText.split(separator: "\n", omittingEmptySubsequences: true) {
            print("  пояснение: \(line)")
        }
        for button in alert.buttons {
            print("  кнопка: «\(button.title)» активна=\(button.isEnabled)")
        }
        guard let accessory = alert.accessoryView else {
            print("  ПОЛЕ ВВОДА ОТСУТСТВУЕТ")
            return
        }
        print("  поле ввода \(Int(accessory.frame.width))×\(Int(accessory.frame.height)):")
        for subview in accessory.subviews {
            guard let field = subview as? NSTextField else { continue }
            let text = field.stringValue.isEmpty
                ? "подсказка «\(field.placeholderString ?? "")»"
                : "«\(field.stringValue)»"
            print("    y=\(Int(field.frame.minY)) h=\(Int(field.frame.height)) \(text)")
        }
    }

    /// Где нашлись CLI и какой User-Agent из них получился.
    private static func checkBinaries() {
        if let claude = BinaryLocator.claude() {
            print("claude: \(claude.path) → UA claude-code/\(BinaryLocator.version(of: claude, fallback: "?"))")
        } else {
            print("claude: НЕ НАЙДЕН")
        }
        if let codex = BinaryLocator.codex() {
            print("codex:  \(codex.path) → UA codex_cli_rs/\(BinaryLocator.version(of: codex, fallback: "?"))")
        } else {
            print("codex:  НЕ НАЙДЕН")
        }
        let services = ClaudeKeychain.services()
        print("записи Keychain «Claude Code-credentials»: \(services.isEmpty ? "нет" : services.joined(separator: ", "))")
    }

    /// Хоткеи регистрируются Carbon'ом и могут быть заняты другим приложением.
    @MainActor
    private static func checkHotKeys() {
        let cmdP = HotKey(keyCode: 35, modifiers: 256) {}          // kVK_ANSI_P + cmdKey
        print("хоткей ⌘P: \(cmdP == nil ? "ЗАНЯТ" : "зарегистрирован")")
        let escape = HotKey(keyCode: 53, modifiers: 0) {}
        print("хоткей Esc: \(escape == nil ? "ЗАНЯТ" : "зарегистрирован")")
        _ = cmdP
        _ = escape
        // Локальные регистрации снимаются здесь: иначе менеджер ниже
        // увидит наши же ⌘P и Esc как занятые.
    }

    /// Смена сочетания: регистрация, сохранение и восстановление настройки.
    @MainActor
    static func checkHotKeyManager() {
        let defaults = UserDefaults.standard
        let backup = defaults.data(forKey: "hotKey")
        defaults.removeObject(forKey: "hotKey")

        let manager = HotKeyManager {}
        print("по умолчанию: \(manager.displayName), стандартная=\(manager.isStandard)")

        // ⌃⌥F9 — заведомо свободное сочетание.
        let custom = HotKeyConfig(keyCode: 101, modifiers: 2048 | 4096, display: "⌃⌥F9")
        print("смена на ⌃⌥F9: \(manager.apply(custom) ? "ок" : "ЗАНЯТО")")
        print("после смены: \(manager.displayName), сохранено=\(defaults.data(forKey: "hotKey") != nil)")

        let reloaded = HotKeyManager {}
        print("после перезапуска: \(reloaded.displayName)")

        print("выключение: \(reloaded.apply(nil) ? "ок" : "сбой"), теперь: \(reloaded.displayName)")
        print("возврат к ⌘P: \(reloaded.apply(.standard) ? "ок" : "ЗАНЯТО"), теперь: \(reloaded.displayName)")

        if let backup { defaults.set(backup, forKey: "hotKey") } else { defaults.removeObject(forKey: "hotKey") }
    }

    /// Набор окон Claude не фиксирован — проверяем, что парсер обобщённый.
    private static func checkClaudeParser() {
        let payload = """
        {
          "five_hour":       {"utilization": 12.5, "resets_at": "2026-08-25T18:00:00Z"},
          "seven_day":       {"utilization": 63,   "resets_at": "2026-08-30T09:00:00+00:00"},
          "seven_day_opus":  {"utilization": 91,   "resets_at": "2026-08-30T09:00:00Z"},
          "brand_new_window":{"utilization": 4,    "resets_at": "2026-08-26T00:00:00Z"},
          "extra_usage":     {"utilization": 999,  "resets_at": "2026-08-26T00:00:00Z"},
          "plan": "max",
          "nested": {"no_utilization": 1}
        }
        """
        guard let windows = ClaudeProvider.parse(Data(payload.utf8)) else {
            print("парсер Claude: НЕ РАЗОБРАЛ")
            return
        }
        print("парсер Claude: \(windows.count) окон")
        for window in windows {
            print("  - \(window.key) → «\(window.title)» \(Int(window.utilization))% "
                  + "reset=\(window.resetsAt.map { ISO8601DateFormatter().string(from: $0) } ?? "—")")
        }
    }

    @MainActor
    static func runIfRequested() -> Bool {
        guard ProcessInfo.processInfo.environment["NOTCHLIMITS_PROBE"] == "1" else { return false }

        checkBinaries()
        checkAddAccountDialog()
        checkHotKeys()
        checkHotKeyManager()
        checkClaudeParser()

        let accounts = RealDiscovery().discover()
        print("найдено аккаунтов: \(accounts.count)")
        for account in accounts {
            print("  • \(account.id)  провайдер=\(account.provider.rawValue)  профиль=\(account.profileName)")
        }

        let providers: [Provider: UsageProvider] = [
            .claude: ClaudeProvider(),
            .codex: CodexProvider()
        ]

        let group = DispatchGroup()
        for account in accounts {
            guard let provider = providers[account.provider] else { continue }
            group.enter()
            Task {
                let outcome = await provider.fetch(account)
                print("\n[\(account.id)]")
                switch outcome {
                case .success(let snapshot):
                    print("  ok, подпись: \(snapshot.subtitle ?? "—")")
                    for window in snapshot.windows {
                        let reset = window.resetsAt.map { Format.reset($0) } ?? "без даты сброса"
                        print("  - \(window.title) [\(window.key)]: \(Int(window.utilization))% · \(reset)")
                    }
                case .rateLimited(let retryAfter):
                    print("  429, ждать \(retryAfter.map { String(Int($0)) + " c" } ?? "по бэкоффу")")
                case .reauth(let message):
                    print("  \(message)")
                case .failure(let message):
                    print("  ошибка: \(message)")
                }
                group.leave()
            }
        }

        DispatchQueue.global().async {
            group.wait()
            DispatchQueue.main.async { exit(0) }
        }
        // Ждём завершения задач в общем runloop.
        return true
    }
}
