import Foundation

/// Самопроверка для CI: `NOTCHLIMITS_SELFTEST=1 NotchLimits`.
///
/// Ничего не требует от окружения — ни сети, ни Keychain, ни оконного сервера,
/// поэтому спокойно живёт на раннере. Возвращает ненулевой код при первой же
/// несостыковке.
enum SelfTest {

    private static var failures: [String] = []

    static func runIfRequested() -> Bool {
        guard ProcessInfo.processInfo.environment["NOTCHLIMITS_SELFTEST"] == "1" else {
            return false
        }
        failures = []

        checkClaudeParser()
        checkCodexParser()
        checkWindowTitles()
        checkJWT()
        checkFormatting()
        checkCodableRoundTrips()
        checkLocalizations()

        if failures.isEmpty {
            print("\nсамопроверка пройдена")
            exit(0)
        }
        print("\nпровалов: \(failures.count)")
        for failure in failures { print("  ✗ \(failure)") }
        exit(1)
    }

    private static func expect(_ name: String, _ condition: Bool, _ detail: @autoclosure () -> String = "") {
        if condition {
            print("  ✓ \(name)")
        } else {
            let suffix = detail()
            failures.append(suffix.isEmpty ? name : "\(name): \(suffix)")
            print("  ✗ \(name)\(suffix.isEmpty ? "" : " — " + suffix)")
        }
    }

    private static func section(_ title: String) {
        print("\n\(title)")
    }

    // MARK: - Провайдеры

    private static func checkClaudeParser() {
        section("Claude: разбор ответа")
        let payload = """
        {
          "five_hour":        {"utilization": 12.5, "resets_at": "2026-08-25T18:00:00Z"},
          "seven_day":        {"utilization": 63,   "resets_at": "2026-08-30T09:00:00+00:00"},
          "seven_day_opus":   {"utilization": 91,   "resets_at": "2026-08-30T09:00:00.500Z"},
          "brand_new_window": {"utilization": 4,    "resets_at": "2026-08-26T00:00:00Z"},
          "extra_usage":      {"utilization": 999,  "resets_at": "2026-08-26T00:00:00Z"},
          "plan": "max",
          "nested": {"no_utilization": 1}
        }
        """
        guard let windows = ClaudeProvider.parse(Data(payload.utf8)) else {
            expect("ответ разобран", false)
            return
        }
        expect("окон ровно 4", windows.count == 4, "получено \(windows.count)")
        expect("extra_usage отброшен", !windows.contains { $0.key == "extra_usage" })
        expect("поля без utilization отброшены", !windows.contains { $0.key == "nested" })
        expect("five_hour первым", windows.first?.key == "five_hour")
        expect("seven_day вторым", windows.dropFirst().first?.key == "seven_day")
        expect("дробный процент сохранён", windows.first?.utilization == 12.5)
        expect("resets_at разобран", windows.allSatisfy { $0.resetsAt != nil })
        expect("дробные секунды разобраны",
               windows.first { $0.key == "seven_day_opus" }?.resetsAt != nil)
        expect("неизвестный ключ показан словами",
               windows.first { $0.key == "brand_new_window" }?.title == "Brand New Window")
        expect("кодовое имя модели читаемо", ClaudeProvider.humanized("nimbus_quill") == "Nimbus Quill")
        expect("известный префикс развёрнут",
               windows.first { $0.key == "seven_day_opus" }?.title == L.t("window.week") + " · Opus")
        expect("порядок: пять часов, неделя, производные",
               windows.map(\.key) == ["five_hour", "seven_day", "seven_day_opus", "brand_new_window"],
               windows.map(\.key).joined(separator: ","))
        expect("пустой ответ не ломает", ClaudeProvider.parse(Data("{}".utf8))?.isEmpty == true)
        expect("мусор не ломает", ClaudeProvider.parse(Data("не json".utf8)) == nil)
    }

    private static func checkCodexParser() {
        section("Codex: разбор ответа")
        let payload = """
        {
          "email": "user@example.com",
          "rate_limit": {
            "primary_window":   {"used_percent": 21, "limit_window_seconds": 604800, "reset_at": 1788149680},
            "secondary_window": null
          },
          "additional_rate_limits": [
            {
              "limit_name": "GPT-5.3-Codex-Spark",
              "metered_feature": "codex_bengalfox",
              "rate_limit": {
                "primary_window":   {"used_percent": 0, "limit_window_seconds": 18000, "reset_at": 1787658128},
                "secondary_window": {"used_percent": 7, "limit_window_seconds": 604800, "reset_after_seconds": 600}
              }
            }
          ]
        }
        """
        guard let windows = CodexProvider.parse(Data(payload.utf8)) else {
            expect("ответ разобран", false)
            return
        }
        expect("окон ровно 3", windows.count == 3, "получено \(windows.count)")
        expect("secondary_window = null пропущен", !windows.contains { $0.key == "main.secondary_window" })
        expect("основное окно первым", windows.first?.key == "main.primary_window")
        expect("имя лимита ушло в префикс",
               windows.contains { $0.title.hasPrefix("GPT-5.3-Codex-Spark · ") })
        expect("reset_at превращён в дату",
               windows.first?.resetsAt == Date(timeIntervalSince1970: 1_788_149_680))
        expect("reset_after_seconds тоже даёт дату",
               windows.last?.resetsAt != nil)
        expect("e-mail вынут", CodexProvider.email(from: Data(payload.utf8)) == "user@example.com")
        expect("мусор не ломает", CodexProvider.parse(Data("[]".utf8)) == nil)
    }

    private static func checkWindowTitles() {
        section("Названия окон по длительности")
        expect("18000 с → 5-часовое", CodexProvider.title(forWindowSeconds: 18_000) == L.t("window.fiveHour"))
        expect("604800 с → недельное", CodexProvider.title(forWindowSeconds: 604_800) == L.t("window.week"))
        expect("259200 с → 3-дневное", CodexProvider.title(forWindowSeconds: 259_200) == L.t("window.days", 3))
        expect("10800 с → 3-часовое", CodexProvider.title(forWindowSeconds: 10_800) == L.t("window.hours", 3))
        expect("nil → общее название", CodexProvider.title(forWindowSeconds: nil) == L.t("window.generic"))
    }

    private static func checkJWT() {
        section("JWT")
        // Подпись не проверяется — нужны только claims. Токен синтетический.
        let claims = #"{"exp":2000000000,"email":"user@example.com"}"#
        var encoded = Data(claims.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        while encoded.hasSuffix("=") { encoded.removeLast() }
        let token = "header." + encoded + ".signature"

        expect("exp прочитан", JWT.expiry(token) == Date(timeIntervalSince1970: 2_000_000_000))
        expect("email прочитан", JWT.email(token) == "user@example.com")
        expect("мусор не ломает", JWT.claims("не.токен") == nil)
        expect("пустая строка не ломает", JWT.expiry("") == nil)
    }

    private static func checkFormatting() {
        section("Форматирование времени")
        let now = Date(timeIntervalSince1970: 1_000_000)
        let inTwoDays = now.addingTimeInterval(2 * 86_400 + 5 * 3_600)
        let inThreeHours = now.addingTimeInterval(3 * 3_600 + 12 * 60)

        expect("дни и часы", Format.reset(inTwoDays, now: now).contains("2"))
        expect("часы и минуты", Format.reset(inThreeHours, now: now).contains("12"))
        expect("прошедшая дата не пустая", !Format.reset(now.addingTimeInterval(-10), now: now).isEmpty)
        expect("возраст в секундах", Format.age(now.addingTimeInterval(-12), now: now).contains("12"))
        expect("свежие данные — «только что»",
               Format.age(now.addingTimeInterval(-1), now: now) == L.t("age.justNow"))
        expect("возраст в минутах", Format.age(now.addingTimeInterval(-180), now: now).contains("3"))
        expect("проценты округляются", Format.percent(56.4).contains("56"))
        expect("цвет по загрузке", Theme.color(for: 10) != Theme.color(for: 95))
    }

    private static func checkCodableRoundTrips() {
        section("Сохранение настроек")
        let window = LimitWindow(key: "five_hour", title: "x", utilization: 42,
                                 resetsAt: Date(timeIntervalSince1970: 1_700_000_000))
        let cached = CachedColumn(id: "claude:main", provider: .claude, profileName: "main",
                                  subtitle: nil, windows: [window],
                                  updatedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let cacheOK = (try? JSONEncoder().encode(cached))
            .flatMap { try? JSONDecoder().decode(CachedColumn.self, from: $0) }
        expect("кэш колонки", cacheOK?.windows.first?.utilization == 42)

        let config = HotKeyConfig(keyCode: 35, modifiers: 256, display: "⌘P")
        let configOK = (try? JSONEncoder().encode(config))
            .flatMap { try? JSONDecoder().decode(HotKeyConfig.self, from: $0) }
        expect("настройка хоткея", configOK == config)

        var column = AccountColumn(id: "codex:default", provider: .codex, profileName: "main")
        expect("заголовок по имени профиля", column.header == "CODEX · main")
        column.customName = "work"
        expect("заголовок по своему имени", column.header == "CODEX · work")
    }

    // MARK: - Локализации

    private static func checkLocalizations() {
        section("Локализации")
        let languages = Set(Bundle.main.localizations).subtracting(["Base"]).sorted()
        expect("языки в бандле есть", !languages.isEmpty)

        func table(_ language: String) -> [String: String]? {
            guard let url = Bundle.main.url(forResource: "Localizable", withExtension: "strings",
                                            subdirectory: nil, localization: language),
                  let dictionary = NSDictionary(contentsOf: url) as? [String: String]
            else { return nil }
            return dictionary
        }

        guard let base = table("en") else {
            expect("английский найден", false)
            return
        }
        expect("английский найден", true)
        let baseKeys = Set(base.keys)
        expect("ключей достаточно", baseKeys.count > 60, "\(baseKeys.count)")

        for language in languages {
            guard let strings = table(language) else {
                expect("\(language): файл на месте", false)
                continue
            }
            let keys = Set(strings.keys)
            let missing = baseKeys.subtracting(keys).sorted()
            let extra = keys.subtracting(baseKeys).sorted()
            let empty = strings.filter { $0.value.trimmingCharacters(in: .whitespaces).isEmpty }.keys.sorted()

            expect("\(language): \(keys.count) ключей, без пропусков",
                   missing.isEmpty && extra.isEmpty && empty.isEmpty,
                   [missing.isEmpty ? "" : "нет " + missing.joined(separator: ","),
                    extra.isEmpty ? "" : "лишние " + extra.joined(separator: ","),
                    empty.isEmpty ? "" : "пустые " + empty.joined(separator: ",")]
                       .filter { !$0.isEmpty }.joined(separator: "; "))

            // Спецификаторы формата обязаны совпадать с английским,
            // иначе String(format:) уронит приложение на чужом языке.
            for key in baseKeys.intersection(keys) where specifiers(base[key]!) != specifiers(strings[key]!) {
                expect("\(language): спецификаторы в \(key)", false,
                       "\(specifiers(base[key]!)) против \(specifiers(strings[key]!))")
            }
        }
    }

    /// Набор спецификаторов формата в строке, без учёта порядка и литеральных «%%».
    private static func specifiers(_ format: String) -> [String] {
        var result: [String] = []
        let iterator = Array(format)
        var index = 0
        while index < iterator.count {
            guard iterator[index] == "%" else { index += 1; continue }
            var token = "%"
            var cursor = index + 1
            while cursor < iterator.count, "0123456789$".contains(iterator[cursor]) {
                token.append(iterator[cursor])
                cursor += 1
            }
            if cursor < iterator.count {
                token.append(iterator[cursor])
                cursor += 1
            }
            if !token.hasSuffix("%") {
                // Позиционный префикс не важен: важен сам тип аргумента.
                result.append("%" + String(token.suffix(1)))
            }
            index = cursor
        }
        return result.sorted()
    }
}
