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
        checkClaudeAuth()
        checkNotifications()
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
          "extra_usage":      {"utilization": null, "used_credits": 10308,
                               "currency": "USD",   "decimal_places": 2},
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

        let stats = ClaudeProvider.stats(Data(payload.utf8))
        expect("extra_usage ушёл в статистику", stats.first?.key == "extraUsage")
        // Сумма минорная: 10308 при decimal_places=2 — это 103.08, а не 10308.
        expect("минорные единицы превращены в сумму",
               stats.first.map { $0.value.contains("103") && !$0.value.contains("10308") } == true,
               stats.first?.value ?? "нет строки")
        expect("нулевой extra_usage не показываем",
               ClaudeProvider.stats(Data(#"{"extra_usage":{"used_credits":0}}"#.utf8)).isEmpty)
        expect("без extra_usage статистики нет",
               ClaudeProvider.stats(Data("{}".utf8)).isEmpty)
        expect("отсутствие decimal_places не ломает",
               ClaudeProvider.stats(Data(#"{"extra_usage":{"used_credits":500}}"#.utf8))
                   .first?.value.contains("5") == true)
        expect("нулевой decimal_places оставляет целое",
               Format.money(minor: 42, places: 0, currency: "USD").contains("42"))
    }

    private static func checkCodexParser() {
        section("Codex: разбор ответа")
        let payload = """
        {
          "email": "user@example.com",
          "plan_type": "pro",
          "credits": {"unlimited": false, "balance": "42"},
          "rate_limit_reset_credits": {"available_count": 1, "applicable_available_count": 0},
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

        expect("подпись — план и почта",
               CodexProvider.subtitle(from: Data(payload.utf8), email: "user@example.com")
                   == "Pro · user@example.com")
        expect("без плана остаётся почта",
               CodexProvider.subtitle(from: Data("{}".utf8), email: "user@example.com")
                   == "user@example.com")
        expect("без обоих подписи нет",
               CodexProvider.subtitle(from: Data("{}".utf8), email: nil) == nil)

        let stats = CodexProvider.stats(from: Data(payload.utf8))
        expect("статистики ровно 2", stats.count == 2, "получено \(stats.count)")
        expect("баланс строкой разобран",
               stats.first { $0.key == "credits" }?.value == "42")
        expect("досрочные сбросы показаны",
               stats.first { $0.key == "resetCredits" }?.value == "1")
        expect("нулевой баланс не показываем",
               CodexProvider.stats(from: Data(#"{"credits":{"balance":"0"}}"#.utf8)).isEmpty)
        expect("безлимит показываем словом",
               CodexProvider.stats(from: Data(#"{"credits":{"unlimited":true}}"#.utf8))
                   .first?.value == L.t("stat.unlimited"))
        expect("мусор не ломает статистику",
               CodexProvider.stats(from: Data("[]".utf8)).isEmpty)
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

    private static func checkClaudeAuth() {
        section("Claude: запись Keychain и обновление токена")
        let now = Date(timeIntervalSince1970: 1_000_000)

        // Запись CLI. Сроки в ней — миллисекунды.
        let item: [String: Any] = [
            "claudeAiOauth": [
                "accessToken": "at",
                "refreshToken": "rt",
                "expiresAt": 1_000_000_000 as NSNumber,
                "refreshTokenExpiresAt": 4_000_000_000_000 as NSNumber,
                "subscriptionType": "max",
                "scopes": ["user:inference", "user:profile"]
            ]
        ]
        guard let parsed = ClaudeKeychain.parse(item) else {
            expect("запись разобрана", false)
            return
        }
        expect("запись разобрана", true)
        expect("миллисекунды переведены в дату",
               parsed.expiresAt == Date(timeIntervalSince1970: 1_000_000))
        expect("refresh-токен прочитан", parsed.refreshToken == "rt")
        expect("права прочитаны", parsed.scopes.count == 2)
        expect("план прочитан", parsed.plan == "max")
        expect("живой refresh-токен годен к обновлению", parsed.isRefreshable)

        expect("запись без refresh-токена не обновляема",
               ClaudeKeychain.parse(["claudeAiOauth": ["accessToken": "at"]])?.isRefreshable == false)
        expect("протухший refresh-токен не обновляем",
               ClaudeKeychain.parse(["claudeAiOauth": [
                   "accessToken": "at", "refreshToken": "rt",
                   "refreshTokenExpiresAt": 1000 as NSNumber]])?.isRefreshable == false)
        expect("чужой JSON не ломает", ClaudeKeychain.parse(["other": 1]) == nil)

        // Ответ на обновление: сроки относительные, в секундах.
        let response = """
        {"access_token":"new","refresh_token":"newrt","expires_in":3600,
         "refresh_token_expires_in":7200,"scope":"user:inference user:profile"}
        """
        guard let tokens = ClaudeOAuth.parse(Data(response.utf8), now: now) else {
            expect("ответ разобран", false)
            return
        }
        expect("ответ разобран", true)
        expect("срок доступа отсчитан от сейчас",
               tokens.expiresAt == now.addingTimeInterval(3_600))
        expect("ротация подхвачена", tokens.refreshToken == "newrt")
        expect("срок refresh-токена отсчитан",
               tokens.refreshTokenExpiresAt == now.addingTimeInterval(7_200))
        expect("права разобраны из строки", tokens.scopes == ["user:inference", "user:profile"])

        // Без ротации сервер не присылает refresh_token — прежний остаётся годен,
        // и затирать его нулём нельзя.
        let noRotation = ClaudeOAuth.parse(Data(#"{"access_token":"a","expires_in":60}"#.utf8), now: now)
        expect("без ротации refresh-токен не трогаем", noRotation?.refreshToken == nil)
        expect("без ротации срок refresh-токена не трогаем", noRotation?.refreshTokenExpiresAt == nil)

        expect("ответ без токена отвергнут",
               ClaudeOAuth.parse(Data(#"{"expires_in":60}"#.utf8), now: now) == nil)
        expect("ответ без срока отвергнут",
               ClaudeOAuth.parse(Data(#"{"access_token":"a"}"#.utf8), now: now) == nil)
        expect("мусор не ломает", ClaudeOAuth.parse(Data("не json".utf8), now: now) == nil)
    }

    private static func checkNotifications() {
        section("Уведомления о порогах и сбросе")
        let thresholds: [Double] = [80, 95]
        let floor: Double = 50
        func decide(_ stored: String, _ stamp: String, _ util: Double) -> ThresholdNotifier.Decision {
            ThresholdNotifier.decide(stored: stored, stamp: stamp, utilization: util,
                                     thresholds: thresholds, resetFloor: floor)
        }

        // Первое наблюдение окна: сброс не шлём, порог 80 срабатывает.
        let first = decide("", "100", 90)
        expect("первое окно без пуша о сбросе", first.postReset == false)
        expect("порог 80 сработал", first.fireThresholds == [80])
        expect("пик и метка записаны", first.encoded == "100@80@90")

        // То же окно, дошло до 96 — 80 уже был, шлём только 95.
        let again = decide("100@80@90", "100", 96)
        expect("порог 95 сработал", again.fireThresholds == [95])
        expect("80 повторно не шлём", !again.fireThresholds.contains(80))
        expect("пик подрос до 96", again.encoded == "100@80,95@96")

        // Метка сменилась после тяжёлого окна — шлём сброс, пороги перевзведены.
        let reset = decide("100@80,95@96", "200", 4)
        expect("сброс после тяжёлого окна", reset.postReset == true)
        expect("пороги перевзведены", reset.fireThresholds.isEmpty)
        expect("новая метка, пик обнулён", reset.encoded == "200@@4")

        // Метка сменилась, но окно почти не трогали — сброс не шлём.
        let quiet = decide("100@@30", "200", 2)
        expect("тихое окно без пуша о сбросе", quiet.postReset == false)

        // Старый формат состояния без поля пика читается и не ломает разбор.
        let legacy = decide("100@80,95", "200", 3)
        expect("старый формат: пик отсутствует → не шумим", legacy.postReset == false)
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
                                  stats: [UsageStat(key: "credits", label: "Credits", value: "42")],
                                  updatedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let cacheOK = (try? JSONEncoder().encode(cached))
            .flatMap { try? JSONDecoder().decode(CachedColumn.self, from: $0) }
        expect("кэш колонки", cacheOK?.windows.first?.utilization == 42)
        expect("статистика пережила кэш", cacheOK?.stats?.first?.value == "42")

        // Запись, сохранённая до появления stats, обязана читаться: иначе
        // обновление приложения молча теряет весь кэш процентов.
        let legacy = """
        {"id":"claude:main","provider":"claude","profileName":"main",
         "windows":[{"key":"five_hour","title":"x","utilization":42}],
         "updatedAt":721000000}
        """
        let legacyOK = try? JSONDecoder().decode(CachedColumn.self, from: Data(legacy.utf8))
        expect("старый кэш без stats читается", legacyOK?.windows.first?.utilization == 42)
        expect("у старого кэша статистика пустая", legacyOK?.stats == nil)

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
