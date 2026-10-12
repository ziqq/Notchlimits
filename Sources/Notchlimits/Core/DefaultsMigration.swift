import Foundation

/// Перенос настроек со старого идентификатора бандла `com.ziqq.notchlimits`.
///
/// UserDefaults живут в домене по идентификатору: без переноса после смены ID
/// пропали бы имена и скрытие колонок, горячая клавиша, кэш процентов
/// и история расхода. Переносим один раз и только недостающие ключи — то, что
/// уже записано под новым ID, важнее. Старый домен не трогаем: если вернуться
/// на прежнюю сборку, её настройки останутся на месте.
enum DefaultsMigration {
    static let legacyDomain = "com.ziqq.notchlimits"
    static let doneKey = "migration.legacyDomainImported"

    static func runIfNeeded(defaults: UserDefaults = .standard) {
        guard !defaults.bool(forKey: doneKey) else { return }
        defer { defaults.set(true, forKey: doneKey) }

        guard let current = Bundle.main.bundleIdentifier, current != legacyDomain,
              let legacy = defaults.persistentDomain(forName: legacyDomain)
        else { return }

        let existing = defaults.persistentDomain(forName: current) ?? [:]
        for (key, value) in missingValues(legacy: legacy, existing: existing) {
            defaults.set(value, forKey: key)
        }
    }

    /// Значения старого домена, которых ещё нет в новом.
    static func missingValues(legacy: [String: Any], existing: [String: Any]) -> [String: Any] {
        legacy.filter { existing[$0.key] == nil }
    }
}
