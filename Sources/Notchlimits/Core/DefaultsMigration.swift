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

    /// Copy settings to escaped profile IDs once, preserving existing values.
    /// Keep the original entries: a legacy ID can still belong to `default`.
    static func migrateCodexProfileSettingsIfNeeded(defaults: UserDefaults = .standard) {
        let doneKey = "migration.codexProfileSettingsEscaped"
        guard !defaults.bool(forKey: doneKey) else { return }

        let oldHidden = Set(defaults.stringArray(forKey: "hiddenColumns") ?? [])
        let oldNames = defaults.dictionary(forKey: "columnNames") as? [String: String] ?? [:]
        var hidden = oldHidden
        var names = oldNames
        for directory in ProfileDirectories.codexProfiles() {
            let name = directory.lastPathComponent
            guard name.hasPrefix("profile:") else { continue }
            let legacyID = "codex:\(name)"
            let currentID = AuthSwap$Codex.profileColumnID(name)
            if oldHidden.contains(legacyID) { hidden.insert(currentID) }
            if names[currentID] == nil, let name = oldNames[legacyID] {
                names[currentID] = name
            }
        }

        defaults.set(Array(hidden), forKey: "hiddenColumns")
        defaults.set(names, forKey: "columnNames")
        defaults.set(true, forKey: doneKey)
    }
}
