import Foundation

/// Последние успешные проценты и даты сброса в UserDefaults.
/// Токены сюда не попадают ни при каких условиях.
struct UsageCache {
    private let defaults = UserDefaults.standard
    private let prefix = "cache."

    func save(_ column: AccountColumn) {
        guard let updatedAt = column.updatedAt else { return }
        let payload = CachedColumn(id: column.id,
                                   provider: column.provider,
                                   profileName: column.profileName,
                                   subtitle: column.subtitle,
                                   windows: column.windows,
                                   updatedAt: updatedAt)
        guard let data = try? JSONEncoder().encode(payload) else { return }
        defaults.set(data, forKey: prefix + column.id)
    }

    func load(id: String) -> CachedColumn? {
        guard let data = defaults.data(forKey: prefix + id) else { return nil }
        return try? JSONDecoder().decode(CachedColumn.self, from: data)
    }
}
