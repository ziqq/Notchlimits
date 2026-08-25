import Foundation

/// Поиск доступных аккаунтов. Вызывается на каждом цикле обновления,
/// чтобы новые профили подхватывались без перезапуска.
protocol AccountDiscovery {
    func discover() -> [DiscoveredAccount]
}
