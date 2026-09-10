import Foundation

/// Проверка обновлений по требованию: спрашиваем последний релиз на GitHub и
/// сравниваем с текущей версией из Info.plist. Только вручную (пункт меню) —
/// автоматических запросов к GitHub нет, чтобы не превращать это в фоновый
/// трафик мимо usage-эндпоинтов. Скачивание/замену не делаем: отдаём ссылку на
/// страницу релиза, ставит пользователь сам.
enum UpdateCheck {

    static let repo = "ziqq/Notchlimits"
    static let releasesPage = URL(string: "https://github.com/\(repo)/releases/latest")!
    private static let apiURL = URL(string: "https://api.github.com/repos/\(repo)/releases/latest")!

    struct Release: Equatable {
        let version: String
        let url: URL
    }

    enum Outcome: Equatable {
        case upToDate(current: String)
        case available(Release)
        case failed(String)
    }

    static func current() -> String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0.0.0"
    }

    static func check() async -> Outcome {
        let headers = [
            "Accept": "application/vnd.github+json",
            // GitHub без User-Agent отвечает 403.
            "User-Agent": "NotchLimits"
        ]
        switch await HTTPClient.shared.get(apiURL, headers: headers) {
        case .failure(let error):
            if case .transport(let message) = error { return .failed(message) }
            return .failed(L.t("error.network"))
        case .success(let response):
            // 404 — релизов ещё не публиковали. Это не ошибка: обновляться не на что.
            if response.status == 404 { return .upToDate(current: current()) }
            guard response.status == 200 else { return .failed(L.t("error.http", response.status)) }
            guard let release = parse(response.data) else { return .failed(L.t("error.parse")) }
            let current = current()
            return isNewer(release.version, than: current)
                ? .available(release)
                : .upToDate(current: current)
        }
    }

    /// Разбор ответа GitHub. Чистый — под самопроверку.
    static func parse(_ data: Data) -> Release? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = root["tag_name"] as? String, !tag.isEmpty
        else { return nil }
        let url = (root["html_url"] as? String).flatMap(URL.init(string:)) ?? releasesPage
        return Release(version: normalize(tag), url: url)
    }

    /// «v1.2.0» → «1.2.0».
    static func normalize(_ tag: String) -> String {
        tag.hasPrefix("v") || tag.hasPrefix("V") ? String(tag.dropFirst()) : tag
    }

    /// Сравнение версий по числовым компонентам: «1.10.0» новее «1.9.9».
    static func isNewer(_ candidate: String, than base: String) -> Bool {
        let lhs = components(candidate), rhs = components(base)
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left > right }
        }
        return false
    }

    private static func components(_ version: String) -> [Int] {
        version.split(whereSeparator: { $0 == "." || $0 == "-" }).map { Int($0) ?? 0 }
    }
}
