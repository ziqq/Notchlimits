import Foundation

/// Короткая история процентов по каждому окну — для спарклайна и прогноза
/// исчерпания. Только числа и метки времени, без токенов; лежит в UserDefaults.
///
/// Замеры пишутся на каждый успешный опрос. Когда окно сбрасывается (процент
/// резко падает), серия начинается заново — старый склон уже не про это окно.
struct UsageHistory {

    struct Sample: Codable, Equatable {
        let t: TimeInterval
        let u: Double
    }

    private let defaults = UserDefaults.standard
    private let storeKey = "usageHistory"
    /// Держим только хвост: для склона важен недавний темп, не вся неделя.
    private let maxSamples = 40
    /// Падение процента больше этого считаем сбросом окна.
    private let resetDrop = 0.5

    /// Записать замер и вернуть обновлённую серию окна.
    func record(columnID: String, window: LimitWindow, now: Date) -> [Sample] {
        var all = load()
        let key = "\(columnID)|\(window.key)"
        var series = all[key] ?? []

        if let last = series.last, window.utilization < last.u - resetDrop {
            series = []  // окно сбросилось — начинаем заново
        }
        series.append(Sample(t: now.timeIntervalSince1970, u: window.utilization))
        if series.count > maxSamples { series.removeFirst(series.count - maxSamples) }

        all[key] = series
        save(all)
        return series
    }

    /// Прогноз момента, когда окно упрётся в 100 % при текущем темпе.
    /// Возвращает дату только если предел наступит РАНЬШЕ сброса — иначе
    /// беспокоиться не о чем. Чистая функция: покрыта самопроверкой.
    static func projection(samples: [Sample], current: Double,
                           resetsAt: Date?, now: Date) -> Date? {
        guard current < 100, samples.count >= 3 else { return nil }

        // Склон по методу наименьших квадратов, проценты в секунду.
        let n = Double(samples.count)
        let meanT = samples.reduce(0) { $0 + $1.t } / n
        let meanU = samples.reduce(0) { $0 + $1.u } / n
        var cov = 0.0, varT = 0.0
        for s in samples {
            cov += (s.t - meanT) * (s.u - meanU)
            varT += (s.t - meanT) * (s.t - meanT)
        }
        // Нужен заметный разброс по времени, иначе склон — шум.
        guard varT > 0, let first = samples.first, let last = samples.last,
              last.t - first.t >= 300 else { return nil }

        let slope = cov / varT
        guard slope > 0 else { return nil }  // ровно или падает — предела не будет

        let seconds = (100 - current) / slope
        guard seconds.isFinite, seconds > 0 else { return nil }
        let eta = now.addingTimeInterval(seconds)

        // Показываем, только если упрёмся до сброса окна.
        if let resetsAt, eta >= resetsAt { return nil }
        return eta
    }

    private func load() -> [String: [Sample]] {
        guard let data = defaults.data(forKey: storeKey),
              let dict = try? JSONDecoder().decode([String: [Sample]].self, from: data)
        else { return [:] }
        return dict
    }

    private func save(_ dict: [String: [Sample]]) {
        guard let data = try? JSONEncoder().encode(dict) else { return }
        defaults.set(data, forKey: storeKey)
    }
}
