import Foundation

/// Макет данных для отладки геометрии и вёрстки: NOTCHLIMITS_MOCK=1.
struct MockDiscovery: AccountDiscovery {
    func discover() -> [DiscoveredAccount] {
        [
            DiscoveredAccount(id: "claude:main", provider: .claude,
                              profileName: "main", source: .mock(seed: 0)),
            DiscoveredAccount(id: "claude:work", provider: .claude,
                              profileName: "work", source: .mock(seed: 1)),
            DiscoveredAccount(id: "codex:default", provider: .codex,
                              profileName: "default", source: .mock(seed: 2))
        ]
    }
}

struct MockProvider: UsageProvider {
    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .mock(let seed) = account.source else {
            return .failure("mock: неизвестный источник")
        }
        try? await Task.sleep(nanoseconds: 400_000_000)

        let hour: TimeInterval = 3_600
        switch seed {
        case 0:
            return .success(UsageSnapshot(subtitle: "user@example.com", windows: [
                LimitWindow(key: "five_hour", title: "5-часовое окно",
                            utilization: 42, resetsAt: Date().addingTimeInterval(2.4 * hour)),
                LimitWindow(key: "seven_day", title: "Недельное окно",
                            utilization: 71, resetsAt: Date().addingTimeInterval(74 * hour)),
                LimitWindow(key: "seven_day_opus", title: "seven_day_opus",
                            utilization: 93, resetsAt: Date().addingTimeInterval(74 * hour))
            ]))
        case 1:
            return .success(UsageSnapshot(subtitle: "work@example.com", windows: [
                LimitWindow(key: "five_hour", title: "5-часовое окно",
                            utilization: 8, resetsAt: Date().addingTimeInterval(4.1 * hour)),
                LimitWindow(key: "seven_day", title: "Недельное окно",
                            utilization: 55, resetsAt: Date().addingTimeInterval(30 * hour))
            ]))
        default:
            return .success(UsageSnapshot(subtitle: "codex@example.com", windows: [
                LimitWindow(key: "primary", title: "Недельное окно",
                            utilization: 21, resetsAt: Date().addingTimeInterval(141 * hour)),
                LimitWindow(key: "spark_primary", title: "Spark · 5-часовое окно",
                            utilization: 0, resetsAt: Date().addingTimeInterval(5 * hour)),
                LimitWindow(key: "spark_secondary", title: "Spark · Недельное окно",
                            utilization: 87, resetsAt: Date().addingTimeInterval(168 * hour))
            ]))
        }
    }
}
