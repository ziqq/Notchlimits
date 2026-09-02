import Foundation
import SwiftUI

/// Оркестратор опроса: держит колонки, расписание и бэкофф.
/// Каждый аккаунт живёт сам по себе — падение одного не трогает остальные.
@MainActor
final class UsageStore: ObservableObject {

    @Published private(set) var columns: [AccountColumn] = []
    @Published private(set) var hidden: Set<String> = []
    @Published private(set) var customNames: [String: String] = [:]

    var visibleColumns: [AccountColumn] { columns.filter { !hidden.contains($0.id) } }
    var hasHiddenColumns: Bool { !hidden.isEmpty }

    var lastUpdatedAt: Date? {
        visibleColumns.compactMap(\.updatedAt).max()
    }

    /// Вызывается, когда меняется набор колонок — панели нужно пересчитать ширину.
    var onColumnsChanged: (() -> Void)?

    private var runtime: [String: Runtime] = [:]
    private var accounts: [DiscoveredAccount] = []
    private var tick: Timer?
    private var lastDiscovery: Date?
    private let cache = UsageCache()
    private let history = UsageHistory()
    private let notifier = ThresholdNotifier()
    private let providers: [Provider: UsageProvider]
    private let discovery: AccountDiscovery

    /// Опрос раз в 3 минуты, аккаунты разнесены на 4 секунды.
    private enum Schedule {
        static let interval: TimeInterval = 180
        static let stagger: TimeInterval = 4
        static let staleOnOpen: TimeInterval = 120
        static let backoff: [TimeInterval] = [120, 240, 480, 900]
    }

    private struct Runtime {
        var nextDue: Date
        var backoffStep: Int = 0
        var inFlight: Bool = false
    }

    init(providers: [Provider: UsageProvider], discovery: AccountDiscovery) {
        self.providers = providers
        self.discovery = discovery
        hidden = Set(UserDefaults.standard.stringArray(forKey: "hiddenColumns") ?? [])
        customNames = UserDefaults.standard.dictionary(forKey: "columnNames") as? [String: String] ?? [:]
    }

    // MARK: - Запуск

    func start() {
        rediscover(force: true)
        tick = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.pump() }
        }
        pump()
    }

    /// Пересканировать профили. Данные уже известных колонок сохраняются.
    /// Перечисление Keychain небесплатное, поэтому не чаще раза в 30 секунд —
    /// это всё равно в шесть раз чаще, чем цикл опроса.
    func rediscover(force: Bool = false) {
        let now = Date()
        if !force, let last = lastDiscovery, now.timeIntervalSince(last) < 30 { return }
        lastDiscovery = now

        let found = discovery.discover()
        guard found.map(\.id) != accounts.map(\.id) else { return }
        accounts = found

        var next: [AccountColumn] = []
        for (index, account) in found.enumerated() {
            if let existing = columns.first(where: { $0.id == account.id }) {
                // Уже известная колонка — её данные и статус сохраняем как есть.
                next.append(existing)
            } else {
                var column = AccountColumn(id: account.id,
                                           provider: account.provider,
                                           profileName: account.profileName)
                column.customName = customNames[account.id]
                if let cached = cache.load(id: account.id) {
                    column.windows = cached.windows
                    column.subtitle = cached.subtitle
                    column.stats = cached.stats ?? []
                    column.updatedAt = cached.updatedAt
                    column.fromCache = true
                    column.status = .ok
                }
                next.append(column)
                runtime[account.id] = Runtime(nextDue: now.addingTimeInterval(Double(index) * Schedule.stagger))
            }
        }
        // Забываем расписание исчезнувших профилей.
        let ids = Set(found.map(\.id))
        runtime = runtime.filter { ids.contains($0.key) }

        columns = next
        onColumnsChanged?()
    }

    // MARK: - Планировщик

    private func pump() {
        rediscover()
        let now = Date()
        for account in accounts {
            guard var state = runtime[account.id], !state.inFlight, state.nextDue <= now else { continue }
            state.inFlight = true
            runtime[account.id] = state
            Task { await self.fetch(account) }
        }
    }

    /// Принудительное обновление (кнопка / пункт меню).
    func refreshAll(force: Bool = true) {
        let now = Date()
        for account in accounts {
            guard var state = runtime[account.id] else { continue }
            if force { state.backoffStep = 0 }
            state.nextDue = now
            runtime[account.id] = state
        }
        pump()
    }

    /// При раскрытии панели обновляем только то, что старше двух минут.
    func refreshStale() {
        let now = Date()
        for account in accounts {
            guard var state = runtime[account.id], !state.inFlight else { continue }
            let column = columns.first(where: { $0.id == account.id })
            let age = column?.updatedAt.map { now.timeIntervalSince($0) } ?? .greatestFiniteMagnitude
            guard age > Schedule.staleOnOpen else { continue }
            // Бэкофф 429 не сбрасываем: панель открыли — эндпоинт от этого не подобрел.
            if case .waiting = column?.status ?? .ok, state.nextDue > now { continue }
            state.nextDue = now
            runtime[account.id] = state
        }
        pump()
    }

    func setHidden(_ id: String, hidden isHidden: Bool) {
        if isHidden { hidden.insert(id) } else { hidden.remove(id) }
        UserDefaults.standard.set(Array(hidden), forKey: "hiddenColumns")
        onColumnsChanged?()
    }

    /// Своё имя для колонки. Пустая строка возвращает имя профиля.
    func setCustomName(_ name: String, for id: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { customNames[id] = nil } else { customNames[id] = trimmed }
        UserDefaults.standard.set(customNames, forKey: "columnNames")
        if let index = columns.firstIndex(where: { $0.id == id }) {
            columns[index].customName = customNames[id]
        }
    }

    func showAllColumns() {
        hidden.removeAll()
        UserDefaults.standard.set([String](), forKey: "hiddenColumns")
        onColumnsChanged?()
    }

    // MARK: - Опрос

    private func fetch(_ account: DiscoveredAccount) async {
        guard let provider = providers[account.provider] else {
            finish(account.id, outcome: .failure(L.t("error.noProvider")))
            return
        }
        let outcome = await provider.fetch(account)
        finish(account.id, outcome: outcome)
    }

    private func finish(_ id: String, outcome: FetchOutcome) {
        guard var state = runtime[id] else { return }
        state.inFlight = false
        guard let index = columns.firstIndex(where: { $0.id == id }) else {
            runtime[id] = state
            return
        }

        switch outcome {
        case .success(let snapshot):
            state.backoffStep = 0
            state.nextDue = Date().addingTimeInterval(Schedule.interval)
            let now = Date()
            // Дописываем историю и считаем тренд/прогноз для каждого окна.
            columns[index].windows = snapshot.windows.map { window in
                let samples = history.record(columnID: id, window: window, now: now)
                var enriched = window
                enriched.trend = samples.map(\.u)
                enriched.exhaustsAt = UsageHistory.projection(samples: samples,
                                                              current: window.utilization,
                                                              resetsAt: window.resetsAt, now: now)
                return enriched
            }
            columns[index].subtitle = snapshot.subtitle
            columns[index].stats = snapshot.stats
            columns[index].updatedAt = now
            columns[index].status = .ok
            columns[index].fromCache = false
            cache.save(columns[index])
            notifier.evaluate(column: columns[index])

        case .rateLimited(let retryAfter):
            let delay = retryAfter ?? Schedule.backoff[min(state.backoffStep, Schedule.backoff.count - 1)]
            state.backoffStep = min(state.backoffStep + 1, Schedule.backoff.count - 1)
            let until = Date().addingTimeInterval(delay)
            state.nextDue = until
            columns[index].status = .waiting(until: until)

        case .reauth(let message):
            state.backoffStep = 0
            state.nextDue = Date().addingTimeInterval(Schedule.interval)
            columns[index].status = .reauth(message)

        case .failure(let message):
            state.backoffStep = 0
            state.nextDue = Date().addingTimeInterval(Schedule.interval)
            columns[index].status = .failed(message)
        }

        runtime[id] = state
    }
}

extension UsageStore {
    /// Только для офф-скрин рендера макета (NOTCHLIMITS_RENDER).
    func setColumnsForRendering(_ value: [AccountColumn]) {
        columns = value
    }
}
