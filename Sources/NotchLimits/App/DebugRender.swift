import AppKit
import SwiftUI

/// Офф-скрин рендер панели в PNG: `NOTCHLIMITS_RENDER=<папка>`.
/// Нужен и для проверки вёрстки без разрешения «Запись экрана»,
/// и для картинок в README.
enum DebugRender {

    @MainActor
    static func runIfRequested() -> Bool {
        guard let directory = ProcessInfo.processInfo.environment["NOTCHLIMITS_RENDER"] else {
            return false
        }
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        // Питание — из фикстуры, а не с этого Mac: картинки не должны зависеть
        // от того, где их рендерят (и есть ли там аккумулятор).
        PowerMonitor.shared.setSnapshotForRendering(chargingPower)

        renderPanel(to: root.appendingPathComponent("panel.png"), columns: healthyColumns())
        renderPanel(to: root.appendingPathComponent("states.png"), columns: mixedColumns(), extraHeight: 40)
        renderCollapsed(to: root.appendingPathComponent("collapsed.png"))
        KeepAwake.shared.setActive(true)
        renderPanel(to: root.appendingPathComponent("controls.png"), columns: [],
                    extraHeight: Self.indicatorsOnlyHeight - Layout.contentHeight)
        KeepAwake.shared.setActive(false)
        renderCollapsedNotch(to: root.appendingPathComponent("collapsed-awake.png"))

        PowerMonitor.shared.setSnapshotForRendering(batteryPower)
        renderPanel(to: root.appendingPathComponent("power-battery.png"), columns: [],
                    extraHeight: Self.indicatorsOnlyHeight - Layout.contentHeight)

        exit(0)
    }

    // MARK: - Сцены

    /// Высота панели без колонок: строка индикаторов и подсказка.
    /// ImageRenderer не гоняет цикл предпочтений, поэтому задаём её вручную.
    private static let indicatorsOnlyHeight: CGFloat = 66

    @MainActor
    private static func renderPanel(to url: URL, columns: [AccountColumn], extraHeight: CGFloat = 16) {
        let store = UsageStore(providers: [:], discovery: MockDiscovery())
        store.setColumnsForRendering(columns)

        let state = PanelState()
        state.geometry = notchedScreen
        state.expanded = true
        // Чип re-auth рисуем в рабочем виде, а не выключенным.
        state.onRelogin = { _ in }
        state.expandedSize = state.geometry.expandedSize(columnCount: columns.count)
        // ImageRenderer не гоняет цикл предпочтений, поэтому высоту под
        // перенесённые названия (и строки под окнами) закладываем здесь вручную.
        state.expandedSize.height += extraHeight

        let panelSize = state.expandedSize
        let scene = ZStack(alignment: .top) {
            desktop
            RootView(store: store, state: state, keepAwake: .shared, power: .shared)
                .frame(width: panelSize.width, height: panelSize.height)
        }
        .frame(width: panelSize.width + 48, height: panelSize.height + 40, alignment: .top)

        write(scene, to: url)
    }

    @MainActor
    private static func renderCollapsed(to url: URL) {
        let store = UsageStore(providers: [:], discovery: MockDiscovery())
        store.setColumnsForRendering(healthyColumns())

        let state = PanelState()
        state.expanded = false
        state.geometry = NotchGeometry(screenFrame: CGRect(x: 0, y: 0, width: 2048, height: 1152),
                                       hasNotch: false,
                                       notchRect: CGRect(x: 929, y: 1122, width: 190, height: 30))

        let scene = ZStack(alignment: .top) {
            desktop
            RootView(store: store, state: state, keepAwake: .shared, power: .shared)
                .frame(width: 190, height: 30)
        }
        .frame(width: 420, height: 96, alignment: .top)

        write(scene, to: url)
    }

    /// Свёрнутая челка с включённым Keep Awake: индикаторы в «ушках».
    @MainActor
    private static func renderCollapsedNotch(to url: URL) {
        let store = UsageStore(providers: [:], discovery: MockDiscovery())
        KeepAwake.shared.setActive(true)
        defer { KeepAwake.shared.setActive(false) }

        let state = PanelState()
        state.expanded = false
        state.geometry = notchedScreen
        state.keepAwakeIndicator = true
        let size = state.collapsedSize

        let scene = ZStack(alignment: .top) {
            desktop
            RootView(store: store, state: state, keepAwake: .shared, power: .shared)
                .frame(width: size.width, height: size.height)
        }
        .frame(width: 420, height: 96, alignment: .top)

        write(scene, to: url)
    }

    private static var desktop: some View {
        LinearGradient(colors: [Color(red: 0.16, green: 0.17, blue: 0.21),
                                Color(red: 0.09, green: 0.10, blue: 0.13)],
                       startPoint: .top, endPoint: .bottom)
    }

    private static let notchedScreen = NotchGeometry(
        screenFrame: CGRect(x: 0, y: 0, width: 1512, height: 982),
        hasNotch: true,
        notchRect: CGRect(x: 663, y: 950, width: 185, height: 32)
    )

    @MainActor
    private static func write<V: View>(_ view: V, to url: URL) {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        guard let image = renderer.nsImage,
              let tiff = image.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else {
            FileHandle.standardError.write(Data("render failed: \(url.path)\n".utf8))
            return
        }
        try? png.write(to: url)
        print("rendered -> \(url.path)")
    }

    // MARK: - Данные для картинок

    private static let chargingPower: PowerSnapshot = {
        var power = PowerSnapshot(state: .charging, percent: 84)
        power.voltage = 12.41
        power.current = 2.13
        power.temperature = 31.6
        power.cycleCount = 309
        power.maxCapacity = 5017
        power.designCapacity = 6075
        power.adapter = .init(name: "96W USB-C Power Adapter", watts: 94, voltage: 20, current: 4.69)
        power.input = .init(watts: 51.5, voltage: 20.2, current: 2.55)
        return power
    }()

    private static let batteryPower: PowerSnapshot = {
        var power = PowerSnapshot(state: .onBattery, percent: 18)
        power.voltage = 11.38
        power.current = -1.2
        power.temperature = 29.4
        power.cycleCount = 309
        power.maxCapacity = 5017
        power.designCapacity = 6075
        return power
    }()

    private static let hour: TimeInterval = 3_600

    private static func healthyColumns() -> [AccountColumn] {
        var main = AccountColumn(id: "claude:main", provider: .claude, profileName: "main")
        main.subtitle = "Pro · user@example.com"
        main.isActive = true      // открыт в приложении Claude — имя подсвечено
        main.updatedAt = Date()
        main.status = .ok
        main.windows = [
            LimitWindow(key: "five_hour", title: L.t("window.fiveHour"), utilization: 42,
                        resetsAt: Date().addingTimeInterval(2.4 * hour),
                        exhaustsAt: Date().addingTimeInterval(1.6 * hour)),
            LimitWindow(key: "seven_day", title: L.t("window.week"), utilization: 71,
                        resetsAt: Date().addingTimeInterval(74 * hour)),
            LimitWindow(key: "seven_day_opus", title: L.t("window.week") + " · Opus", utilization: 93,
                        resetsAt: Date().addingTimeInterval(74 * hour))
        ]

        var work = AccountColumn(id: "claude:work", provider: .claude, profileName: "work")
        work.subtitle = "Max · work@example.com"
        work.updatedAt = Date()
        work.status = .ok
        work.windows = [
            LimitWindow(key: "five_hour", title: L.t("window.fiveHour"), utilization: 8,
                        resetsAt: Date().addingTimeInterval(4.1 * hour)),
            LimitWindow(key: "seven_day", title: L.t("window.week"), utilization: 55,
                        resetsAt: Date().addingTimeInterval(30 * hour))
        ]

        var codex = AccountColumn(id: "codex:default", provider: .codex,
                                  profileName: ProfileDirectories.primaryName)
        codex.subtitle = "Plus · codex@example.com"
        codex.isActive = true
        codex.updatedAt = Date()
        codex.status = .ok
        codex.windows = [
            LimitWindow(key: "main.primary", title: L.t("window.week"), utilization: 22,
                        resetsAt: Date().addingTimeInterval(141 * hour)),
            LimitWindow(key: "spark.primary", title: "GPT-5.3-Codex-Spark · " + L.t("window.fiveHour"),
                        utilization: 34, resetsAt: Date().addingTimeInterval(5 * hour)),
            LimitWindow(key: "spark.secondary", title: "GPT-5.3-Codex-Spark · " + L.t("window.week"),
                        utilization: 87, resetsAt: Date().addingTimeInterval(168 * hour))
        ]
        codex.stats = [UsageStat(key: "resetCredits", label: L.t("stat.resetCredits"), value: "3")]

        return [main, work, codex]
    }

    /// Три состояния разом: свежие данные, требуется вход, данные из кэша.
    private static func mixedColumns() -> [AccountColumn] {
        var columns = healthyColumns()

        columns[1].windows = []
        columns[1].subtitle = nil
        columns[1].updatedAt = nil
        columns[1].status = .reauth(L.t("column.reauth"))

        columns[2].updatedAt = Date().addingTimeInterval(-11 * 60)
        columns[2].status = .waiting(until: Date().addingTimeInterval(180))
        columns[2].fromCache = true

        return columns
    }
}
