import SwiftUI

/// Маленькие индикаторы состояния в строке «Обновлено …»: Keep Awake и питание.
/// Только показывают — включается всё из контекстного меню. Подробности —
/// во всплывающей подсказке, чтобы капсулы оставались короткими.
struct StatusIndicators: View {
    @ObservedObject var keepAwake: KeepAwake
    @ObservedObject var power: PowerMonitor

    var body: some View {
        HStack(spacing: 6) {
            if keepAwake.isActive {
                Chip(help: keepAwakeHelp) {
                    Image(systemName: "cup.and.saucer.fill")
                    if keepAwake.keepDisplayOn {
                        Image(systemName: "display")
                    }
                }
            }
            if let snapshot = power.snapshot {
                PowerChips(snapshot: snapshot)
            }
        }
        .fixedSize()
    }

    private var keepAwakeHelp: String {
        var lines = [L.t("keepAwake.sleep.help")]
        if keepAwake.keepDisplayOn { lines.append(L.t("keepAwake.display.help")) }
        return lines.joined(separator: "\n")
    }
}

/// Капсула индикатора: иконки и короткое значение, в тон подписи «Обновлено».
private struct Chip<Content: View>: View {
    var help: String?
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 4) { content }
            .font(.system(size: 9.5, weight: .semibold))
            .foregroundColor(Theme.secondary)
            .monospacedDigit()
            .lineLimit(1)
            .padding(.horizontal, 7)
            .frame(height: 18)
            .background(Capsule().fill(Color.white.opacity(0.08)))
            .help(help ?? "")
    }
}

/// Питание тремя капсулами: заряд, мощность от зарядки, температура аккумулятора.
private struct PowerChips: View {
    let snapshot: PowerSnapshot

    var body: some View {
        Chip(help: batteryHelp) {
            Image(systemName: symbol).foregroundColor(symbolColor)
            if let percent = snapshot.percent {
                Text(Format.percent(Double(percent)))
            }
        }
        if let watts = chargerWatts {
            Chip(help: chargerHelp) {
                Image(systemName: "bolt.fill")
                Text(watts)
            }
        }
        if let temperature = snapshot.temperature {
            Chip(help: L.t("power.battery")) {
                Image(systemName: "thermometer.medium")
                Text(Format.unit(temperature, digits: 0, "°C"))
            }
        }
    }

    private var symbol: String {
        switch snapshot.state {
        case .charging: return "battery.100percent.bolt"
        case .charged, .notCharging: return "powerplug.fill"
        case .onBattery:
            switch snapshot.percent ?? 100 {
            case ..<13: return "battery.0percent"
            case ..<38: return "battery.25percent"
            case ..<63: return "battery.50percent"
            case ..<88: return "battery.75percent"
            default: return "battery.100percent"
            }
        }
    }

    private var symbolColor: Color {
        switch snapshot.state {
        case .charging: return Theme.green
        case .onBattery where (snapshot.percent ?? 100) <= 20: return Theme.red
        default: return Theme.secondary
        }
    }

    /// Сколько Mac берёт от зарядки сейчас, а без телеметрии — паспорт адаптера.
    private var chargerWatts: String? {
        if let input = snapshot.input { return Format.unit(input.watts, digits: 1, "W") }
        if let watts = snapshot.adapter?.watts { return Format.unit(Double(watts), digits: 0, "W") }
        return nil
    }

    private var stateTitle: String {
        switch snapshot.state {
        case .charging: return L.t("power.charging")
        case .charged: return L.t("power.charged")
        case .notCharging: return L.t("power.notCharging")
        case .onBattery: return L.t("power.onBattery")
        }
    }

    /// «Заряжается / Аккумулятор: 12,41 V · 2,13 A · 31,6 °C / Здоровье: 83 % · циклов: 309».
    private var batteryHelp: String {
        var lines = [stateTitle]
        let battery = joined([snapshot.voltage.map { Format.unit($0, digits: 2, "V") },
                              snapshot.current.map { Format.unit($0, digits: 2, "A") },
                              snapshot.temperature.map { Format.unit($0, digits: 1, "°C") }])
        if !battery.isEmpty { lines.append(L.t("power.battery") + ": " + battery) }
        if let health = healthValue { lines.append(L.t("power.health") + ": " + health) }
        if let maximum = snapshot.maxCapacity, let design = snapshot.designCapacity {
            lines.append(L.t("power.health.help", maximum, design))
        }
        return lines.joined(separator: "\n")
    }

    /// Адаптер по паспорту и что Mac берёт от него прямо сейчас.
    private var chargerHelp: String {
        var lines: [String] = []
        if let adapter = snapshot.adapter {
            let value = joined([adapter.name,
                                adapter.watts.map { Format.unit(Double($0), digits: 0, "W") },
                                adapter.voltage.map { Format.unit($0, digits: $0 == $0.rounded() ? 0 : 1, "V") },
                                adapter.current.map { Format.unit($0, digits: 2, "A") }])
            lines.append(L.t("power.charger") + ": " + value)
        }
        if let input = snapshot.input {
            let value = joined([Format.unit(input.watts, digits: 1, "W"),
                                input.voltage.map { Format.unit($0, digits: 1, "V") },
                                input.current.map { Format.unit($0, digits: 2, "A") }])
            lines.append(L.t("power.input") + ": " + value)
            lines.append(L.t("power.input.help"))
        }
        return lines.joined(separator: "\n")
    }

    private var healthValue: String? {
        switch (snapshot.health, snapshot.cycleCount) {
        case let (health?, cycles?): return L.t("power.health.value", Format.percent(health), cycles)
        case let (health?, nil): return Format.percent(health)
        default: return nil
        }
    }

    private func joined(_ parts: [String?]) -> String {
        parts.compactMap { $0 }.joined(separator: " · ")
    }
}

/// Индикатор Keep Awake в «ушках» свёрнутой панели: чашка слева,
/// справа — экран, если он тоже не гаснет.
struct KeepAwakeEars: View {
    @ObservedObject var keepAwake: KeepAwake

    var body: some View {
        HStack(spacing: 0) {
            ear("cup.and.saucer.fill")
            Spacer(minLength: 0)
            if keepAwake.keepDisplayOn {
                ear("display")
            }
        }
    }

    private func ear(_ symbol: String) -> some View {
        Image(systemName: symbol)
            .font(.system(size: 10, weight: .semibold))
            .foregroundColor(Theme.primary)
            .frame(width: Layout.earWidth)
    }
}

// MARK: - Рамки кнопок

/// Рамки кнопок в координатах окна: контроллер по ним отличает нажатие
/// кнопки (например, «Обновить») от клика по фону, который закрепляет панель.
struct ControlFramesKey: PreferenceKey {
    static var defaultValue: [CGRect] = []
    static func reduce(value: inout [CGRect], nextValue: () -> [CGRect]) {
        value.append(contentsOf: nextValue())
    }
}

extension View {
    func reportsControlFrame() -> some View {
        background(
            GeometryReader { proxy in
                Color.clear.preference(key: ControlFramesKey.self,
                                       value: [proxy.frame(in: .global)])
            }
        )
    }
}
