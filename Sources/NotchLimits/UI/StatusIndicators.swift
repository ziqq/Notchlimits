import SwiftUI

/// Маленькие индикаторы состояния в строке «Обновлено …»: Keep Awake и питание.
/// Только показывают — включается всё из контекстного меню. Подробности —
/// во всплывающей подсказке, чтобы капсулы оставались короткими.
struct StatusIndicators: View {
    @ObservedObject var keepAwake: KeepAwake
    @ObservedObject var power: PowerMonitor

    var body: some View {
        HStack(spacing: 6) {
            // Оба режима видны всегда: включён — ярко, выключен — приглушённо.
            Chip(help: L.t("keepAwake.sleep.help"), isOn: keepAwake.isActive, tint: Theme.primary) {
                Image(systemName: keepAwake.isActive ? "cup.and.saucer.fill" : "cup.and.saucer")
            }
            Chip(help: L.t("keepAwake.display.help"), isOn: displayKeptOn, tint: Theme.primary) {
                Image(systemName: "display")
            }
            if let snapshot = power.snapshot {
                PowerChips(snapshot: snapshot)
            }
        }
        .fixedSize()
    }

    /// Экран держится, только пока включён основной режим.
    private var displayKeptOn: Bool { keepAwake.isActive && keepAwake.keepDisplayOn }
}

/// Капсула индикатора: иконки и короткое значение, в тон подписи «Обновлено».
/// `isOn: false` — приглушённая капсула выключенного режима; `tint` — цвет
/// иконки и значения, когда капсула включена.
private struct Chip<Content: View>: View {
    var help: String?
    var isOn = true
    var tint: Color = Theme.secondary
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 4) { content }
            .font(.system(size: 9.5, weight: .semibold))
            .foregroundColor(isOn ? tint : Theme.tertiary.opacity(0.7))
            .monospacedDigit()
            .lineLimit(1)
            .padding(.horizontal, 7)
            .frame(height: 18)
            .background(Capsule().fill(Color.white.opacity(isOn ? 0.1 : 0.04)))
            .help(help ?? "")
    }
}

/// Питание двумя капсулами: аккумулятор (заряд и температура) и зарядка
/// («сколько берёт сейчас / на сколько рассчитан адаптер»).
private struct PowerChips: View {
    let snapshot: PowerSnapshot

    var body: some View {
        Chip(help: batteryHelp, tint: levelColor) {
            Image(systemName: symbol)
            if let percent = snapshot.percent {
                Text(Format.percent(Double(percent)))
            }
            if let temperature = snapshot.temperature {
                Text("· " + Format.unit(temperature, digits: 0, "°C"))
                    .foregroundColor(Theme.secondary)
            }
        }
        if let watts = chargerWatts {
            Chip(help: chargerHelp) {
                Image(systemName: "bolt.fill")
                Text(watts)
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

    /// Зелёный — от сети (заряжается или уже полон), красный — мало заряда.
    private var levelColor: Color {
        switch snapshot.state {
        case .charging, .charged, .notCharging: return Theme.green
        case .onBattery where (snapshot.percent ?? 100) <= 20: return Theme.red
        case .onBattery: return Theme.secondary
        }
    }

    /// «37,2 / 94 W»: сколько Mac берёт от зарядки сейчас из паспортной мощности
    /// адаптера. Без телеметрии — только паспорт, без адаптера — ничего.
    private var chargerWatts: String? {
        let rated = snapshot.adapter?.watts
        guard let input = snapshot.input else {
            return rated.map { Format.unit(Double($0), digits: 0, "W") }
        }
        guard let rated else { return Format.unit(input.watts, digits: 1, "W") }
        return Format.number(input.watts, digits: 1) + " / " + Format.unit(Double(rated), digits: 0, "W")
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
