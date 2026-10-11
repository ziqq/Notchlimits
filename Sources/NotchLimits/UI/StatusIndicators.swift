import SwiftUI

/// Маленькие индикаторы состояния в строке «Обновлено …»: Keep Awake, питание, порты.
/// Только показывают — включается всё из контекстного меню. Подробности по
/// наведению пишутся в `hint`: системные подсказки (`.help`) в неактивной
/// панели не появляются, поэтому текст рисует сама панель.
struct StatusIndicators: View {
    @ObservedObject var keepAwake: KeepAwake
    @ObservedObject var power: PowerMonitor
    @Binding var hint: ChipHint?

    var body: some View {
        HStack(spacing: 6) {
            // Оба режима видны всегда: включён — ярко, выключен — приглушённо.
            Chip(help: L.t("keepAwake.sleep.help"), isOn: keepAwake.isActive, tint: Theme.primary) {
                Image(systemName: keepAwake.isActive ? "cup.and.saucer.fill" : "cup.and.saucer")
            }
            Chip(help: L.t("keepAwake.display.help"), isOn: keepAwake.keepDisplayOn, tint: Theme.primary) {
                Image(systemName: "display")
            }
            PowerChips(snapshot: power.snapshot, ports: power.ports)
        }
        .fixedSize()
        .environment(\.chipHint, $hint)
    }

}

/// Капсула индикатора: иконки и короткое значение, в тон подписи «Обновлено».
/// `isOn: false` — приглушённая капсула выключенного режима; `tint` — цвет
/// иконки и значения, когда капсула включена.
private struct Chip<Content: View>: View {
    var help: String?
    var isOn = true
    var tint: Color = Theme.secondary
    @ViewBuilder var content: Content
    @Environment(\.chipHint) private var hint
    /// Рамка капсулы в координатах подвала — к ней привязывается подсказка.
    @State private var frame: CGRect = .zero

    var body: some View {
        HStack(spacing: 4) { content }
            .font(.system(size: 9.5, weight: .semibold))
            .foregroundColor(isOn ? tint : Theme.tertiary.opacity(0.7))
            .monospacedDigit()
            .lineLimit(1)
            .padding(.horizontal, 7)
            .frame(height: 18)
            .background(Capsule().fill(Color.white.opacity(isOn ? 0.1 : 0.04)))
            .contentShape(Capsule())
            .background(
                GeometryReader { proxy in
                    Color.clear
                        .onAppear { frame = proxy.frame(in: .named(ChipHint.space)) }
                        .onChange(of: proxy.frame(in: .named(ChipHint.space))) { frame = $0 }
                }
            )
            .onHover { inside in
                guard let hint, let help, !help.isEmpty else { return }
                if inside {
                    hint.wrappedValue = ChipHint(text: help, chip: frame)
                } else if hint.wrappedValue?.text == help {
                    hint.wrappedValue = nil
                }
            }
    }
}

/// Подсказка капсулы и где стоит сама капсула (в пространстве `ChipHint.space`).
struct ChipHint: Equatable {
    static let space = "chipHints"
    var text: String
    var chip: CGRect
}

/// Куда капсулы пишут подсказку при наведении.
private struct ChipHintKey: EnvironmentKey {
    static let defaultValue: Binding<ChipHint?>? = nil
}

extension EnvironmentValues {
    var chipHint: Binding<ChipHint?>? {
        get { self[ChipHintKey.self] }
        set { self[ChipHintKey.self] = newValue }
    }
}

/// Плашка над капсулой: правый край — по правому краю капсулы, низ — на 6 pt
/// выше её верха. Ставится в `overlay(alignment: .topLeading)` того вида, где
/// объявлено пространство `ChipHint.space`. Свой размер плашка узнаёт после
/// первой вёрстки, до этого она прозрачна — так не мелькает не на своём месте.
struct AnchoredHintBubble: View {
    let hint: ChipHint
    @State private var size: CGSize = .zero

    var body: some View {
        ChipHintBubble(text: hint.text)
            .background(
                GeometryReader { proxy in
                    Color.clear
                        .onAppear { size = proxy.size }
                        .onChange(of: proxy.size) { size = $0 }
                }
            )
            // Не левее края подвала, если плашка шире места слева от капсулы.
            .offset(x: max(0, hint.chip.maxX - size.width), y: hint.chip.minY - 6 - size.height)
            .opacity(size == .zero ? 0 : 1)
    }
}

/// Подсказка капсулы: плашка в тон панели.
struct ChipHintBubble: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 10))
            .foregroundColor(Theme.secondary)
            .lineSpacing(2)
            .fixedSize()
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color(white: 0.13)))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.divider))
            .allowsHitTesting(false)
    }
}

/// Питание и порты: аккумулятор (заряд и температура), зарядка («порт · сколько
/// берёт сейчас / на сколько рассчитан адаптер») и занятость разъёмов USB-C.
private struct PowerChips: View {
    let snapshot: PowerSnapshot?
    let ports: PortsSnapshot?

    var body: some View {
        if let snapshot {
            BatteryChip(snapshot: snapshot)
        }
        if let charger = chargerText {
            Chip(help: chargerHelp) {
                Image(systemName: "bolt.fill")
                Text(charger)
            }
        }
        if let ports, ports.ports.contains(where: { !$0.isMagSafe }) {
            PortsChip(ports: ports)
        }
    }

    private var contract: PortsSnapshot.Contract? { ports?.contract }

    /// «MagSafe · 37,2 / 94 W»: порт питания и мощность.
    private var chargerText: String? {
        let parts = [contract.map(Self.shortName), chargerWatts].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// «MagSafe», «USB-C 2» — коротко, для капсулы.
    static func shortName(_ contract: PortsSnapshot.Contract) -> String {
        contract.portKind.hasPrefix("MagSafe") ? "MagSafe" : "\(contract.portKind) \(contract.portNumber)"
    }

    /// «37,2 / 94 W»: сколько Mac берёт от зарядки сейчас из паспортной мощности
    /// адаптера. Без телеметрии — только паспорт, без адаптера — ничего.
    private var chargerWatts: String? {
        let rated = snapshot?.adapter?.watts ?? contract.map { Int($0.watts.rounded()) }
        guard let input = snapshot?.input else {
            return rated.map { Format.unit(Double($0), digits: 0, "W") }
        }
        guard let rated else { return Format.unit(input.watts, digits: 1, "W") }
        return Format.number(input.watts, digits: 1) + " / " + Format.unit(Double(rated), digits: 0, "W")
    }

    /// Порт и контракт, адаптер по паспорту и что Mac берёт от него прямо сейчас.
    private var chargerHelp: String {
        var lines: [String] = []
        if let contract {
            lines.append(L.t("power.port") + ": " + joined([
                contract.portKind.hasPrefix("MagSafe") ? contract.portKind : "\(contract.portKind) \(contract.portNumber)",
                Format.unit(contract.voltage, digits: contract.voltage == contract.voltage.rounded() ? 0 : 1, "V"),
                Format.unit(contract.current, digits: 2, "A"),
                Format.unit(contract.watts, digits: 1, "W")
            ]))
            if contract.offeredVoltages.count > 1 {
                lines.append(L.t("power.modes") + ": "
                             + contract.offeredVoltages.map { Format.number($0, digits: 0) }.joined(separator: " / ")
                             + "\u{00A0}V")
            }
        }
        if let adapter = snapshot?.adapter {
            let value = joined([adapter.name,
                                adapter.watts.map { Format.unit(Double($0), digits: 0, "W") }])
            lines.append(L.t("power.charger") + ": " + value)
        }
        if let input = snapshot?.input {
            let value = joined([Format.unit(input.watts, digits: 1, "W"),
                                input.voltage.map { Format.unit($0, digits: 1, "V") },
                                input.current.map { Format.unit($0, digits: 2, "A") }])
            lines.append(L.t("power.input") + ": " + value)
            lines.append(L.t("power.input.help"))
        }
        return lines.joined(separator: "\n")
    }

    private func joined(_ parts: [String?]) -> String {
        parts.compactMap { $0 }.joined(separator: " · ")
    }
}

/// Разъёмы USB-C цифрами: занятые — ярко, свободные — приглушённо.
private struct PortsChip: View {
    let ports: PortsSnapshot

    private var usbC: [PortsSnapshot.Port] { ports.ports.filter { !$0.isMagSafe } }

    var body: some View {
        Chip(help: help) {
            Image(systemName: "cable.connector")
            Text("USB-C")
            ForEach(usbC) { port in
                Text("\(port.number)")
                    .foregroundColor(port.connected ? Theme.primary : Theme.tertiary.opacity(0.6))
            }
        }
    }

    /// «USB-C 1: USB 2 / USB-C 3: свободен / MagSafe 3: зарядка».
    private var help: String {
        ports.ports.map { port in
            let state: String
            if ports.contract?.portKind == port.kind && ports.contract?.portNumber == port.number {
                state = L.t("ports.charging")
            } else if !port.connected {
                state = L.t("ports.free")
            } else if port.transports.isEmpty {
                state = L.t("ports.connected")
            } else {
                state = port.transports.map(Self.transportName).joined(separator: " · ")
            }
            return "\(Self.portName(port)): \(state)"
        }
        .joined(separator: "\n")
    }

    /// «USB-C 2», а MagSafe — один на корпусе, без номера: «MagSafe 3».
    static func portName(_ port: PortsSnapshot.Port) -> String {
        port.isMagSafe ? port.kind : "\(port.kind) \(port.number)"
    }

    private static func transportName(_ raw: String) -> String {
        switch raw {
        case "USB2": return "USB 2"
        case "USB3": return "USB 3"
        case "CIO": return "Thunderbolt"
        default: return raw
        }
    }
}

/// Аккумулятор: заряд и температура, цвет — от сети или мало заряда.
private struct BatteryChip: View {
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
