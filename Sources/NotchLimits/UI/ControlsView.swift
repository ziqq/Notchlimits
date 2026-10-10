import SwiftUI

/// Секция «Управление»: круглые плитки-переключатели в духе Пункта управления,
/// справа от них — сводка питания, если у Mac есть аккумулятор.
struct ControlsSection: View {
    @ObservedObject var keepAwake: KeepAwake
    @ObservedObject var power: PowerMonitor

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            tiles
            if let snapshot = power.snapshot {
                Spacer(minLength: 12)
                PowerReadout(snapshot: snapshot)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
    }

    private var tiles: some View {
        HStack(alignment: .top, spacing: 8) {
            ControlTile(symbol: "cup.and.saucer",
                        activeSymbol: "cup.and.saucer.fill",
                        title: L.t("keepAwake.sleep"),
                        help: L.t("keepAwake.sleep.help"),
                        isOn: keepAwake.isActive) {
                keepAwake.toggle()
            }
            // Экран — уточнение к основному режиму: пока тот выключен,
            // плитка приглушена, но настройку всё равно можно поменять заранее.
            ControlTile(symbol: "display",
                        activeSymbol: "display",
                        title: L.t("keepAwake.display"),
                        help: L.t("keepAwake.display.help"),
                        isOn: keepAwake.keepDisplayOn) {
                keepAwake.keepDisplayOn.toggle()
            }
            .opacity(keepAwake.isActive ? 1 : 0.55)
        }
    }
}

/// Сводка питания: состояние и заряд, затем строки «подпись — значения».
/// По высоте не больше плиток, чтобы секция не прыгала при появлении блока.
struct PowerReadout: View {
    let snapshot: PowerSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                Image(systemName: symbol)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(symbolColor)
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(Theme.primary)
            }
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 3) {
                if let adapter = snapshot.adapter {
                    row(L.t("power.charger"), adapterValue(adapter), help: adapterHelp(adapter))
                }
                if let input = snapshot.input {
                    row(L.t("power.input"), joined([Format.unit(input.watts, digits: 1, "W"),
                                                    input.current.map { Format.unit($0, digits: 2, "A") }]),
                        help: L.t("power.input.help"))
                }
                row(L.t("power.battery"), joined([
                    snapshot.voltage.map { Format.unit($0, digits: 2, "V") },
                    snapshot.current.map { Format.unit($0, digits: 2, "A") },
                    snapshot.temperature.map { Format.unit($0, digits: 1, "°C") }
                ]), help: nil)
                if let health = healthValue {
                    row(L.t("power.health"), health, help: healthHelp)
                }
            }
        }
        .fixedSize()
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String, help: String?) -> some View {
        if !value.isEmpty {
            GridRow {
                Text(label)
                    .foregroundColor(Theme.tertiary)
                Text(value)
                    .foregroundColor(Theme.secondary)
                    .monospacedDigit()
            }
            .font(.system(size: 10))
            .lineLimit(1)
            .help(help ?? "")
        }
    }

    private var title: String {
        let state: String
        switch snapshot.state {
        case .charging: state = L.t("power.charging")
        case .charged: state = L.t("power.charged")
        case .notCharging: state = L.t("power.notCharging")
        case .onBattery: state = L.t("power.onBattery")
        }
        guard let percent = snapshot.percent else { return state }
        return state + " · " + Format.percent(Double(percent))
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
        default: return Theme.primary
        }
    }

    /// «96 W · 20 V»: паспортная мощность и согласованное напряжение.
    private func adapterValue(_ adapter: PowerSnapshot.Adapter) -> String {
        joined([adapter.watts.map { Format.unit(Double($0), digits: 0, "W") },
                adapter.voltage.map { Format.unit($0, digits: $0 == $0.rounded() ? 0 : 1, "V") }])
    }

    /// Имя адаптера от системы и потолок тока: «96W USB-C Power Adapter · 4,69 A».
    private func adapterHelp(_ adapter: PowerSnapshot.Adapter) -> String {
        joined([adapter.name, adapter.current.map { Format.unit($0, digits: 2, "A") }])
    }

    private var healthValue: String? {
        switch (snapshot.health, snapshot.cycleCount) {
        case let (health?, cycles?): return L.t("power.health.value", Format.percent(health), cycles)
        case let (health?, nil): return Format.percent(health)
        default: return nil
        }
    }

    private var healthHelp: String? {
        guard let maximum = snapshot.maxCapacity, let design = snapshot.designCapacity else { return nil }
        return L.t("power.health.help", maximum, design)
    }

    private func joined(_ parts: [String?]) -> String {
        parts.compactMap { $0 }.joined(separator: " · ")
    }
}

/// Круглая кнопка с подписью под ней. Включена — белый круг и тёмная иконка.
private struct ControlTile: View {
    let symbol: String
    let activeSymbol: String
    let title: String
    let help: String
    let isOn: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: isOn ? activeSymbol : symbol)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundColor(isOn ? .black : Theme.primary)
                    .frame(width: 44, height: 44)
                    .background(Circle().fill(circleFill))
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(Theme.primary)
                    .multilineTextAlignment(.center)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: 104)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(help)
        .reportsControlFrame()
    }

    private var circleFill: Color {
        if isOn { return Color.white.opacity(hovering ? 0.85 : 1) }
        return Color.white.opacity(hovering ? 0.18 : 0.12)
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
/// кнопки от клика по фону, который закрепляет панель.
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
