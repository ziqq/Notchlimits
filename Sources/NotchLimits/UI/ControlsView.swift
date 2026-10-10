import SwiftUI

/// Секция «Управление»: круглые плитки-переключатели в духе Пункта управления.
struct ControlsSection: View {
    @ObservedObject var keepAwake: KeepAwake

    var body: some View {
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
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
    }
}

/// Круглая кнопка с подписью. Включена — белый круг и тёмная иконка.
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
