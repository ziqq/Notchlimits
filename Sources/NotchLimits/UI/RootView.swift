import SwiftUI

struct RootView: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState
    @ObservedObject var keepAwake: KeepAwake
    let power: PowerMonitor

    private var shapeWidth: CGFloat { state.expanded ? state.expandedSize.width : state.notchSize.width }
    private var shapeHeight: CGFloat { state.expanded ? state.expandedSize.height : state.notchSize.height }
    private var cornerRadius: CGFloat {
        state.expanded ? Layout.expandedCornerRadius : Layout.collapsedCornerRadius
    }

    var body: some View {
        ZStack(alignment: .top) {
            ZStack(alignment: .top) {
                panelBackground

                CollapsedContent(store: store, state: state)
                    .frame(width: state.notchSize.width, height: state.notchSize.height)
                    .opacity(state.expanded ? 0 : 1)

                ExpandedContent(store: store, state: state, keepAwake: keepAwake, power: power)
                    .frame(width: state.expandedSize.width, height: state.expandedSize.height)
                    .opacity(state.expanded ? 1 : 0)
                    // Появляемся с задержкой, гаснем быстро: так текст не успевает
                    // попасть в кадры, где панель ещё сплющена.
                    .animation(state.expanded
                               ? .easeOut(duration: 0.18).delay(0.08)
                               : .easeIn(duration: 0.15),
                               value: state.expanded)
                    .allowsHitTesting(state.expanded)
            }
            .frame(width: shapeWidth, height: shapeHeight, alignment: .top)
            .clipShape(BottomRoundedRectangle(radius: cornerRadius))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .ignoresSafeArea()
        .onPreferenceChange(ColumnsHeightKey.self) { height in
            state.onColumnsHeightChange?(height)
        }
        .onPreferenceChange(ControlFramesKey.self) { frames in
            state.controlFrames = frames
        }
    }

    private var panelBackground: some View {
        BottomRoundedRectangle(radius: cornerRadius).fill(Theme.panelBackground)
    }
}

/// Свёрнутое состояние. На маке с челкой — ровно чёрный вырез, панели не видно.
/// На внешнем мониторе — маленькая пилюля с точкой на каждый аккаунт.
private struct CollapsedContent: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState

    var body: some View {
        if state.hasNotch {
            Color.clear
        } else {
            HStack(spacing: 5) {
                ForEach(store.visibleColumns) { column in
                    Circle()
                        .fill(Theme.color(for: column.peakUtilization))
                        .frame(width: 6, height: 6)
                        .opacity(column.hasData ? 1 : 0.35)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

private struct ExpandedContent: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState
    @ObservedObject var keepAwake: KeepAwake
    let power: PowerMonitor
    /// Подсказка капсулы под курсором.
    @State private var hint: String?

    var body: some View {
        VStack(spacing: 0) {
            // Зона выреза — под ней ничего не рисуем.
            Color.clear.frame(height: state.notchSize.height)

            // Высоту блока меряем здесь и по ней растим окно, иначе
            // перенесённые строки упёрлись бы в нижнюю кромку панели.
            VStack(spacing: 0) {
                if store.visibleColumns.isEmpty {
                    // Без аккаунтов — только индикаторы и тихая подсказка.
                    StatusIndicators(keepAwake: keepAwake, power: power, hint: $hint)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 14)
                        .padding(.top, 10)
                    // Подсказка капсулы встаёт на место подсказки про аккаунты.
                    if let hint {
                        ChipHintBubble(text: hint)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 14)
                            .padding(.top, 8)
                    } else {
                        EmptyHint(store: store)
                    }
                } else {
                    columns
                    FooterView(store: store, state: state, keepAwake: keepAwake, power: power, hint: $hint)
                        .padding(.top, Layout.columnsFooterGap)
                }
            }
            // Блок берёт свою естественную высоту, а не ту, что предложила
            // панель: иначе колонки растягиваются, а подвал уходит за край.
            .fixedSize(horizontal: false, vertical: true)
            .background(
                GeometryReader { proxy in
                    Color.clear.preference(key: ColumnsHeightKey.self,
                                           value: proxy.size.height)
                }
            )

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 6)
        .padding(.bottom, Layout.contentBottomPadding)
        .onChange(of: state.expanded) { expanded in
            if !expanded { hint = nil }
        }
    }

    private var columns: some View {
        HStack(alignment: .top, spacing: 0) {
            ForEach(Array(store.visibleColumns.enumerated()), id: \.element.id) { index, column in
                if index > 0 {
                    Rectangle()
                        .fill(Theme.divider)
                        .frame(width: 1)
                        .padding(.vertical, 2)
                }
                ColumnView(column: column,
                           onRelogin: state.onRelogin.map { relogin in { relogin(column.id) } })
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 14)
            }
        }
        .padding(.top, 10)
    }
}

/// Подсказка под индикаторами, пока нет ни одной видимой колонки лимитов.
private struct EmptyHint: View {
    @ObservedObject var store: UsageStore

    var body: some View {
        Text(L.t(store.hasHiddenColumns ? "panel.hidden.hint" : "panel.empty.hint"))
            .font(.system(size: 10))
            .foregroundColor(Theme.tertiary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14)
            .padding(.top, 14)
    }
}

private struct FooterView: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState
    let keepAwake: KeepAwake
    let power: PowerMonitor
    @Binding var hint: String?

    var body: some View {
        HStack(alignment: .center, spacing: 5) {
            TimelineView(.periodic(from: .now, by: state.expanded ? 1 : 600)) { context in
                Text(footerText(now: context.date))
                    .font(.system(size: 10))
                    .foregroundColor(Theme.tertiary)
            }
            // Кнопка — сразу за временем обновления: это одно действие про
            // одну цифру, а не отдельный элемент в дальнем углу.
            RefreshButton { store.refreshAll(force: true) }
            Spacer(minLength: 12)
            StatusIndicators(keepAwake: keepAwake, power: power, hint: $hint)
        }
        .padding(.horizontal, 14)
        .padding(.top, 6)
        // Подсказка поверх колонок над капсулами: высоту панели она не меняет.
        .overlay(alignment: .bottomTrailing) {
            if let hint {
                ChipHintBubble(text: hint)
                    .padding(.trailing, 14)
                    .alignmentGuide(.bottom) { $0[.bottom] + 22 }
            }
        }
    }

    private func footerText(now: Date) -> String {
        guard let latest = store.lastUpdatedAt else { return L.t("panel.noData") }
        return L.t("panel.updated", Format.age(latest, now: now))
    }
}

/// Обновить сейчас: лёгкая иконка сразу за «Обновлено … назад», в тон тексту.
/// Без подложки — рядом с мелкой строкой плашка смотрелась кривой. Отклик
/// на наведение — цветом и едва заметным кругом.
private struct RefreshButton: View {
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: "arrow.clockwise")
                .font(.system(size: 9.5, weight: .semibold))
                .foregroundColor(hovering ? Theme.primary : Theme.tertiary)
                .frame(width: 18, height: 18)
                .background(Circle().fill(Color.white.opacity(hovering ? 0.1 : 0)))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(L.t("panel.refresh.help"))
        .reportsControlFrame()
    }
}
