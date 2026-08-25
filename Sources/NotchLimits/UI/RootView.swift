import SwiftUI

struct RootView: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState

    private var shapeWidth: CGFloat { state.expanded ? state.expandedSize.width : state.notchSize.width }
    private var shapeHeight: CGFloat { state.expanded ? state.expandedSize.height : state.notchSize.height }
    private var cornerRadius: CGFloat {
        state.expanded ? Layout.expandedCornerRadius : Layout.collapsedCornerRadius
    }

    var body: some View {
        ZStack(alignment: .top) {
            ZStack(alignment: .top) {
                BottomRoundedRectangle(radius: cornerRadius)
                    .fill(Theme.panelBackground)

                CollapsedContent(store: store, state: state)
                    .frame(width: state.notchSize.width, height: state.notchSize.height)
                    .opacity(state.expanded ? 0 : 1)

                ExpandedContent(store: store, state: state)
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

    var body: some View {
        VStack(spacing: 0) {
            // Зона выреза — под ней ничего не рисуем.
            Color.clear.frame(height: state.notchSize.height)

            if store.visibleColumns.isEmpty {
                EmptyStateView(store: store)
            } else {
                HStack(alignment: .top, spacing: 0) {
                    ForEach(Array(store.visibleColumns.enumerated()), id: \.element.id) { index, column in
                        if index > 0 {
                            Rectangle()
                                .fill(Theme.divider)
                                .frame(width: 1)
                                .padding(.vertical, 2)
                        }
                        ColumnView(column: column)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 14)
                    }
                }
                .padding(.top, 10)
                // Высоту колонок меряем здесь и по ней растим окно, иначе
                // перенесённые строки упёрлись бы в нижнюю кромку панели.
                .background(
                    GeometryReader { proxy in
                        Color.clear.preference(key: ColumnsHeightKey.self,
                                               value: proxy.size.height)
                    }
                )
            }

            Spacer(minLength: Layout.columnsFooterGap)

            FooterView(store: store, state: state)
        }
        .padding(.horizontal, 6)
        .padding(.bottom, 10)
    }
}

private struct EmptyStateView: View {
    @ObservedObject var store: UsageStore

    var body: some View {
        VStack(spacing: 8) {
            Text(L.t(store.hasHiddenColumns ? "panel.hidden.title" : "panel.empty.title"))
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(Theme.primary)
            Text(L.t(store.hasHiddenColumns ? "panel.hidden.hint" : "panel.empty.hint"))
                .font(.system(size: 11))
                .foregroundColor(Theme.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 340)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct FooterView: View {
    @ObservedObject var store: UsageStore
    @ObservedObject var state: PanelState

    var body: some View {
        HStack(spacing: 8) {
            TimelineView(.periodic(from: .now, by: state.expanded ? 1 : 600)) { context in
                Text(footerText(now: context.date))
                    .font(.system(size: 10))
                    .foregroundColor(Theme.tertiary)
            }
            Spacer(minLength: 8)
            Button {
                store.refreshAll(force: true)
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(Theme.secondary)
                    .frame(width: 22, height: 18)
                    .background(
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .fill(Color.white.opacity(0.08))
                    )
            }
            .buttonStyle(.plain)
            .help(L.t("panel.refresh.help"))
        }
        .padding(.horizontal, 14)
        .padding(.top, 6)
    }

    private func footerText(now: Date) -> String {
        guard let latest = store.lastUpdatedAt else { return L.t("panel.noData") }
        return L.t("panel.updated", Format.age(latest, now: now))
    }
}
