import SwiftUI

struct ColumnView: View {
    let column: AccountColumn

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(column.header)
                .font(.system(size: 9.5, weight: .semibold))
                .kerning(1.3)
                .foregroundColor(Theme.secondary)
                .lineLimit(1)

            if let subtitle = column.subtitle, !subtitle.isEmpty {
                Text(subtitle)
                    .font(.system(size: 9))
                    .foregroundColor(Theme.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.top, 2)
            }

            Spacer().frame(height: 10)

            if column.hasData {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(column.windows) { window in
                        LimitRowView(window: window)
                    }
                }
                if let note = staleNote {
                    Text(note)
                        .font(.system(size: 9))
                        .foregroundColor(Theme.tertiary)
                        .padding(.top, 8)
                }
            } else {
                PlaceholderView(status: column.status)
            }

            Spacer(minLength: 0)
        }
    }

    /// Серая пометка о возрасте данных: показываем, когда свежего ответа нет.
    private var staleNote: String? {
        guard let updatedAt = column.updatedAt else { return nil }
        switch column.status {
        case .ok where !column.fromCache:
            return nil
        default:
            return L.t("column.stale", Format.age(updatedAt))
        }
    }
}

private struct PlaceholderView: View {
    let status: ColumnStatus

    var body: some View {
        switch status {
        case .loading, .waiting, .ok:
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.small)
                    .scaleEffect(0.6)
                    .frame(width: 12, height: 12)
                Text(L.t("column.updating"))
                    .font(.system(size: 10))
                    .foregroundColor(Theme.tertiary)
            }
        case .reauth(let message):
            Text(message)
                .font(.system(size: 10.5))
                .foregroundColor(Theme.yellow.opacity(0.9))
                .fixedSize(horizontal: false, vertical: true)
        case .failed(let message):
            Text(message)
                .font(.system(size: 10.5))
                .foregroundColor(Theme.red.opacity(0.9))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct LimitRowView: View {
    let window: LimitWindow

    private var fraction: Double { min(max(window.utilization / 100, 0), 1) }
    private var color: Color { Theme.color(for: window.utilization) }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                // Названия вроде «GPT-5.3-Codex-Spark · Недельное окно» длиннее
                // колонки, поэтому переносим их, а не режем многоточием.
                Text(window.title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(Theme.primary)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                Text(Format.percent(window.utilization))
                    .font(.system(size: 11, weight: .semibold).monospacedDigit())
                    .foregroundColor(color)
                    .fixedSize()
                    // Проценты не сжимаем: переносится заголовок.
                    .layoutPriority(1)
            }

            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.track)
                    Capsule()
                        .fill(color)
                        .frame(width: max(fraction > 0 ? 3 : 0, proxy.size.width * fraction))
                }
            }
            .frame(height: 5)

            if let resetsAt = window.resetsAt {
                Text(Format.reset(resetsAt))
                    .font(.system(size: 9.5))
                    .foregroundColor(Theme.tertiary)
            }
        }
    }
}
