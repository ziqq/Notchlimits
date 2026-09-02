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

            // Строку подзаголовка резервируем всегда — даже когда её нет.
            // Иначе колонка с почтой (Codex) уезжает вниз относительно
            // колонки без неё (Claude), и первые строки лимитов не совпадают.
            Text(column.subtitle?.isEmpty == false ? column.subtitle! : " ")
                .font(.system(size: 9))
                .foregroundColor(Theme.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .padding(.top, 2)
                .opacity(column.subtitle?.isEmpty == false ? 1 : 0)

            Spacer().frame(height: 10)

            if column.hasData {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(column.windows) { window in
                        LimitRowView(window: window)
                    }
                }
                if !column.stats.isEmpty {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(column.stats) { stat in
                            HStack(spacing: 6) {
                                Text(stat.label)
                                    .font(.system(size: 9.5))
                                    .foregroundColor(Theme.tertiary)
                                    .lineLimit(1)
                                Spacer(minLength: 4)
                                Text(stat.value)
                                    .font(.system(size: 9.5, weight: .medium).monospacedDigit())
                                    .foregroundColor(Theme.secondary)
                                    .fixedSize()
                            }
                        }
                    }
                    .padding(.top, 10)
                }

                // Причину, по которой данные замерли, показываем прямо над
                // возрастом: иначе протухший токен выглядит просто как старые
                // цифры, и непонятно, что надо перелогиниться.
                if let problem = Self.problem(for: column.status) {
                    Text(problem.message)
                        .font(.system(size: 9.5))
                        .foregroundColor(problem.color)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 8)
                }
                if let note = staleNote {
                    Text(note)
                        .font(.system(size: 9))
                        .foregroundColor(Theme.tertiary)
                        .padding(.top, Self.problem(for: column.status) == nil ? 8 : 2)
                }
            } else {
                PlaceholderView(status: column.status)
            }

            Spacer(minLength: 0)
        }
    }

    /// Сообщение о проблеме, которую видно даже поверх кэша.
    /// 429 сюда не попадает — это ожидание, а не поломка.
    static func problem(for status: ColumnStatus) -> (message: String, color: Color)? {
        switch status {
        case .reauth(let message): return (message, Theme.yellow.opacity(0.9))
        case .failed(let message): return (message, Theme.red.opacity(0.9))
        case .ok, .loading, .waiting: return nil
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
        if let problem = ColumnView.problem(for: status) {
            Text(problem.message)
                .font(.system(size: 10.5))
                .foregroundColor(problem.color)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.small)
                    .scaleEffect(0.6)
                    .frame(width: 12, height: 12)
                Text(L.t("column.updating"))
                    .font(.system(size: 10))
                    .foregroundColor(Theme.tertiary)
            }
        }
    }
}

struct LimitRowView: View {
    let window: LimitWindow

    private var fraction: Double { min(max(window.utilization / 100, 0), 1) }
    private var color: Color { Theme.color(for: window.utilization) }

    /// Спарклайн показываем, только когда есть что показывать: хотя бы три
    /// замера и заметное движение, иначе это просто плоская линия-шум.
    private var trend: [Double]? {
        guard let trend = window.trend, trend.count >= 3,
              let lo = trend.min(), let hi = trend.max(), hi - lo > 1 else { return nil }
        return trend
    }

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
                if let trend {
                    Sparkline(values: trend)
                        .stroke(color.opacity(0.7), style: StrokeStyle(lineWidth: 1.3,
                                                                       lineCap: .round, lineJoin: .round))
                        .frame(width: 34, height: 12)
                        .layoutPriority(1)
                }
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
            // Прогноз: упрёмся в предел раньше сброса — предупреждаем.
            // Цвет тревожный независимо от текущего процента (в том и смысл:
            // сейчас мало, но при таком темпе не хватит). Совсем скоро — красный.
            if let exhaustsAt = window.exhaustsAt {
                Text(L.t("burn.limitAt", Format.resetAbsolute(exhaustsAt)))
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(exhaustsAt.timeIntervalSinceNow < 45 * 60 ? Theme.red : Theme.yellow)
            }
        }
        // При наведении — точный момент сброса: «сегодня, 13:30».
        .help(window.resetsAt.map(Format.resetAbsolute) ?? "")
    }
}

/// Спарклайн процентов. Шкала жёстко 0–100, чтобы крутизна линии отражала
/// реальный темп, а не автомасштаб: 2 %→3 % должно выглядеть почти плоско.
struct Sparkline: Shape {
    let values: [Double]

    func path(in rect: CGRect) -> Path {
        var path = Path()
        guard values.count >= 2 else { return path }
        let stepX = rect.width / CGFloat(values.count - 1)
        func point(_ index: Int) -> CGPoint {
            let clamped = min(max(values[index], 0), 100) / 100
            return CGPoint(x: rect.minX + CGFloat(index) * stepX,
                           y: rect.maxY - CGFloat(clamped) * rect.height)
        }
        path.move(to: point(0))
        for index in 1..<values.count { path.addLine(to: point(index)) }
        return path
    }
}
