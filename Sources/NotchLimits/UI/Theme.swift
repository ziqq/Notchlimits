import SwiftUI

enum Theme {
    static let panelBackground = Color.black
    static let primary = Color.white
    static let secondary = Color.white.opacity(0.55)
    static let tertiary = Color.white.opacity(0.35)
    static let track = Color.white.opacity(0.12)
    static let divider = Color.white.opacity(0.10)

    static let green = Color(red: 0.30, green: 0.84, blue: 0.47)
    static let yellow = Color(red: 0.98, green: 0.77, blue: 0.22)
    static let red = Color(red: 0.98, green: 0.36, blue: 0.33)

    /// Зелёный < 60 %, жёлтый 60–85 %, красный > 85 %.
    static func color(for utilization: Double) -> Color {
        switch utilization {
        case ..<60: return green
        case ..<85.000001: return yellow
        default: return red
        }
    }
}

/// Прямоугольник со скруглением только снизу: верх панели всегда прижат
/// к кромке экрана, скруглять его нечем.
struct BottomRoundedRectangle: Shape {
    var radius: CGFloat

    var animatableData: CGFloat {
        get { radius }
        set { radius = newValue }
    }

    func path(in rect: CGRect) -> Path {
        var path = Path()
        let r = max(0, min(radius, min(rect.width, rect.height) / 2))
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - r))
        path.addQuadCurve(to: CGPoint(x: rect.maxX - r, y: rect.maxY),
                          control: CGPoint(x: rect.maxX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX + r, y: rect.maxY))
        path.addQuadCurve(to: CGPoint(x: rect.minX, y: rect.maxY - r),
                          control: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

enum Format {
    /// Время до сброса окна. Единицы сокращённые — так строка не зависит
    /// от правил множественного числа ни в одном из поддерживаемых языков.
    static func reset(_ date: Date, now: Date = Date()) -> String {
        let seconds = Int(date.timeIntervalSince(now))
        guard seconds > 0 else { return L.t("reset.imminent") }
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return L.t("reset.days", days, hours) }
        if hours > 0 { return L.t("reset.hours", hours, minutes) }
        return L.t("reset.minutes", max(minutes, 1))
    }

    /// Возраст данных: «12 с назад», «3 мин назад», «2 ч назад».
    static func age(_ date: Date, now: Date = Date()) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(date)))
        if seconds < 5 { return L.t("age.justNow") }
        if seconds < 60 { return L.t("age.seconds", seconds) }
        if seconds < 3_600 { return L.t("age.minutes", seconds / 60) }
        if seconds < 86_400 { return L.t("age.hours", seconds / 3_600) }
        return L.t("age.days", seconds / 86_400)
    }

    /// Проценты: во французском и немецком перед знаком нужен пробел.
    static func percent(_ value: Double) -> String {
        L.t("format.percent", Int(value.rounded()))
    }
}
/// Высота блока колонок, измеренная SwiftUI: по ней подбирается высота окна.
struct ColumnsHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
