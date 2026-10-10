import SwiftUI

/// Визуальное состояние панели, общее для AppKit-контроллера и SwiftUI-вида.
final class PanelState: ObservableObject {
    @Published var expanded = false
    @Published var pinned = false
    @Published var geometry = NotchGeometry.current()
    @Published var expandedSize = CGSize(width: Layout.minPanelWidth,
                                         height: Layout.contentHeight + 32)
    /// Включён «Не давать Mac уснуть»: свёрнутая панель показывает индикатор.
    @Published var keepAwakeIndicator = false

    var notchSize: CGSize { geometry.notchRect.size }
    var hasNotch: Bool { geometry.hasNotch }

    /// Свёрнутая рамка. На маке с челкой индикатор не влезает в сам вырез,
    /// поэтому рамка расширяется «ушками» по обе стороны — симметрично, чтобы
    /// анимация раскрытия оставалась отцентрованной по вырезу.
    var collapsedRect: CGRect {
        let notch = geometry.notchRect
        guard keepAwakeIndicator else { return notch }
        return notch.insetBy(dx: -Layout.earWidth, dy: 0)
    }

    var collapsedSize: CGSize { collapsedRect.size }

    /// Сообщение из вёрстки о фактической высоте колонок.
    var onColumnsHeightChange: ((CGFloat) -> Void)?
    /// Нажатие на чип re-auth в колонке: id колонки.
    var onRelogin: ((String) -> Void)?
    /// Рамки кнопок в координатах окна (origin сверху-слева). Клик по ним —
    /// действие кнопки, а не закрепление/закрытие панели.
    var controlFrames: [CGRect] = []
}
