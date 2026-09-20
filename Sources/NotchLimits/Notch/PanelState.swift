import SwiftUI

/// Визуальное состояние панели, общее для AppKit-контроллера и SwiftUI-вида.
final class PanelState: ObservableObject {
    @Published var expanded = false
    @Published var pinned = false
    @Published var geometry = NotchGeometry.current()
    @Published var expandedSize = CGSize(width: Layout.minPanelWidth,
                                         height: Layout.contentHeight + 32)

    /// Материал Liquid Glass вместо сплошного фона (macOS 26+). По умолчанию
    /// включён; можно выключить в меню. Хранится в UserDefaults.
    @Published var liquidGlass: Bool = (UserDefaults.standard.object(forKey: "liquidGlassEnabled") as? Bool) ?? true {
        didSet { UserDefaults.standard.set(liquidGlass, forKey: "liquidGlassEnabled") }
    }

    var notchSize: CGSize { geometry.notchRect.size }
    var hasNotch: Bool { geometry.hasNotch }

    /// Сообщение из вёрстки о фактической высоте колонок.
    var onColumnsHeightChange: ((CGFloat) -> Void)?
}
