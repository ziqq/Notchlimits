import SwiftUI

/// Визуальное состояние панели, общее для AppKit-контроллера и SwiftUI-вида.
final class PanelState: ObservableObject {
    @Published var expanded = false
    @Published var pinned = false
    @Published var geometry = NotchGeometry.current()
    @Published var expandedSize = CGSize(width: Layout.minPanelWidth,
                                         height: Layout.contentHeight + 32)

    /// Значки включённых режимов Keep Awake для свёрнутой панели.
    @Published var indicatorSymbols: [String] = []

    var notchSize: CGSize { geometry.notchRect.size }
    var hasNotch: Bool { geometry.hasNotch }

    /// «Ушко» слева от выреза под значки Keep Awake: справа от челки живут
    /// системные значки строки меню, а слева обычно пусто.
    var earWidth: CGFloat {
        indicatorSymbols.isEmpty ? 0 : CGFloat(indicatorSymbols.count) * Layout.earIconSpacing + Layout.earPadding
    }

    /// Рамка свёрнутого окна: вырез и ушко слева от него. Справа окно не
    /// расширяем — там системные значки, их нельзя ни закрывать, ни перехватывать.
    var collapsedRect: CGRect {
        var rect = geometry.notchRect
        rect.origin.x -= earWidth
        rect.size.width += earWidth
        return rect
    }
    var collapsedSize: CGSize { collapsedRect.size }

    /// Окно сейчас в раскрытой рамке (она отцентрована по экрану). Пока панель
    /// свёрнута, а рамка ещё раскрытая, свёрнутую форму сдвигаем на пол-ушка
    /// влево — так она стоит ровно над вырезом и в начале, и в конце анимации.
    @Published var windowExpanded = false
    var collapsedOffset: CGFloat { !expanded && windowExpanded ? -earWidth / 2 : 0 }

    /// Сообщение из вёрстки о фактической высоте колонок.
    var onColumnsHeightChange: ((CGFloat) -> Void)?
    /// Нажатие на чип re-auth в колонке: id колонки.
    var onRelogin: ((String) -> Void)?
    /// Рамки кнопок в координатах окна (origin сверху-слева). Клик по ним —
    /// действие кнопки, а не закрепление/закрытие панели.
    var controlFrames: [CGRect] = []
}
