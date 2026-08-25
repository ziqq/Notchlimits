import AppKit

/// Геометрия выреза (челки) на активном экране.
struct NotchGeometry: Equatable {
    let screenFrame: CGRect
    let hasNotch: Bool
    /// Прямоугольник выреза в глобальных координатах (origin снизу-слева).
    let notchRect: CGRect

    static let fallbackSize = CGSize(width: 190, height: 30)

    /// Экран с челкой, иначе — экран с курсором, иначе — главный.
    static func currentScreen() -> NSScreen? {
        if let notched = NSScreen.screens.first(where: { $0.safeAreaInsets.top > 0 }) {
            return notched
        }
        let mouse = NSEvent.mouseLocation
        if let under = NSScreen.screens.first(where: { $0.frame.contains(mouse) }) {
            return under
        }
        return NSScreen.main ?? NSScreen.screens.first
    }

    static func current() -> NotchGeometry {
        guard let screen = currentScreen() else {
            let f = CGRect(x: 0, y: 0, width: 1440, height: 900)
            return NotchGeometry(screenFrame: f, hasNotch: false, notchRect: centered(fallbackSize, in: f))
        }
        let frame = screen.frame
        let top = screen.safeAreaInsets.top

        if top > 0 {
            let height = top
            var width = fallbackSize.width
            if let left = screen.auxiliaryTopLeftArea, let right = screen.auxiliaryTopRightArea {
                let candidate = frame.width - left.width - right.width
                if candidate > 40 { width = candidate }
            }
            let rect = CGRect(x: frame.midX - width / 2,
                              y: frame.maxY - height,
                              width: width,
                              height: height)
            return NotchGeometry(screenFrame: frame, hasNotch: true, notchRect: rect)
        }

        return NotchGeometry(screenFrame: frame, hasNotch: false, notchRect: centered(fallbackSize, in: frame))
    }

    private static func centered(_ size: CGSize, in frame: CGRect) -> CGRect {
        CGRect(x: frame.midX - size.width / 2,
               y: frame.maxY - size.height,
               width: size.width,
               height: size.height)
    }

    /// Раскрытая рамка окна: прижата к верху экрана, отцентрована по вырезу.
    func expandedRect(columnCount: Int) -> CGRect {
        let size = expandedSize(columnCount: columnCount)
        return CGRect(x: screenFrame.midX - size.width / 2,
                      y: screenFrame.maxY - size.height,
                      width: size.width,
                      height: size.height)
    }

    func expandedSize(columnCount: Int) -> CGSize {
        let byColumns = CGFloat(max(columnCount, 1)) * Layout.columnWidth
        let width = min(max(Layout.minPanelWidth, byColumns), screenFrame.width - 40)
        return CGSize(width: width, height: notchRect.height + Layout.contentHeight)
    }
}

enum Layout {
    static let minPanelWidth: CGFloat = 500
    static let columnWidth: CGFloat = 250
    /// Минимальная высота содержимого. Если колонки переросли её из-за
    /// переносов в названиях окон, панель становится выше.
    static let contentHeight: CGFloat = 252
    static let maxContentHeight: CGFloat = 560
    static let columnsFooterGap: CGFloat = 6
    static let footerHeight: CGFloat = 24
    static let contentBottomPadding: CGFloat = 10
    static let collapsedCornerRadius: CGFloat = 8
    static let expandedCornerRadius: CGFloat = 20
}
