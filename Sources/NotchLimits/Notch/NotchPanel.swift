import AppKit
import SwiftUI

/// Панель, которая живёт вплотную к верхней кромке экрана.
///
/// AppKit по умолчанию не пускает окна под меню-бар: `constrainFrameRect(_:to:)`
/// сдвигает рамку вниз, и панель перестаёт прилипать к челке. Переопределение
/// возвращает рамку как есть.
final class NotchPanel: NSPanel {

    init(contentRect: NSRect) {
        super.init(contentRect: contentRect,
                   styleMask: [.borderless, .nonactivatingPanel],
                   backing: .buffered,
                   defer: false)

        isOpaque = false
        backgroundColor = .clear
        hasShadow = false
        isMovable = false
        isMovableByWindowBackground = false
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        acceptsMouseMovedEvents = true
        ignoresMouseEvents = false
        isFloatingPanel = true
        becomesKeyOnlyIfNeeded = true

        // .statusBar+1 на свежих macOS оказывается НИЖЕ пунктов меню-бара.
        level = .popUpMenu
        collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
    }

    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }

    override func constrainFrameRect(_ frameRect: NSRect, to screen: NSScreen?) -> NSRect {
        frameRect
    }
}

/// Хост SwiftUI, который перехватывает правый клик и показывает контекстное меню
/// панели, не отдавая событие внутрь иерархии SwiftUI.
final class NotchHostingView<Content: View>: NSHostingView<Content> {
    var onRightClick: ((NSEvent) -> Void)?

    required init(rootView: Content) {
        super.init(rootView: rootView)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func rightMouseDown(with event: NSEvent) {
        onRightClick?(event)
    }

    /// Окно само стоит поверх выреза, поэтому никакой safe area внутри быть
    /// не должно: иначе AppKit сдвинет содержимое ещё на высоту челки.
    override var safeAreaInsets: NSEdgeInsets {
        NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0)
    }

    /// Снимок собственного окна — не требует разрешения «Запись экрана».
    func snapshotPNG() -> Data? {
        guard let rep = bitmapImageRepForCachingDisplay(in: bounds) else { return nil }
        cacheDisplay(in: bounds, to: rep)
        return rep.representation(using: .png, properties: [:])
    }
}
