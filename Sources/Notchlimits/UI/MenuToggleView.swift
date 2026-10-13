import AppKit

/// Переключатель внутри NSMenu: нажатие кнопки не завершает отслеживание меню.
@MainActor
final class MenuToggleView: NSButton {
    private weak var item: NSMenuItem?
    private var hoverTracking: NSTrackingArea?
    private var hovering = false

    init(item: NSMenuItem) {
        self.item = item
        let font = NSFont.menuFont(ofSize: 0)
        let width = (item.title as NSString).size(withAttributes: [.font: font]).width + 38
        super.init(frame: NSRect(x: 0, y: 0, width: ceil(width), height: 22))
        title = item.title
        self.font = font
        setButtonType(.switch)
        state = item.state
        isBordered = false
        autoresizingMask = [.width]
        target = self
        action = #selector(activate)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverTracking { removeTrackingArea(hoverTracking) }
        let tracking = NSTrackingArea(rect: .zero,
                                      options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
                                      owner: self)
        addTrackingArea(tracking)
        hoverTracking = tracking
    }

    override func mouseEntered(with event: NSEvent) {
        hovering = true
        needsDisplay = true
    }

    override func mouseExited(with event: NSEvent) {
        hovering = false
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let highlighted = hovering || enclosingMenuItem?.isHighlighted == true || cell?.isHighlighted == true
        if highlighted {
            NSColor.selectedContentBackgroundColor.setFill()
            NSBezierPath(roundedRect: bounds, xRadius: 5, yRadius: 5).fill()
        }
        let textColor = highlighted ? NSColor.selectedMenuItemTextColor : NSColor.labelColor
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font ?? NSFont.menuFont(ofSize: 0), .foregroundColor: textColor
        ]
        let titleSize = (title as NSString).size(withAttributes: attributes)
        (title as NSString).draw(at: NSPoint(x: 22, y: (bounds.height - titleSize.height) / 2),
                                withAttributes: attributes)
        if state == .on {
            ("✓" as NSString).draw(at: NSPoint(x: 5, y: (bounds.height - titleSize.height) / 2),
                                  withAttributes: attributes)
        }
    }

    @objc private func activate() {
        guard let item, let action = item.action else { return }
        NSApp.sendAction(action, to: item.target, from: item)
        state = item.state
        needsDisplay = true
    }
}
