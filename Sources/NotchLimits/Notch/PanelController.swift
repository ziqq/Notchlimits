import AppKit
import Combine
import SwiftUI

/// Открытие/закрытие панели: hover-мониторы, анимации, клик-пин, Esc.
@MainActor
final class PanelController {

    let state = PanelState()
    private let store: UsageStore
    private let keepAwake: KeepAwake
    private var keepAwakeObserver: AnyCancellable?
    private var panel: NotchPanel!
    private var hosting: NotchHostingView<RootView>!

    private var globalMonitor: Any?
    private var localMonitor: Any?
    private var safetyTimer: Timer?
    private var escHotKey: HotKey?

    private var closeWork: DispatchWorkItem?
    private var shrinkWork: DispatchWorkItem?

    /// Задержки из спецификации анимации.
    private enum Timing {
        static let closeDelay: TimeInterval = 0.1
        static let shrinkDelay: TimeInterval = 0.35
        static let openSpring = Animation.spring(response: 0.32, dampingFraction: 0.82)
        static let closeCurve = Animation.easeInOut(duration: 0.22)
    }

    var onContextMenu: ((NSEvent, NSView) -> Void)?
    var onWillOpen: (() -> Void)?

    init(store: UsageStore, keepAwake: KeepAwake) {
        self.store = store
        self.keepAwake = keepAwake
    }

    // MARK: - Жизненный цикл

    func install() {
        state.geometry = NotchGeometry.current()
        state.expandedSize.height = state.geometry.notchRect.height + Layout.contentHeight
        state.onColumnsHeightChange = { [weak self] height in
            self?.applyColumnsHeight(height)
        }
        recomputeExpandedSize()

        let root = RootView(store: store, state: state, keepAwake: keepAwake)
        hosting = NotchHostingView(rootView: root)
        hosting.onRightClick = { [weak self] event in
            guard let self else { return }
            self.onContextMenu?(event, self.hosting)
        }

        state.keepAwakeIndicator = keepAwake.isActive
        panel = NotchPanel(contentRect: state.collapsedRect)
        panel.contentView = hosting
        panel.setFrame(state.collapsedRect, display: true)
        panel.orderFrontRegardless()

        startMonitors()
        observeScreenChanges()
        observeKeepAwake()
    }

    /// Индикатор в свёрнутой панели меняет её ширину: рамку окна подгоняем,
    /// только пока панель свёрнута — раскрытую рамку он не трогает.
    private func observeKeepAwake() {
        keepAwakeObserver = keepAwake.$isActive
            .removeDuplicates()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] active in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    withAnimation(Timing.openSpring) { self.state.keepAwakeIndicator = active }
                    if !self.state.expanded {
                        self.panel.setFrame(self.state.collapsedRect, display: true)
                    }
                }
            }
    }

    private func observeScreenChanges() {
        NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenParametersChanged() }
        }
    }

    private func screenParametersChanged() {
        state.geometry = NotchGeometry.current()
        recomputeExpandedSize()
        panel.setFrame(state.expanded ? expandedRect() : state.collapsedRect, display: true)
    }

    /// Ширина зависит от числа колонок. Высоту сюда не трогаем — её задаёт
    /// фактический размер колонок, см. `applyColumnsHeight(_:)`.
    func recomputeExpandedSize() {
        let width = state.geometry.expandedSize(columnCount: store.visibleColumns.count).width
        guard abs(width - state.expandedSize.width) > 0.5 else { return }
        state.expandedSize.width = width
        if state.expanded {
            panel.setFrame(expandedRect(), display: true)
        }
    }

    /// Панель растёт, если названия окон перенеслись на несколько строк.
    private func applyColumnsHeight(_ columnsHeight: CGFloat) {
        guard columnsHeight > 0 else { return }
        let notch = state.geometry.notchRect.height
        // Подвал «Обновлено …» и «Управление» входят в измеренный блок,
        // поэтому панель — ровно по содержимому.
        let needed = columnsHeight + Layout.contentBottomPadding
        let content = min(needed.rounded(.up), Layout.maxContentHeight)
        let height = notch + content
        guard abs(height - state.expandedSize.height) > 0.5 else { return }
        state.expandedSize.height = height
        if state.expanded {
            panel.setFrame(expandedRect(), display: true)
        }
    }

    private func expandedRect() -> CGRect {
        let size = state.expandedSize
        let frame = state.geometry.screenFrame
        return CGRect(x: frame.midX - size.width / 2,
                      y: frame.maxY - size.height,
                      width: size.width,
                      height: size.height)
    }

    // MARK: - Открытие / закрытие

    func open() {
        closeWork?.cancel()
        shrinkWork?.cancel()
        guard !state.expanded else { return }

        onWillOpen?()
        recomputeExpandedSize()
        // Рамка сразу становится раскрытой — иначе анимация обрежется по старому окну.
        panel.setFrame(expandedRect(), display: true)
        panel.orderFrontRegardless()

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            withAnimation(Timing.openSpring) { self.state.expanded = true }
        }
    }

    func close(force: Bool = false) {
        if state.pinned && !force { return }
        closeWork?.cancel()
        guard state.expanded else { return }

        setPinned(false)
        withAnimation(Timing.closeCurve) { state.expanded = false }

        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.state.expanded else { return }
            self.panel.setFrame(self.state.collapsedRect, display: true)
        }
        shrinkWork = work
        // Ужимаем рамку позже конца анимации, чтобы не срезать последние кадры.
        DispatchQueue.main.asyncAfter(deadline: .now() + Timing.shrinkDelay, execute: work)
    }

    func toggle() {
        if state.expanded {
            setPinned(false)
            close(force: true)
        } else {
            open()
            setPinned(true)
        }
    }

    private func scheduleClose() {
        guard state.expanded, !state.pinned, closeWork == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            self?.closeWork = nil
            self?.close()
        }
        closeWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Timing.closeDelay, execute: work)
    }

    private func cancelClose() {
        closeWork?.cancel()
        closeWork = nil
    }

    /// Снимок раскрытой панели для отладки вёрстки.
    func snapshotPNG() -> Data? { hosting.snapshotPNG() }

    /// На время модального диалога опускаем панель под него: она живёт на уровне
    /// `.popUpMenu`, и алерт иначе открывается ПОД ней (NSAlert не даёт поднять
    /// своё окно выше). После диалога уровень возвращаем.
    func setModalSuppression(_ suppressed: Bool) {
        panel.level = suppressed ? .normal : .popUpMenu
    }

    /// Удержание панели раскрытой на время модального взаимодействия (меню, алерт).
    func holdOpen(_ hold: Bool) {
        if hold {
            open()
            state.pinned = true
        } else {
            setPinned(false)
            evaluateHover()
        }
    }

    private func setPinned(_ value: Bool) {
        guard state.pinned != value else { return }
        state.pinned = value
        // Esc перехватываем глобально только пока панель закреплена.
        if value {
            escHotKey = HotKey(keyCode: 53, modifiers: 0) { [weak self] in
                self?.setPinned(false)
                self?.close(force: true)
            }
        } else {
            escHotKey = nil
        }
    }

    // MARK: - Мониторы мыши

    private func startMonitors() {
        panel.acceptsMouseMovedEvents = true

        globalMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.mouseMoved, .leftMouseDown, .rightMouseDown]
        ) { [weak self] event in
            MainActor.assumeIsolated { self?.handleGlobal(event) }
        }

        localMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.mouseMoved, .leftMouseDown]
        ) { [weak self] event in
            MainActor.assumeIsolated { self?.handleLocal(event) }
            return event
        }

        // Страховка: глобальные мониторы молчат, когда курсор в модальном цикле
        // чужого приложения. Тик раз в полсекунды закрывает панель в этом случае.
        safetyTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.evaluateHover() }
        }
    }

    private func handleGlobal(_ event: NSEvent) {
        switch event.type {
        case .mouseMoved:
            evaluateHover()
        case .leftMouseDown, .rightMouseDown:
            // Клик мимо панели снимает закрепление.
            if state.expanded && !panel.frame.contains(NSEvent.mouseLocation) {
                setPinned(false)
                close(force: true)
            }
        default:
            break
        }
    }

    private func handleLocal(_ event: NSEvent) {
        switch event.type {
        case .mouseMoved:
            evaluateHover()
        case .leftMouseDown:
            guard state.expanded, panel.frame.contains(NSEvent.mouseLocation) else { return }
            // Клик по кнопке — это её действие, панель от него не закрепляется
            // и не закрывается (иначе второе нажатие плитки захлопнуло бы панель).
            if isOverControl(NSEvent.mouseLocation) { return }
            setPinned(!state.pinned)
            if !state.pinned { close(force: true) }
        default:
            break
        }
    }

    /// Экранная точка над одной из кнопок панели (`state.controlFrames`).
    private func isOverControl(_ screenPoint: NSPoint) -> Bool {
        guard let content = panel.contentView else { return false }
        let inWindow = panel.convertPoint(fromScreen: screenPoint)
        // SwiftUI меряет рамки от верхнего левого угла, окно — от нижнего.
        let flipped = CGPoint(x: inWindow.x, y: content.bounds.height - inWindow.y)
        return state.controlFrames.contains { $0.contains(flipped) }
    }

    private func evaluateHover() {
        let point = NSEvent.mouseLocation
        if state.expanded {
            guard !state.pinned else { return }
            if panel.frame.contains(point) {
                cancelClose()
            } else {
                scheduleClose()
            }
        } else {
            // Небольшой допуск по бокам: попасть точно в вырез мышью тяжело.
            let zone = state.collapsedRect.insetBy(dx: -4, dy: 0)
            if zone.contains(point) { open() }
        }
    }
}
