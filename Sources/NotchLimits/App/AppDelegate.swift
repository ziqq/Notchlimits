import AppKit
import Carbon.HIToolbox

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    private var store: UsageStore!
    private var panel: PanelController!
    private var hotKeys: HotKeyManager!

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        if DebugRender.runIfRequested() { return }
        if DebugProbe.runIfRequested() { return }

        let useMock = ProcessInfo.processInfo.environment["NOTCHLIMITS_MOCK"] == "1"
        let discovery: AccountDiscovery = useMock ? MockDiscovery() : RealDiscovery()
        let providers: [Provider: UsageProvider] = useMock
            ? [.claude: MockProvider(), .codex: MockProvider()]
            : [.claude: ClaudeProvider(), .codex: CodexProvider()]

        store = UsageStore(providers: providers, discovery: discovery)
        panel = PanelController(store: store)

        store.onColumnsChanged = { [weak self] in self?.panel.recomputeExpandedSize() }
        panel.onWillOpen = { [weak self] in self?.store.refreshStale() }
        panel.onContextMenu = { [weak self] event, view in
            self?.showContextMenu(event: event, view: view)
        }

        panel.install()
        store.start()
        ThresholdNotifier.requestAuthorization()

        if let path = ProcessInfo.processInfo.environment["NOTCHLIMITS_SNAPSHOT"] {
            panel.holdOpen(true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
                if let data = self?.panel.snapshotPNG() {
                    try? data.write(to: URL(fileURLWithPath: path))
                    print("snapshot -> \(path)")
                }
                exit(0)
            }
        }

        // Открытие панели с клавиатуры. Carbon-хоткей не требует Accessibility.
        hotKeys = HotKeyManager { [weak self] in self?.panel.toggle() }
    }

    // MARK: - Контекстное меню

    private func showContextMenu(event: NSEvent, view: NSView) {
        // Пока меню на экране, панель не должна схлопываться под ним.
        panel.holdOpen(true)
        defer { panel.holdOpen(false) }

        let menu = NSMenu()
        menu.autoenablesItems = false

        menu.addItem(item(L.t("menu.refresh"), #selector(refresh)))
        menu.addItem(.separator())
        menu.addItem(item(L.t("menu.addClaude"), #selector(addClaude)))
        menu.addItem(item(L.t("menu.addCodex"), #selector(addCodex)))
        menu.addItem(.separator())

        let hideItem = NSMenuItem(title: L.t("menu.hideColumn"), action: nil, keyEquivalent: "")
        let hideSubmenu = NSMenu()
        let visible = store.visibleColumns
        if visible.isEmpty {
            let empty = NSMenuItem(title: L.t("menu.noColumns"), action: nil, keyEquivalent: "")
            empty.isEnabled = false
            hideSubmenu.addItem(empty)
        } else {
            for column in visible {
                let entry = item(column.header, #selector(hideColumn(_:)))
                entry.representedObject = column.id
                hideSubmenu.addItem(entry)
            }
        }
        hideItem.submenu = hideSubmenu
        hideItem.isEnabled = !visible.isEmpty
        menu.addItem(hideItem)

        let renameItem = NSMenuItem(title: L.t("menu.renameColumn"), action: nil, keyEquivalent: "")
        let renameSubmenu = NSMenu()
        if visible.isEmpty {
            let empty = NSMenuItem(title: L.t("menu.noColumns"), action: nil, keyEquivalent: "")
            empty.isEnabled = false
            renameSubmenu.addItem(empty)
        } else {
            for column in visible {
                let entry = item(column.header, #selector(renameColumn(_:)))
                entry.representedObject = column.id
                renameSubmenu.addItem(entry)
            }
        }
        renameItem.submenu = renameSubmenu
        renameItem.isEnabled = !visible.isEmpty
        menu.addItem(renameItem)

        let showAll = item(L.t("menu.showHidden"), #selector(showAllColumns))
        showAll.isEnabled = store.hasHiddenColumns
        menu.addItem(showAll)

        menu.addItem(.separator())

        let hotKeyItem = NSMenuItem(title: L.t("menu.hotKey", hotKeys.displayName),
                                    action: nil, keyEquivalent: "")
        let hotKeySubmenu = NSMenu()
        hotKeySubmenu.addItem(item(L.t("menu.hotKey.change"), #selector(changeHotKey)))
        let standard = item(L.t("menu.hotKey.standard"), #selector(resetHotKey),
                            state: hotKeys.isStandard ? .on : .off)
        hotKeySubmenu.addItem(standard)
        hotKeySubmenu.addItem(.separator())
        hotKeySubmenu.addItem(item(L.t("menu.hotKey.disable"), #selector(disableHotKey),
                                   state: hotKeys.config == nil ? .on : .off))
        hotKeyItem.submenu = hotKeySubmenu
        menu.addItem(hotKeyItem)

        menu.addItem(item(L.t("menu.loginItem"), #selector(toggleLoginItem),
                          state: LoginItem.isEnabled ? .on : .off))
        menu.addItem(.separator())
        menu.addItem(item(L.t("menu.quit"), #selector(quit)))

        NSMenu.popUpContextMenu(menu, with: event, for: view)
    }

    private func item(_ title: String,
                      _ action: Selector,
                      state: NSControl.StateValue = .off) -> NSMenuItem {
        let menuItem = NSMenuItem(title: title, action: action, keyEquivalent: "")
        menuItem.target = self
        menuItem.state = state
        menuItem.isEnabled = true
        return menuItem
    }

    // MARK: - Действия

    @objc private func refresh() {
        store.rediscover(force: true)
        store.refreshAll(force: true)
    }

    @objc private func addClaude() {
        AccountSetup.addClaude { [weak self] in self?.store.rediscover(force: true) }
    }

    @objc private func addCodex() {
        AccountSetup.addCodex { [weak self] in self?.store.rediscover(force: true) }
    }

    @objc private func hideColumn(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        store.setHidden(id, hidden: true)
    }

    @objc private func renameColumn(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String,
              let column = store.columns.first(where: { $0.id == id }) else { return }

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = L.t("rename.title")
        alert.informativeText = L.t("rename.hint", column.profileName)
        alert.addButton(withTitle: L.t("common.save"))
        alert.addButton(withTitle: L.t("common.cancel"))

        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.stringValue = column.customName ?? ""
        field.placeholderString = column.profileName
        alert.accessoryView = field
        alert.window.initialFirstResponder = field

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        store.setCustomName(field.stringValue, for: id)
    }

    @objc private func showAllColumns() {
        store.showAllColumns()
    }

    @objc private func changeHotKey() {
        guard let config = HotKeyRecorder.record(current: hotKeys.config) else { return }
        guard hotKeys.apply(config) else {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = L.t("hotkey.taken.title", config.display)
            alert.informativeText = L.t("hotkey.taken.body")
            alert.addButton(withTitle: L.t("common.ok"))
            alert.runModal()
            return
        }
    }

    @objc private func resetHotKey() {
        hotKeys.apply(.standard)
    }

    @objc private func disableHotKey() {
        hotKeys.apply(nil)
    }

    @objc private func toggleLoginItem() {
        LoginItem.toggle()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
