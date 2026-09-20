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
        // Диалоги добавления аккаунта тоже должны быть над панелью.
        AccountSetup.suppressPanel = { [weak self] suppressed in
            self?.panel.setModalSuppression(suppressed)
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

        // Удаление доступно и для скрытых колонок, поэтому список — по всем.
        // Плюс незавершённые профили (папка есть, входа нет) — их колонки нет,
        // но удалить надо уметь.
        let removeItem = NSMenuItem(title: L.t("menu.removeColumn"), action: nil, keyEquivalent: "")
        let removeSubmenu = NSMenu()
        let allColumns = store.columns
        let orphans = orphanProfiles()
        if allColumns.isEmpty && orphans.isEmpty {
            let empty = NSMenuItem(title: L.t("menu.noColumns"), action: nil, keyEquivalent: "")
            empty.isEnabled = false
            removeSubmenu.addItem(empty)
        } else {
            for column in allColumns {
                let entry = item(column.header, #selector(removeColumn(_:)))
                entry.representedObject = column.id
                removeSubmenu.addItem(entry)
            }
            if !orphans.isEmpty {
                if !allColumns.isEmpty { removeSubmenu.addItem(.separator()) }
                for orphan in orphans {
                    let entry = item(L.t("remove.incomplete", orphan.label), #selector(removeOrphanProfile(_:)))
                    entry.representedObject = orphan.url.path
                    removeSubmenu.addItem(entry)
                }
            }
        }
        removeItem.submenu = removeSubmenu
        removeItem.isEnabled = !allColumns.isEmpty || !orphans.isEmpty
        menu.addItem(removeItem)

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
        menu.addItem(item(L.t("menu.checkUpdates"), #selector(checkForUpdates)))
        menu.addItem(item(L.t("menu.about"), #selector(showAbout)))
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

        guard runModalAbovePanel(alert) == .alertFirstButtonReturn else { return }
        store.setCustomName(field.stringValue, for: id)
    }

    @objc private func showAllColumns() {
        store.showAllColumns()
    }

    /// Незавершённые профили: папки ~/.codex-profiles / ~/.claude-profiles,
    /// для которых нет колонки (вход не выполнен, поэтому не обнаружены).
    private func orphanProfiles() -> [(label: String, url: URL)] {
        let codexIds = Set(store.columns.filter { $0.provider == .codex }.map(\.id))
        let claudeDirs = Set(store.discoveredAccounts.compactMap { account -> String? in
            if case .claudeKeychain(_, let dir) = account.source { return dir?.path }
            return nil
        })
        var result: [(label: String, url: URL)] = []
        for dir in ProfileDirectories.codexProfiles() where !codexIds.contains("codex:\(dir.lastPathComponent)") {
            result.append(("CODEX · \(dir.lastPathComponent)", dir))
        }
        for dir in ProfileDirectories.claudeProfiles() where !claudeDirs.contains(dir.path) {
            result.append(("CLAUDE · \(dir.lastPathComponent)", dir))
        }
        return result
    }

    @objc private func removeOrphanProfile(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        let url = URL(fileURLWithPath: path)

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = L.t("remove.title", url.lastPathComponent)
        alert.informativeText = L.t("remove.body")
        let deleteButton = alert.addButton(withTitle: L.t("remove.delete"))
        let cancelButton = alert.addButton(withTitle: L.t("common.cancel"))
        deleteButton.hasDestructiveAction = true
        deleteButton.keyEquivalent = ""
        cancelButton.keyEquivalent = "\r"
        guard runModalAbovePanel(alert) == .alertFirstButtonReturn else { return }

        do {
            try FileManager.default.removeItem(at: url)
            store.rediscover(force: true)
        } catch {
            errorAlert(L.t("remove.failed.title"), error)
        }
    }

    @objc private func removeColumn(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String,
              let column = store.columns.first(where: { $0.id == id }) else { return }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = L.t("remove.title", column.header)
        alert.informativeText = L.t("remove.body")
        let deleteButton = alert.addButton(withTitle: L.t("remove.delete"))
        let cancelButton = alert.addButton(withTitle: L.t("common.cancel"))
        deleteButton.hasDestructiveAction = true
        // Отмена — действие по умолчанию (Enter), чтобы не удалить случайно.
        deleteButton.keyEquivalent = ""
        cancelButton.keyEquivalent = "\r"

        guard runModalAbovePanel(alert) == .alertFirstButtonReturn else { return }

        do {
            try store.removeAccount(id: id)
        } catch {
            errorAlert(L.t("remove.failed.title"), error)
        }
    }

    @objc private func changeHotKey() {
        guard let config = HotKeyRecorder.record(current: hotKeys.config) else { return }
        guard hotKeys.apply(config) else {
            let alert = NSAlert()
            alert.messageText = L.t("hotkey.taken.title", config.display)
            alert.informativeText = L.t("hotkey.taken.body")
            alert.addButton(withTitle: L.t("common.ok"))
            runModalAbovePanel(alert)
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

    @objc private func checkForUpdates() {
        Task { @MainActor in
            let outcome = await UpdateCheck.check()
            let alert = NSAlert()
            switch outcome {
            case .upToDate(let current):
                alert.messageText = L.t("update.upToDate", current)
                alert.addButton(withTitle: L.t("common.ok"))
                runModalAbovePanel(alert)

            case .available(let release):
                alert.messageText = L.t("update.available", release.version)
                alert.informativeText = L.t("update.availableBody")
                // «Обновить сейчас» — только если можем заменить бандл на месте.
                let canInstall = release.downloadURL != nil && UpdateInstaller.canInstallInPlace()
                if canInstall { alert.addButton(withTitle: L.t("update.install")) }
                alert.addButton(withTitle: L.t("update.open"))
                alert.addButton(withTitle: L.t("common.cancel"))

                let response = runModalAbovePanel(alert)
                if canInstall && response == .alertFirstButtonReturn {
                    installUpdate(release)
                } else if response == (canInstall ? .alertSecondButtonReturn : .alertFirstButtonReturn) {
                    NSWorkspace.shared.open(release.url)
                }

            case .failed(let message):
                alert.messageText = L.t("update.failed")
                alert.informativeText = message
                alert.addButton(withTitle: L.t("common.ok"))
                runModalAbovePanel(alert)
            }
        }
    }

    private func installUpdate(_ release: UpdateCheck.Release) {
        let hud = ProgressHUD(message: L.t("update.installing"))
        hud.show()
        Task { @MainActor in
            do {
                try await UpdateInstaller.install(release)
                // Бандл заменит и перезапустит скрипт — нам остаётся выйти.
                NSApp.terminate(nil)
            } catch {
                hud.close()
                let alert = NSAlert()
                alert.messageText = L.t("update.installFailed")
                alert.informativeText = error.localizedDescription
                alert.addButton(withTitle: L.t("update.open"))
                alert.addButton(withTitle: L.t("common.ok"))
                if runModalAbovePanel(alert) == .alertFirstButtonReturn {
                    NSWorkspace.shared.open(release.url)
                }
            }
        }
    }

    private func errorAlert(_ title: String, _ error: Error) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = error.localizedDescription
        alert.addButton(withTitle: L.t("common.ok"))
        runModalAbovePanel(alert)
    }

    /// Модальный диалог поверх панели. Панель у чёлки на уровне `.popUpMenu`, и
    /// окно алерта вылезает ПОД ней (NSAlert не даёт поднять своё окно выше),
    /// поэтому на время диалога опускаем саму панель.
    @discardableResult
    private func runModalAbovePanel(_ alert: NSAlert) -> NSApplication.ModalResponse {
        NSApp.activate(ignoringOtherApps: true)
        panel.setModalSuppression(true)
        defer { panel.setModalSuppression(false) }
        return alert.runModal()
    }

    @objc private func showAbout() {
        // Нативная панель About: сама берёт иконку, имя и версию из бандла.
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            NSApplication.AboutPanelOptionKey.applicationName: "Notch Limits"
        ])
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
