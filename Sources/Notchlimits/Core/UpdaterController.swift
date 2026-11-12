import AppKit
import Sparkle
import SwiftUI

/// Ручная проверка обновления; подпись, установка и перезапуск принадлежат Sparkle.
@MainActor
final class UpdaterController: NSObject, SPUStandardUserDriverDelegate {
    private let suppressPanel: (Bool) -> Void
    private lazy var driver = CompactUpdateUserDriver(delegate: self, suppressPanel: suppressPanel)
    private lazy var updater = SPUUpdater(hostBundle: .main, applicationBundle: .main,
                                         userDriver: driver, delegate: nil)
    private var startError: Error?

    init(suppressPanel: @escaping (Bool) -> Void) {
        self.suppressPanel = suppressPanel
        super.init()
        do { try updater.start() }
        catch { startError = error }
    }

    func checkForUpdates() {
        // Создаём окна после завершения отслеживания контекстного меню.
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let startError = self.startError {
                self.driver.showUpdaterError(startError) {}
            } else if self.updater.canCheckForUpdates {
                self.updater.checkForUpdates()
            }
        }
    }

    nonisolated func standardUserDriverWillShowModalAlert() {
        MainActor.assumeIsolated { suppressPanel(true) }
    }

    nonisolated func standardUserDriverDidShowModalAlert() {
        MainActor.assumeIsolated { suppressPanel(false) }
    }
}

/// Компактное окно для обычного обновления без release notes, как в Copybara.
/// Остальные окна и состояние сессии остаются у стандартного драйвера Sparkle.
@MainActor
final class CompactUpdateUserDriver: SPUStandardUserDriver {
    private let suppressPanel: (Bool) -> Void
    private var updatePanel: UpdateDialogPanel?

    init(delegate: SPUStandardUserDriverDelegate, suppressPanel: @escaping (Bool) -> Void) {
        self.suppressPanel = suppressPanel
        super.init(hostBundle: .main, delegate: delegate)
    }

    private func presentUpdate(version: String) -> NSApplication.ModalResponse {
        let bundle = Bundle(for: SPUStandardUserDriver.self)
        let view = UpdateDialogView(
            icon: NSApp.applicationIconImage,
            title: L.t("update.available", version),
            message: L.t("update.availableBody"),
            installTitle: bundle.localizedString(forKey: "Install Update", value: nil, table: "Sparkle"),
            skipTitle: bundle.localizedString(forKey: "Skip This Version", value: nil, table: "Sparkle"),
            onInstall: { NSApp.stopModal(withCode: .alertFirstButtonReturn) },
            onSkip: { NSApp.stopModal(withCode: .alertSecondButtonReturn) }
        )
        let host = NSHostingView(rootView: view)
        let panel = UpdateDialogPanel(contentRect: NSRect(origin: .zero, size: host.fittingSize),
                                      styleMask: .borderless, backing: .buffered, defer: false)
        panel.title = view.title
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.contentView = host
        panel.center()
        updatePanel = panel
        suppressPanel(true)
        defer {
            panel.orderOut(nil)
            updatePanel = nil
            suppressPanel(false)
        }
        NSApp.unhideWithoutActivation()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        return NSApp.runModal(for: panel)
    }

    override func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState,
                                  reply: @escaping (SPUUserUpdateChoice) -> Void) {
        guard !appcastItem.isInformationOnlyUpdate, !appcastItem.isMajorUpgrade,
              !appcastItem.isCriticalUpdate, appcastItem.releaseNotesURL == nil,
              appcastItem.itemDescription == nil, state.stage == .notDownloaded else {
            super.showUpdateFound(with: appcastItem, state: state, reply: reply)
            return
        }
        super.dismissUpdateInstallation()
        switch presentUpdate(version: appcastItem.displayVersionString) {
        case .alertFirstButtonReturn: reply(.install)
        case .alertSecondButtonReturn: reply(.skip)
        default: reply(.dismiss)
        }
    }

    override func dismissUpdateInstallation() {
        if let updatePanel, NSApp.modalWindow === updatePanel {
            NSApp.abortModal()
        }
        super.dismissUpdateInstallation()
    }

    override func showUpdateInFocus() {
        guard let updatePanel else { super.showUpdateInFocus(); return }
        NSApp.activate(ignoringOtherApps: true)
        updatePanel.makeKeyAndOrderFront(nil)
    }
}

private final class UpdateDialogPanel: NSPanel {
    override var canBecomeKey: Bool { true }

    override func cancelOperation(_ sender: Any?) {
        if NSApp.modalWindow === self {
            NSApp.stopModal(withCode: .cancel)
        }
    }
}
