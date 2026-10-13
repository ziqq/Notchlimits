import AppKit
import Sparkle

/// Ручная проверка обновления; подпись, установка и перезапуск принадлежат Sparkle.
@MainActor
final class UpdaterController: NSObject, SPUStandardUserDriverDelegate {
    private let suppressPanel: (Bool) -> Void
    private let presentAlert: (NSAlert) -> NSApplication.ModalResponse
    private lazy var driver = CompactUpdateUserDriver(delegate: self, presentAlert: presentAlert)
    private lazy var updater = SPUUpdater(hostBundle: .main, applicationBundle: .main,
                                         userDriver: driver, delegate: nil)
    private var startError: Error?

    init(suppressPanel: @escaping (Bool) -> Void,
         presentAlert: @escaping (NSAlert) -> NSApplication.ModalResponse) {
        self.suppressPanel = suppressPanel
        self.presentAlert = presentAlert
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
    private let presentAlert: (NSAlert) -> NSApplication.ModalResponse
    private var updateAlert: NSAlert?

    init(delegate: SPUStandardUserDriverDelegate,
         presentAlert: @escaping (NSAlert) -> NSApplication.ModalResponse) {
        self.presentAlert = presentAlert
        super.init(hostBundle: .main, delegate: delegate)
    }

    static func makeAlert(version: String) -> NSAlert {
        let alert = NSAlert()
        alert.messageText = L.t("update.available", version)
        let label = NSTextField(wrappingLabelWithString: L.t("update.availableBody"))
        label.preferredMaxLayoutWidth = 360
        label.frame = NSRect(x: 0, y: 0, width: 360, height: 50)
        alert.accessoryView = label
        let bundle = Bundle(for: SPUStandardUserDriver.self)
        alert.addButton(withTitle: bundle.localizedString(forKey: "Install Update", value: nil, table: "Sparkle"))
        alert.addButton(withTitle: bundle.localizedString(forKey: "Skip This Version", value: nil, table: "Sparkle"))
        return alert
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
        NSApp.unhideWithoutActivation()
        NSApp.activate(ignoringOtherApps: true)
        let alert = Self.makeAlert(version: appcastItem.displayVersionString)
        updateAlert = alert
        let result = presentAlert(alert)
        updateAlert = nil
        switch result {
        case .alertFirstButtonReturn: reply(.install)
        case .alertSecondButtonReturn: reply(.skip)
        default: reply(.dismiss)
        }
    }

    override func dismissUpdateInstallation() {
        if let updateAlert {
            NSApp.abortModal()
            updateAlert.window.close()
        }
        super.dismissUpdateInstallation()
    }

    override func showUpdateInFocus() {
        guard let updateAlert else { super.showUpdateInFocus(); return }
        NSApp.activate(ignoringOtherApps: true)
        updateAlert.window.makeKeyAndOrderFront(nil)
    }
}
