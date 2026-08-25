import AppKit
import ServiceManagement

/// Запуск при входе через SMAppService — без вспомогательных бандлов и
/// без устаревшего SMLoginItemSetEnabled.
enum LoginItem {

    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func toggle() {
        do {
            if isEnabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = L.t("loginItem.failed.title")
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: L.t("common.ok"))
            alert.runModal()
        }
    }
}
