import AppKit
import Combine

/// Значки Keep Awake в строке меню — по одному на включённый режим, рядом
/// с остальными значками справа. Место им выделяет сама система, поэтому они
/// не наезжают ни на системные индикаторы, ни на вырез. Клик — меню с режимами.
@MainActor
final class KeepAwakeStatusItems {
    private let keepAwake: KeepAwake
    /// Меню по клику на значок: строит делегат, чтобы пункты совпадали с панелью.
    private let makeMenu: () -> NSMenu

    private var sleepItem: NSStatusItem?
    private var displayItem: NSStatusItem?
    private var observers: Set<AnyCancellable> = []

    init(keepAwake: KeepAwake, makeMenu: @escaping () -> NSMenu) {
        self.keepAwake = keepAwake
        self.makeMenu = makeMenu
    }

    func install() {
        keepAwake.$isActive
            .removeDuplicates()
            .sink { [weak self] active in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.sleepItem = self.sync(self.sleepItem, visible: active,
                                               symbol: "cup.and.saucer.fill",
                                               help: L.t("keepAwake.sleep.help"))
                }
            }
            .store(in: &observers)
        keepAwake.$keepDisplayOn
            .removeDuplicates()
            .sink { [weak self] on in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.displayItem = self.sync(self.displayItem, visible: on,
                                                 symbol: "display",
                                                 help: L.t("keepAwake.display.help"))
                }
            }
            .store(in: &observers)
    }

    /// Значок появляется со включением режима и убирается с выключением —
    /// пустое место в строке меню не держим.
    private func sync(_ item: NSStatusItem?, visible: Bool, symbol: String, help: String) -> NSStatusItem? {
        guard visible else {
            if let item { NSStatusBar.system.removeStatusItem(item) }
            return nil
        }
        if let item { return item }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = item.button {
            // Размер как у прочих значков строки меню.
            let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .regular)
            let image = NSImage(systemSymbolName: symbol, accessibilityDescription: help)?
                .withSymbolConfiguration(config)
            image?.isTemplate = true
            button.image = image
            button.toolTip = help
            button.target = self
            button.action = #selector(showMenu(_:))
        }
        return item
    }

    @objc private func showMenu(_ sender: NSStatusBarButton) {
        guard let item = [sleepItem, displayItem].compactMap({ $0 }).first(where: { $0.button === sender })
        else { return }
        item.menu = makeMenu()
        item.button?.performClick(nil)
        // Меню одноразовое: иначе следующий клик не дойдёт до action.
        item.menu = nil
    }
}
