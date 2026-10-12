import AppKit
import Carbon.HIToolbox

/// Сочетание клавиш для открытия панели.
///
/// `keyCode` — физический код клавиши, он не зависит от раскладки;
/// `display` — то, как сочетание выглядело в момент записи, только для меню.
struct HotKeyConfig: Codable, Equatable {
    var keyCode: UInt32
    var modifiers: UInt32
    var display: String

    static let standard = HotKeyConfig(keyCode: UInt32(kVK_ANSI_P),
                                       modifiers: UInt32(cmdKey),
                                       display: "⌘P")

    /// Разбор нажатия. Возвращает nil, если модификаторов нет или их
    /// недостаточно: глобальный хоткей без ⌘/⌥/⌃ перехватывал бы обычный ввод.
    init?(event: NSEvent) {
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        var carbon: UInt32 = 0
        if flags.contains(.control) { carbon |= UInt32(controlKey) }
        if flags.contains(.option) { carbon |= UInt32(optionKey) }
        if flags.contains(.shift) { carbon |= UInt32(shiftKey) }
        if flags.contains(.command) { carbon |= UInt32(cmdKey) }

        let meaningful = carbon & ~UInt32(shiftKey)
        guard meaningful != 0 else { return nil }

        let name = Self.keyName(for: event)
        guard !name.isEmpty else { return nil }

        keyCode = UInt32(event.keyCode)
        modifiers = carbon
        display = Self.symbols(for: carbon) + name
    }

    init(keyCode: UInt32, modifiers: UInt32, display: String) {
        self.keyCode = keyCode
        self.modifiers = modifiers
        self.display = display
    }

    private static func symbols(for modifiers: UInt32) -> String {
        var result = ""
        if modifiers & UInt32(controlKey) != 0 { result += "⌃" }
        if modifiers & UInt32(optionKey) != 0 { result += "⌥" }
        if modifiers & UInt32(shiftKey) != 0 { result += "⇧" }
        if modifiers & UInt32(cmdKey) != 0 { result += "⌘" }
        return result
    }

    private static func keyName(for event: NSEvent) -> String {
        if let special = specialKeys[Int(event.keyCode)] { return special }
        let characters = event.charactersIgnoringModifiers ?? ""
        guard let first = characters.first, !first.isWhitespace else { return "" }
        return String(first).uppercased()
    }

    private static let specialKeys: [Int: String] = [
        kVK_Space: "Space", kVK_Return: "↩", kVK_Tab: "⇥", kVK_Delete: "⌫",
        kVK_ForwardDelete: "⌦", kVK_Escape: "⎋", kVK_Home: "↖", kVK_End: "↘",
        kVK_PageUp: "⇞", kVK_PageDown: "⇟",
        kVK_LeftArrow: "←", kVK_RightArrow: "→", kVK_UpArrow: "↑", kVK_DownArrow: "↓",
        kVK_F1: "F1", kVK_F2: "F2", kVK_F3: "F3", kVK_F4: "F4", kVK_F5: "F5",
        kVK_F6: "F6", kVK_F7: "F7", kVK_F8: "F8", kVK_F9: "F9", kVK_F10: "F10",
        kVK_F11: "F11", kVK_F12: "F12"
    ]
}

/// Хранение и регистрация сочетания. Настройка живёт в UserDefaults.
@MainActor
final class HotKeyManager {

    private struct Stored: Codable {
        var enabled: Bool
        var config: HotKeyConfig
    }

    private let key = "hotKey"
    private let action: () -> Void
    private var hotKey: HotKey?
    private var stored: Stored

    /// Текущее сочетание или nil, если хоткей выключен.
    var config: HotKeyConfig? { stored.enabled ? stored.config : nil }

    var displayName: String { stored.enabled ? stored.config.display : L.t("hotkey.disabled") }

    var isStandard: Bool { stored.enabled && stored.config == .standard }

    init(action: @escaping () -> Void) {
        self.action = action
        if let data = UserDefaults.standard.data(forKey: key),
           let decoded = try? JSONDecoder().decode(Stored.self, from: data) {
            stored = decoded
        } else {
            stored = Stored(enabled: true, config: .standard)
        }
        register()
    }

    /// Применить новое сочетание. `nil` выключает хоткей.
    /// Возвращает false, если сочетание уже занято другим приложением —
    /// в этом случае прежняя настройка остаётся в силе.
    @discardableResult
    func apply(_ config: HotKeyConfig?) -> Bool {
        let previous = stored
        stored = Stored(enabled: config != nil, config: config ?? stored.config)
        guard register() else {
            stored = previous
            register()
            return false
        }
        persist()
        return true
    }

    @discardableResult
    private func register() -> Bool {
        // Сначала снимаем старую регистрацию, иначе то же сочетание не примут.
        hotKey = nil
        guard stored.enabled else { return true }
        hotKey = HotKey(keyCode: stored.config.keyCode,
                        modifiers: stored.config.modifiers,
                        action: action)
        return hotKey != nil
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(stored) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}

/// Запись сочетания: модальный диалог, который ловит следующее нажатие.
@MainActor
enum HotKeyRecorder {

    static func record(current: HotKeyConfig?) -> HotKeyConfig? {
        NSApp.activate(ignoringOtherApps: true)

        let alert = NSAlert()
        alert.messageText = L.t("hotkey.recorder.title")
        alert.informativeText = L.t("hotkey.recorder.hint")
        alert.addButton(withTitle: L.t("hotkey.recorder.save"))
        alert.addButton(withTitle: L.t("common.cancel"))

        let label = NSTextField(labelWithString: current?.display ?? "—")
        label.alignment = .center
        label.font = .systemFont(ofSize: 24, weight: .medium)
        label.frame = NSRect(x: 0, y: 0, width: 260, height: 36)
        alert.accessoryView = label

        var captured: HotKeyConfig?
        alert.buttons[0].isEnabled = false

        let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard let config = HotKeyConfig(event: event) else {
                // Без «наших» модификаторов событие уходит дальше:
                // так Esc по-прежнему закрывает диалог.
                return event
            }
            captured = config
            label.stringValue = config.display
            alert.buttons[0].isEnabled = true
            return nil
        }
        defer { if let monitor { NSEvent.removeMonitor(monitor) } }

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return captured
    }
}
