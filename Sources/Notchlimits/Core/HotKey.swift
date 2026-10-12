import AppKit
import Carbon.HIToolbox

/// Глобальный хоткей через Carbon `RegisterEventHotKey` — работает без
/// разрешения Accessibility, в отличие от CGEventTap.
final class HotKey {

    private static var handlers: [UInt32: () -> Void] = [:]
    private static var nextID: UInt32 = 1
    private static var eventHandler: EventHandlerRef?
    private static let signature: OSType = 0x4E4C_484B // 'NLHK'

    private let id: UInt32
    private var ref: EventHotKeyRef?

    /// - Parameters:
    ///   - keyCode: виртуальный код клавиши (`kVK_ANSI_P`, `kVK_Escape`, …).
    ///   - modifiers: Carbon-модификаторы (`UInt32(cmdKey)` и т. п.).
    init?(keyCode: UInt32, modifiers: UInt32, action: @escaping () -> Void) {
        HotKey.installHandlerIfNeeded()

        id = HotKey.nextID
        HotKey.nextID += 1
        HotKey.handlers[id] = action

        let hotKeyID = EventHotKeyID(signature: HotKey.signature, id: id)
        let status = RegisterEventHotKey(keyCode, modifiers, hotKeyID,
                                         GetApplicationEventTarget(), 0, &ref)
        guard status == noErr, ref != nil else {
            HotKey.handlers[id] = nil
            return nil
        }
    }

    deinit {
        if let ref { UnregisterEventHotKey(ref) }
        HotKey.handlers[id] = nil
    }

    private static func installHandlerIfNeeded() {
        guard eventHandler == nil else { return }
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard),
                                 eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, event, _ -> OSStatus in
            var hotKeyID = EventHotKeyID()
            let status = GetEventParameter(event, EventParamName(kEventParamDirectObject),
                                           EventParamType(typeEventHotKeyID), nil,
                                           MemoryLayout<EventHotKeyID>.size, nil, &hotKeyID)
            guard status == noErr, hotKeyID.signature == HotKey.signature else { return status }
            let action = HotKey.handlers[hotKeyID.id]
            DispatchQueue.main.async { action?() }
            return noErr
        }, 1, &spec, nil, &eventHandler)
    }
}
