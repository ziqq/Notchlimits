import Foundation
import IOKit.pwr_mgt

/// «Не давать Mac уснуть» и «Не гасить экран»: штатные power assertions IOKit,
/// как у `caffeinate`. Режимы независимы и живут, пока работает приложение.
///
/// Прав администратора не нужно. Assertion живёт ровно столько, сколько процесс:
/// если приложение упадёт или его закроют, система снимет его сама, и Mac
/// не останется без сна навсегда. Проверка: `pmset -g assertions`.
@MainActor
final class KeepAwake: ObservableObject {
    static let shared = KeepAwake()

    /// Система не уходит в сон по бездействию.
    @Published private(set) var isActive = false
    /// Экран не гаснет по бездействию (а значит, не засыпает и Mac).
    @Published private(set) var keepDisplayOn = false

    var anyActive: Bool { isActive || keepDisplayOn }

    private var systemAssertion: PowerAssertion?
    private var displayAssertion: PowerAssertion?

    private init() {}

    func toggle() { setActive(!isActive) }
    func toggleDisplay() { setKeepDisplayOn(!keepDisplayOn) }

    func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        systemAssertion = active
            ? PowerAssertion(type: kIOPMAssertPreventUserIdleSystemSleep,
                             reason: "Notch Limits: keep the Mac awake")
            : nil
    }

    func setKeepDisplayOn(_ on: Bool) {
        guard on != keepDisplayOn else { return }
        keepDisplayOn = on
        displayAssertion = on
            ? PowerAssertion(type: kIOPMAssertPreventUserIdleDisplaySleep,
                             reason: "Notch Limits: keep the display on")
            : nil
    }
}

/// Владеет одним IOPM assertion: создаётся в `init`, снимается в `deinit`.
/// Так assertion невозможно «забыть» — достаточно отпустить объект.
final class PowerAssertion {
    private var id = IOPMAssertionID(0)

    /// `nil`, если система отказала в assertion.
    init?(type: String, reason: String) {
        let result = IOPMAssertionCreateWithName(type as CFString,
                                                 IOPMAssertionLevel(kIOPMAssertionLevelOn),
                                                 reason as CFString,
                                                 &id)
        guard result == kIOReturnSuccess else { return nil }
    }

    deinit {
        IOPMAssertionRelease(id)
    }
}
