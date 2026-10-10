import Foundation
import IOKit.pwr_mgt

/// «Не давать Mac уснуть»: штатные power assertions IOKit, как у `caffeinate`.
///
/// Прав администратора не нужно. Assertion живёт ровно столько, сколько процесс:
/// если приложение упадёт или его закроют, система снимет его сама, и Mac
/// не останется без сна навсегда. Проверка: `pmset -g assertions`.
@MainActor
final class KeepAwake: ObservableObject {
    static let shared = KeepAwake()

    private enum Key {
        static let keepDisplayOn = "keepAwake.keepDisplayOn"
    }

    /// Сессия включена: система не уходит в сон по бездействию.
    @Published private(set) var isActive = false

    /// Заодно не гасить экран. Настройка переживает перезапуск; по умолчанию — да.
    @Published var keepDisplayOn: Bool {
        didSet {
            guard keepDisplayOn != oldValue else { return }
            UserDefaults.standard.set(keepDisplayOn, forKey: Key.keepDisplayOn)
            syncAssertions()
        }
    }

    private var systemAssertion: PowerAssertion?
    private var displayAssertion: PowerAssertion?

    private init() {
        let defaults = UserDefaults.standard
        keepDisplayOn = defaults.object(forKey: Key.keepDisplayOn) as? Bool ?? true
    }

    func toggle() {
        setActive(!isActive)
    }

    func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        syncAssertions()
    }

    private func syncAssertions() {
        if isActive, systemAssertion == nil {
            systemAssertion = PowerAssertion(type: kIOPMAssertPreventUserIdleSystemSleep,
                                             reason: "Notch Limits: keep the Mac awake")
        } else if !isActive {
            systemAssertion = nil
        }

        let wantsDisplay = isActive && keepDisplayOn
        if wantsDisplay, displayAssertion == nil {
            displayAssertion = PowerAssertion(type: kIOPMAssertPreventUserIdleDisplaySleep,
                                              reason: "Notch Limits: keep the display on")
        } else if !wantsDisplay {
            displayAssertion = nil
        }
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
