import Foundation
import IOKit

/// Снимок питания: зарядка и аккумулятор из IORegistry `AppleSmartBattery`.
///
/// Это тот же источник, что у `ioreg -rc AppleSmartBattery` и System Information:
/// без root, без приватных фреймворков. Напряжение на конкретном порту USB-C
/// (ключи AppleHPM) и SMC — вентиляторы, датчики — сюда сознательно не входят.
struct PowerSnapshot: Equatable {
    enum State: Equatable {
        case charging, charged, notCharging, onBattery
    }

    /// Паспорт подключённого адаптера: на что он рассчитан и о чём договорился с Mac.
    struct Adapter: Equatable {
        var name: String?
        var watts: Int?
        /// Согласованное напряжение, В.
        var voltage: Double?
        /// Максимальный ток при этом напряжении, А.
        var current: Double?
    }

    /// Что Mac берёт от зарядки прямо сейчас (`PowerTelemetryData`, только Apple Silicon).
    struct Input: Equatable {
        var watts: Double
        var voltage: Double?
        var current: Double?
    }

    var state: State
    var percent: Int?
    /// Напряжение аккумулятора, В.
    var voltage: Double?
    /// Ток аккумулятора, А: плюс — заряжается, минус — разряжается.
    var current: Double?
    /// Температура аккумулятора, °C.
    var temperature: Double?
    var cycleCount: Int?
    /// Полная ёмкость сейчас и по паспорту, мА·ч.
    var maxCapacity: Int?
    var designCapacity: Int?
    var adapter: Adapter?
    var input: Input?

    /// Здоровье: текущая полная ёмкость от паспортной, в процентах.
    var health: Double? {
        guard let maxCapacity, let designCapacity, designCapacity > 0 else { return nil }
        return Double(maxCapacity) / Double(designCapacity) * 100
    }

    /// Разбор словаря свойств `AppleSmartBattery`. `nil` — аккумулятора нет.
    ///
    /// Единицы как в IORegistry: мВ, мА, мА·ч, сотые доли °C, мВт.
    /// На Apple Silicon `CurrentCapacity`/`MaxCapacity` — проценты, а ёмкость
    /// в мА·ч лежит в `AppleRaw…`; на Intel оба ключа сразу в мА·ч.
    static func parse(_ properties: [String: Any]) -> PowerSnapshot? {
        if bool(properties["BatteryInstalled"]) == false { return nil }
        // Пустой или чужой словарь — тоже «аккумулятора нет».
        guard properties["CurrentCapacity"] != nil || properties["Voltage"] != nil else { return nil }

        let external = bool(properties["ExternalConnected"]) ?? false
        let charging = bool(properties["IsCharging"]) ?? false
        let full = bool(properties["FullyCharged"]) ?? false

        var percent: Int?
        if let current = int(properties["CurrentCapacity"]),
           let maximum = int(properties["MaxCapacity"]), maximum > 0 {
            percent = min(100, max(0, Int((Double(current) * 100 / Double(maximum)).rounded())))
        }

        let state: State
        if charging {
            state = .charging
        } else if external {
            state = full || percent == 100 ? .charged : .notCharging
        } else {
            state = .onBattery
        }

        var snapshot = PowerSnapshot(state: state, percent: percent)
        snapshot.voltage = (int(properties["Voltage"]) ?? int(properties["AppleRawBatteryVoltage"]))
            .map { Double($0) / 1000 }
        snapshot.current = (int(properties["Amperage"]) ?? int(properties["InstantAmperage"]))
            .map { Double($0) / 1000 }
        snapshot.temperature = int(properties["Temperature"]).map { Double($0) / 100 }
        snapshot.cycleCount = int(properties["CycleCount"])
        snapshot.maxCapacity = int(properties["AppleRawMaxCapacity"])
            ?? int(properties["MaxCapacity"]).flatMap { $0 > 100 ? $0 : nil }
        snapshot.designCapacity = int(properties["DesignCapacity"])

        // Отключённый адаптер оставляет в словаре огрызок без мощности.
        if external, let details = properties["AdapterDetails"] as? [String: Any],
           let watts = int(details["Watts"]), watts > 0 {
            snapshot.adapter = Adapter(
                name: (details["Name"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                watts: watts,
                voltage: int(details["AdapterVoltage"]).map { Double($0) / 1000 },
                current: int(details["Current"]).map { Double($0) / 1000 }
            )
        }

        if external, let telemetry = properties["PowerTelemetryData"] as? [String: Any],
           let power = int(telemetry["SystemPowerIn"]), power > 0 {
            snapshot.input = Input(
                watts: Double(power) / 1000,
                voltage: int(telemetry["SystemVoltageIn"]).map { Double($0) / 1000 },
                current: int(telemetry["SystemCurrentIn"]).map { Double($0) / 1000 }
            )
        }

        return snapshot
    }

    /// Чтение из IORegistry. На Mac без аккумулятора сервиса нет — `nil`.
    static func readCurrent() -> PowerSnapshot? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSmartBattery"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }

        var properties: Unmanaged<CFMutableDictionary>?
        guard IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, 0) == KERN_SUCCESS,
              let dictionary = properties?.takeRetainedValue() as? [String: Any]
        else { return nil }
        return parse(dictionary)
    }

    /// Числа в IORegistry знаковые 64-битные, но отрицательный ток иногда
    /// приходит как беззнаковое (18446744073709550616 = −1000) — берём битовый образ.
    private static func int(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return Int(truncatingIfNeeded: number.int64Value)
    }

    private static func bool(_ value: Any?) -> Bool? {
        (value as? NSNumber)?.boolValue
    }
}

/// Опрос `AppleSmartBattery`, пока панель раскрыта: свёрнутой панели цифры
/// не нужны, и будить IORegistry впустую незачем.
@MainActor
final class PowerMonitor: ObservableObject {
    static let shared = PowerMonitor()

    static let interval: TimeInterval = 5

    /// `nil` — аккумулятора нет (или ещё не читали): блок питания скрыт.
    @Published private(set) var snapshot: PowerSnapshot?
    /// Разъёмы и договорённость с зарядкой; есть и на Mac без аккумулятора.
    @Published private(set) var ports: PortsSnapshot?

    private var timer: Timer?

    private init() {}

    func setActive(_ active: Bool) {
        if active {
            guard timer == nil else { return }
            refresh()
            let timer = Timer(timeInterval: Self.interval, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refresh() }
            }
            timer.tolerance = 1
            RunLoop.main.add(timer, forMode: .common)
            self.timer = timer
        } else {
            timer?.invalidate()
            timer = nil
        }
    }

    func refresh() {
        let fresh = PowerSnapshot.readCurrent()
        if fresh != snapshot { snapshot = fresh }
        let freshPorts = PortsSnapshot.readCurrent()
        if freshPorts != ports { ports = freshPorts }
    }

    /// Для офф-скрин рендера: подставить снимок без IORegistry.
    func setSnapshotForRendering(_ snapshot: PowerSnapshot?, ports: PortsSnapshot? = nil) {
        self.snapshot = snapshot
        self.ports = ports
    }
}
