import Foundation
import IOKit

/// Разъёмы Mac и то, через какой из них идёт питание.
///
/// Источник — IORegistry: общий класс `IOPort` (USB-C, MagSafe, HDMI, SD) и
/// `IOPortFeaturePowerSource` — договорённость Power Delivery с зарядкой. Всё без
/// root и приватных фреймворков. Живого напряжения на каждом порту здесь нет:
/// macOS отдаёт его только через ключи SMC, которые меняются от модели к модели.
struct PortsSnapshot: Equatable {
    struct Port: Equatable, Identifiable {
        /// «USB-C», «MagSafe 3», «Thunderbolt 4».
        var kind: String
        var number: Int
        var connected: Bool
        /// Активные протоколы без служебного CC: «USB2», «USB3», «CIO», «DisplayPort».
        var transports: [String]

        var id: String { "\(kind)@\(number)" }
        var isMagSafe: Bool { kind.hasPrefix("MagSafe") }
    }

    /// Договорённость с зарядкой: на каком порту и сколько.
    struct Contract: Equatable {
        var portKind: String
        var portNumber: Int
        /// Согласованные напряжение, ток и мощность.
        var voltage: Double
        var current: Double
        var watts: Double
        /// Все напряжения, что предлагает зарядка, по возрастанию.
        var offeredVoltages: [Double]
    }

    var ports: [Port]
    var contract: Contract?

    var isEmpty: Bool { ports.isEmpty && contract == nil }

    /// Только разъёмы питания и данных: HDMI и SD-слот к питанию отношения не имеют.
    static func parsePorts(_ entries: [[String: Any]]) -> [Port] {
        entries.compactMap { properties in
            guard let kind = properties["PortTypeDescription"] as? String,
                  kind == "USB-C" || kind.hasPrefix("MagSafe") || kind.hasPrefix("Thunderbolt"),
                  let number = int(properties["PortNumber"])
            else { return nil }
            let transports = (properties["TransportsActive"] as? [String] ?? []).filter { $0 != "CC" }
            return Port(kind: kind, number: number,
                        connected: (properties["ConnectionActive"] as? NSNumber)?.boolValue ?? false,
                        transports: transports)
        }
        // MagSafe первым, дальше по номеру — как на корпусе слева направо.
        .sorted { ($0.isMagSafe ? 0 : 1, $0.kind, $0.number) < ($1.isMagSafe ? 0 : 1, $1.kind, $1.number) }
    }

    /// Из всех источников питания — тот, что выиграл, с наибольшим приоритетом.
    static func parseContract(_ entries: [[String: Any]]) -> Contract? {
        let candidates: [(priority: Int, contract: Contract)] = entries.compactMap { properties in
            guard let winning = properties["WinningPowerSourceOption"] as? [String: Any],
                  let millivolts = int(winning["Voltage (mV)"]), millivolts > 0,
                  let kind = properties["ParentPortTypeDescription"] as? String,
                  let number = int(properties["ParentPortNumber"])
            else { return nil }
            let milliamps = int(winning["Max Current (mA)"]) ?? 0
            let milliwatts = int(winning["Max Power (mW)"]) ?? millivolts * milliamps / 1000
            let offered = options(properties["PowerSourceOptions"])
                .compactMap { int($0["Voltage (mV)"]) }
                .map { Double($0) / 1000 }
            let contract = Contract(portKind: kind, portNumber: number,
                                    voltage: Double(millivolts) / 1000,
                                    current: Double(milliamps) / 1000,
                                    watts: Double(milliwatts) / 1000,
                                    offeredVoltages: Array(Set(offered)).sorted())
            return (int(properties["Priority"]) ?? 0, contract)
        }
        return candidates.max { $0.priority < $1.priority }?.contract
    }

    /// Режимы зарядки в IORegistry лежат множеством (`NSSet`), не массивом.
    private static func options(_ value: Any?) -> [[String: Any]] {
        if let array = value as? [[String: Any]] { return array }
        return (value as? NSSet)?.allObjects.compactMap { $0 as? [String: Any] } ?? []
    }

    static func readCurrent() -> PortsSnapshot? {
        let snapshot = PortsSnapshot(ports: parsePorts(properties(ofClass: "IOPort")),
                                     contract: parseContract(properties(ofClass: "IOPortFeaturePowerSource")))
        return snapshot.isEmpty ? nil : snapshot
    }

    private static func properties(ofClass name: String) -> [[String: Any]] {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(name), &iterator) == KERN_SUCCESS
        else { return [] }
        defer { IOObjectRelease(iterator) }

        var result: [[String: Any]] = []
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            var properties: Unmanaged<CFMutableDictionary>?
            if IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, 0) == KERN_SUCCESS,
               let dictionary = properties?.takeRetainedValue() as? [String: Any] {
                result.append(dictionary)
            }
        }
        return result
    }

    /// Приоритет «Brick ID» лежит как беззнаковое 2^64−500 — берём битовый образ.
    private static func int(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return Int(truncatingIfNeeded: number.int64Value)
    }
}
