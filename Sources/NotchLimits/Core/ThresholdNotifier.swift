import Foundation
import UserNotifications

/// Уведомления по окнам лимитов:
/// - пересечение 80 % и 95 % — каждый порог один раз за окно;
/// - сброс окна — когда меняется `resets_at`, а прежнее окно было заметно
///   израсходовано (пик ≥ `resetFloor`): значит, лимит освободился.
/// Всё перевзводится при смене `resets_at`, то есть с началом нового окна.
final class ThresholdNotifier {

    private let defaults = UserDefaults.standard
    private let key = "notifiedThresholds"
    private let thresholds: [Double] = [80, 95]
    /// Ниже этого пика сброс окна не заслуживает пуша — окно почти не трогали.
    private let resetFloor: Double = 50

    static func requestAuthorization() {
        UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    @MainActor
    func evaluate(column: AccountColumn) {
        var state = defaults.dictionary(forKey: key) as? [String: String] ?? [:]
        var changed = false

        for window in column.windows {
            let stateKey = "\(column.id)|\(window.key)"
            // Метка окна: смена resets_at означает новое окно.
            let stamp = window.resetsAt.map { String(Int($0.timeIntervalSince1970)) } ?? "none"

            let decision = Self.decide(stored: state[stateKey] ?? "", stamp: stamp,
                                       utilization: window.utilization,
                                       thresholds: thresholds, resetFloor: resetFloor)

            if decision.postReset { postReset(column: column, window: window) }
            for threshold in decision.fireThresholds {
                post(column: column, window: window, threshold: threshold)
            }

            if decision.encoded != (state[stateKey] ?? "") {
                state[stateKey] = decision.encoded
                changed = true
            }
        }

        if changed { defaults.set(state, forKey: key) }
    }

    /// Чистое решение по одному окну — что послать и как переписать состояние.
    /// Вынесено из `evaluate`, чтобы покрыть граничные случаи самопроверкой.
    struct Decision: Equatable {
        var postReset: Bool
        var fireThresholds: [Double]
        var encoded: String
    }

    static func decide(stored: String, stamp: String, utilization: Double,
                       thresholds: [Double], resetFloor: Double) -> Decision {
        // Состояние окна: «метка@пороги@пик». Старый формат без пика читается тоже.
        let parts = stored.split(separator: "@", maxSplits: 2).map(String.init)
        let storedStamp = parts.first ?? ""
        var fired = (parts.count > 1 ? Set(parts[1].split(separator: ",").map(String.init)) : [])
        let storedPeak = parts.count > 2 ? (Double(parts[2]) ?? 0) : 0

        let newWindow = storedStamp != stamp
        var postReset = false
        if newWindow {
            // Окно сменилось. Если прежнее было заметно израсходовано — лимит
            // освободился. На самом первом наблюдении (storedStamp пуст) не шумим.
            if !storedStamp.isEmpty, storedPeak >= resetFloor { postReset = true }
            fired = []
        }

        let peak = max(newWindow ? 0 : storedPeak, utilization)

        var toFire: [Double] = []
        for threshold in thresholds where utilization >= threshold {
            let tag = String(Int(threshold))
            guard !fired.contains(tag) else { continue }
            fired.insert(tag)
            toFire.append(threshold)
        }

        let encoded = stamp + "@" + fired.sorted().joined(separator: ",") + "@" + String(Int(peak.rounded()))
        return Decision(postReset: postReset, fireThresholds: toFire, encoded: encoded)
    }

    private func post(column: AccountColumn, window: LimitWindow, threshold: Double) {
        let content = UNMutableNotificationContent()
        content.title = L.t("notification.title", column.header, Int(threshold))
        var body = L.t("notification.body", window.title, Int(window.utilization.rounded()))
        if let resetsAt = window.resetsAt { body += ". " + Format.reset(resetsAt) }
        content.body = body
        content.sound = .default
        add(content)
    }

    private func postReset(column: AccountColumn, window: LimitWindow) {
        let content = UNMutableNotificationContent()
        content.title = L.t("notification.reset.title", column.header)
        content.body = L.t("notification.reset.body", window.title)
        content.sound = .default
        add(content)
    }

    private func add(_ content: UNMutableNotificationContent) {
        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content,
                                            trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
