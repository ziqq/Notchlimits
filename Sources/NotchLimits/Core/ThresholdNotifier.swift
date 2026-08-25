import Foundation
import UserNotifications

/// Уведомления при пересечении 80 % и 95 %.
/// Каждый порог срабатывает один раз за окно и перевзводится, когда меняется
/// `resets_at` — то есть когда началось новое окно.
final class ThresholdNotifier {

    private let defaults = UserDefaults.standard
    private let key = "notifiedThresholds"
    private let thresholds: [Double] = [80, 95]
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
            // Метка окна: смена resets_at означает новое окно и сброс порогов.
            let stamp = window.resetsAt.map { String(Int($0.timeIntervalSince1970)) } ?? "none"
            let stored = state[stateKey] ?? ""
            let parts = stored.split(separator: "@", maxSplits: 1).map(String.init)
            let storedStamp = parts.first ?? ""
            var fired = (parts.count > 1 ? Set(parts[1].split(separator: ",").map(String.init)) : [])
            if storedStamp != stamp { fired = [] }

            for threshold in thresholds where window.utilization >= threshold {
                let tag = String(Int(threshold))
                guard !fired.contains(tag) else { continue }
                fired.insert(tag)
                post(column: column, window: window, threshold: threshold)
            }

            let encoded = stamp + "@" + fired.sorted().joined(separator: ",")
            if encoded != stored {
                state[stateKey] = encoded
                changed = true
            }
        }

        if changed { defaults.set(state, forKey: key) }
    }

    private func post(column: AccountColumn, window: LimitWindow, threshold: Double) {
        let content = UNMutableNotificationContent()
        content.title = L.t("notification.title", column.header, Int(threshold))
        var body = L.t("notification.body", window.title, Int(window.utilization.rounded()))
        if let resetsAt = window.resetsAt { body += ". " + Format.reset(resetsAt) }
        content.body = body
        content.sound = .default

        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content,
                                            trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
