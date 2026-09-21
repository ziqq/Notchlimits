import Foundation

/// Утилиты для аккаунтов. Свитчер активного аккаунта через подмену базовой
/// записи (Keychain `Claude Code-credentials` / `~/.codex/auth.json`) убран:
/// он путался с аккаунтом ПРИЛОЖЕНИЯ, а перезапись общих кред приводила к
/// рассинхрону токена и метаданных. Переключение аккаунта приложения теперь
/// делает `AppAccountSwitcher` (отдельная папка данных на аккаунт).
enum AccountSwitcher {

    /// Имя-слаг из почты. Чистая функция, покрыта самопроверкой.
    static func slug(_ email: String?) -> String {
        let source = (email?.isEmpty == false) ? email!.lowercased() : "account"
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789")
        let cleaned = source.map { allowed.contains($0) ? $0 : "-" }
        let slug = String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String((slug.isEmpty ? "account" : slug).prefix(48))
    }
}
