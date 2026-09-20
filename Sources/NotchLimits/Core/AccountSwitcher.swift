import Foundation

/// Утилиты для аккаунтов. Раньше здесь жил свитчер «активного» аккаунта через
/// подмену базовой записи (`~/.codex/auth.json`, Keychain `Claude
/// Code-credentials`), но эта модель давала дубли колонок, спам паролём Keychain
/// (перезапись общей записи сбрасывала ACL) и на десктоп-приложение всё равно не
/// влияла. Отказались в пользу профилей: каждый аккаунт — отдельная колонка со
/// своим `CLAUDE_CONFIG_DIR` / `CODEX_HOME`, изолированно и без побочек.
enum AccountSwitcher {

    /// Имя-слаг из почты: для имён папок/записей. Оставлено, т.к. это чистая
    /// функция и её покрывает самопроверка.
    static func slug(_ email: String?) -> String {
        let source = (email?.isEmpty == false) ? email!.lowercased() : "account"
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789")
        let cleaned = source.map { allowed.contains($0) ? $0 : "-" }
        let slug = String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String((slug.isEmpty ? "account" : slug).prefix(48))
    }
}
