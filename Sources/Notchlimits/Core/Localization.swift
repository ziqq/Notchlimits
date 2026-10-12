import Foundation

/// Все пользовательские строки живут в `Resources/<язык>.lproj/Localizable.strings`
/// и попадают в `Contents/Resources` при сборке бандла.
///
/// Язык выбирает система по списку предпочитаемых языков пользователя;
/// запасной — английский (`CFBundleDevelopmentRegion`).
enum L {
    static func t(_ key: String, _ arguments: CVarArg...) -> String {
        let format = NSLocalizedString(key, bundle: .main, comment: "")
        guard !arguments.isEmpty else { return format }
        return String(format: format, locale: .current, arguments: arguments)
    }
}
