import AppKit

/// Добавление аккаунта. Панель никогда не спрашивает пароли и не разговаривает
/// с OAuth сама: она только готовит папку профиля и запускает штатный вход CLI
/// в Terminal.app.
///
/// Открываем именно `.command`-файл через NSWorkspace: это не требует разрешения
/// «Автоматизация», в отличие от AppleScript `do script`.
///
/// Пустое имя = основной аккаунт: вход в стандартное место CLI (Claude —
/// `~/.claude` и базовая запись Keychain, Codex — `~/.codex`). Туда же пишут
/// приложение Claude и расширения, поэтому основной аккаунт, заведённый
/// профилем, потом появлялся второй колонкой «main».
@MainActor
enum AccountSetup {

    /// Опускание панели на время модального диалога (задаёт AppDelegate).
    /// Панель на уровне `.popUpMenu`, иначе диалог открывается под ней.
    static var suppressPanel: ((Bool) -> Void)?

    static func addClaude(completion: @escaping () -> Void) {
        guard let binary = BinaryLocator.claude() else {
            showMissingBinary(name: "claude",
                              install: "curl -fsSL https://claude.ai/install.sh | bash")
            return
        }
        let target = Target.claude
        guard let name = askProfileName(title: L.t("setup.claude.title"), target: target) else { return }

        if name.isEmpty {
            let script = """
            #!/bin/zsh
            # NotchLimits: Claude Code main account.
            unset ANTHROPIC_API_KEY
            unset CLAUDE_CONFIG_DIR
            echo "\(L.t("setup.script.profile", target.mainLabel))"
            echo "\(L.t(target.mainExists() ? "setup.script.relogin" : "setup.script.hint"))"
            "\(binary.path)"
            """
            launch(script: script, in: target.mainScriptDirectory, completion: completion)
            return
        }

        let directory = ProfileDirectories.claudeRoot.appendingPathComponent(name)
        let script = """
        #!/bin/zsh
        # NotchLimits: Claude Code profile "\(name)".
        unset ANTHROPIC_API_KEY
        export CLAUDE_CONFIG_DIR="\(directory.path)"
        echo "\(L.t("setup.script.profile", directory.path))"
        echo "\(L.t("setup.script.hint"))"
        "\(binary.path)"
        """
        launch(script: script, in: directory, completion: completion)
    }

    static func addCodex(completion: @escaping () -> Void) {
        guard let binary = BinaryLocator.codex() else {
            showMissingBinary(name: "codex", install: "brew install codex")
            return
        }
        let target = Target.codex
        guard let name = askProfileName(title: L.t("setup.codex.title"), target: target) else { return }

        if name.isEmpty {
            // Пока в ~/.codex подменён вход профиля (открыт в приложении),
            // основной живёт в запасе — туда и входим, чужой вход не трогаем.
            let home = CodexAuthSwap.liveHome(columnID: CodexAuthSwap.defaultColumnID,
                                              home: CodexAuthSwap.baseHome)
            try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            let script = """
            #!/bin/zsh
            # NotchLimits: Codex main account.
            export CODEX_HOME="\(home.path)"
            echo "\(L.t("setup.script.profile", target.mainLabel))"
            echo "\(L.t("setup.script.hint"))"
            "\(binary.path)" login
            """
            launch(script: script, in: target.mainScriptDirectory, completion: completion)
            return
        }

        let directory = ProfileDirectories.codexRoot.appendingPathComponent(name)
        let script = """
        #!/bin/zsh
        # NotchLimits: Codex profile "\(name)".
        export CODEX_HOME="\(directory.path)"
        echo "\(L.t("setup.script.profile", directory.path))"
        echo "\(L.t("setup.script.hint"))"
        "\(binary.path)" login
        """
        launch(script: script, in: directory, completion: completion)
    }

    // MARK: - Детали

    /// Куда добавляется аккаунт: папка доп. профилей и основное место CLI.
    struct Target {
        let root: URL
        /// Как показать основное место: «~/.claude» / «~/.codex».
        let mainLabel: String
        /// Есть ли уже вход в основном месте (тогда новый вход его заменит).
        let mainExists: () -> Bool
        /// Где положить скрипт входа основного аккаунта.
        let mainScriptDirectory: URL

        static let claude = Target(
            root: ProfileDirectories.claudeRoot,
            mainLabel: "~/.claude",
            mainExists: { ClaudeKeychain.services().contains(ClaudeKeychain.baseService) },
            mainScriptDirectory: DesktopApp.supportDirectory.appendingPathComponent("login/claude-main"))

        static let codex = Target(
            root: ProfileDirectories.codexRoot,
            mainLabel: "~/.codex",
            mainExists: {
                let home = CodexAuthSwap.liveHome(columnID: CodexAuthSwap.defaultColumnID,
                                                  home: CodexAuthSwap.baseHome)
                return FileManager.default.fileExists(atPath: home.appendingPathComponent("auth.json").path)
            },
            mainScriptDirectory: DesktopApp.supportDirectory.appendingPathComponent("login/codex-main"))
    }

    private static func launch(script: String, in directory: URL, completion: @escaping () -> Void) {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            let command = directory.appendingPathComponent("login.command")
            try script.write(to: command, atomically: true, encoding: .utf8)
            try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: command.path)
            NSWorkspace.shared.open(command)
        } catch {
            showAlert(title: L.t("setup.failed.title"),
                      message: error.localizedDescription)
            return
        }
        // Новый профиль подхватится сам на ближайшем цикле, но подтолкнём сразу
        // после того, как пользователь успеет закончить вход.
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { completion() }
    }

    /// Имя профиля; "" — основной аккаунт; nil — отмена.
    private static func askProfileName(title: String, target: Target) -> String? {
        NSApp.activate(ignoringOtherApps: true)

        let (alert, prompt) = makeProfileAlert(title: title, target: target)
        suppressPanel?(true)
        let response = alert.runModal()
        suppressPanel?(false)
        guard response == .alertFirstButtonReturn else { return nil }

        // «main» руками — то же, что пустое поле: основной аккаунт.
        let name = prompt.name.lowercased() == ProfileDirectories.primaryName ? "" : prompt.name
        guard ProfileNamePrompt.isValid(name, root: target.root) else {
            showAlert(title: L.t("setup.badName.title"), message: L.t("setup.badName.body"))
            return nil
        }
        return name
    }

    /// Диалог собирается отдельно от показа, чтобы его можно было отрисовать
    /// офф-скрин при проверке вёрстки.
    private static func makeProfileAlert(title: String, target: Target) -> (NSAlert, ProfileNamePrompt) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = L.t("setup.profile.hint") + "\n\n" + L.t("setup.profile.terminal")
        let createButton = alert.addButton(withTitle: L.t("setup.create"))
        alert.addButton(withTitle: L.t("common.cancel"))

        let prompt = ProfileNamePrompt(target: target) { isValid in
            createButton.isEnabled = isValid
        }
        alert.accessoryView = prompt.view
        alert.window.initialFirstResponder = prompt.field
        return (alert, prompt)
    }

    /// Только для NOTCHLIMITS_RENDER: собранный, но не показанный диалог.
    private static var renderingPrompt: ProfileNamePrompt?

    static func alertForRendering() -> NSAlert {
        let (alert, prompt) = makeProfileAlert(title: L.t("setup.claude.title"), target: .claude)
        renderingPrompt = prompt
        return alert
    }

    private static func showMissingBinary(name: String, install: String) {
        showAlert(title: L.t("setup.missing.title", name),
                  message: L.t("setup.missing.body", install))
    }

    private static func showAlert(title: String, message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: L.t("common.ok"))
        suppressPanel?(true)
        alert.runModal()
        suppressPanel?(false)
    }
}

/// Поле ввода имени профиля: показывает, какая папка получится, и не даёт
/// нажать «Создать», пока имя не годится. Пустое поле — основной аккаунт.
@MainActor
private final class ProfileNamePrompt: NSObject, NSTextFieldDelegate {

    static let placeholder = ProfileDirectories.primaryName

    let view = NSView(frame: NSRect(x: 0, y: 0, width: 330, height: 48))
    let field = NSTextField(frame: NSRect(x: 0, y: 24, width: 330, height: 24))
    private let hint = NSTextField(labelWithString: "")
    private let target: AccountSetup.Target
    private var root: URL { target.root }
    /// Считаем один раз: запрос в Keychain на каждую букву ни к чему.
    private let mainExists: Bool
    private let onValidityChange: (Bool) -> Void

    var name: String {
        field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    init(target: AccountSetup.Target, onValidityChange: @escaping (Bool) -> Void) {
        self.target = target
        self.mainExists = target.mainExists()
        self.onValidityChange = onValidityChange
        super.init()

        field.placeholderString = Self.placeholder
        field.delegate = self

        hint.frame = NSRect(x: 2, y: 2, width: 326, height: 16)
        hint.font = .systemFont(ofSize: 11)
        hint.lineBreakMode = .byTruncatingMiddle

        view.addSubview(field)
        view.addSubview(hint)
        update()
    }

    func controlTextDidChange(_ notification: Notification) {
        update()
    }

    private func update() {
        let name = self.name
        let valid = Self.isValid(name, root: root)
        onValidityChange(valid)

        if !name.isEmpty, !Self.hasAllowedCharacters(name) {
            hint.stringValue = L.t("setup.profile.badChars")
            hint.textColor = .systemRed
        } else if !name.isEmpty, Self.exists(name, root: root) {
            hint.stringValue = L.t("setup.profile.exists")
            hint.textColor = .systemRed
        } else if name.isEmpty {
            hint.stringValue = L.t(mainExists ? "setup.profile.mainReplaces" : "setup.profile.main",
                                   target.mainLabel)
            hint.textColor = mainExists ? .systemOrange : .secondaryLabelColor
        } else {
            hint.stringValue = L.t("setup.profile.folder", Self.abbreviated(root, name: name))
            hint.textColor = .secondaryLabelColor
        }
    }

    private static func abbreviated(_ root: URL, name: String) -> String {
        let path = root.appendingPathComponent(name).path
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    /// Только ASCII: имя уходит и в путь папки, и в shell-скрипт входа.
    private static let allowed = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    )

    static func hasAllowedCharacters(_ name: String) -> Bool {
        name.unicodeScalars.allSatisfy(allowed.contains) && name.first != "."
    }

    static func exists(_ name: String, root: URL) -> Bool {
        FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path)
    }

    /// Пустое имя годится: это основной аккаунт.
    static func isValid(_ name: String, root: URL) -> Bool {
        name.isEmpty || (hasAllowedCharacters(name) && !exists(name, root: root))
    }
}
