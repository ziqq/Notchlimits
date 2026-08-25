import AppKit

@main
enum NotchLimitsApp {
    /// NSApplication.delegate — weak-ссылка, поэтому держим делегат сами.
    private static var retainedDelegate: AppDelegate?

    @MainActor
    static func main() {
        // Самопроверка не поднимает NSApplication: на CI-раннере оконный
        // сервер трогать незачем.
        if SelfTest.runIfRequested() { return }

        let application = NSApplication.shared
        let delegate = AppDelegate()
        retainedDelegate = delegate
        application.delegate = delegate
        application.setActivationPolicy(.accessory)
        application.run()
    }
}
