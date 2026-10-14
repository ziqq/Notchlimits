import AppKit
import SwiftUI

enum L {
    private static let strings = NSDictionary(contentsOfFile: CommandLine.arguments[3]) as? [String: String] ?? [:]
    static func t(_ key: String, _ arguments: CVarArg...) -> String {
        let format = strings[key] ?? key
        return arguments.isEmpty ? format : String(format: format, locale: Locale.current, arguments: arguments)
    }
}

extension View {
    // Control hit-testing is outside these clock tests.
    func reportsControlFrame() -> some View { self }
}

@main
enum TimeLabels {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let scenario = CommandLine.arguments[1]
        let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        var column = AccountColumn(id: "synthetic", provider: .codex, profileName: "synthetic")
        if scenario == "age" {
            column.updatedAt = Date().addingTimeInterval(-10)
            column.status = .waiting(until: Date().addingTimeInterval(60))
        }
        column.windows = [LimitWindow(key: "synthetic", title: "Synthetic window", utilization: 42,
                                      resetsAt: scenario == "reset" ? Date().addingTimeInterval(2) : nil)]
        // One changing label per scenario. The immutable column is never reassigned.
        let root = ColumnView(column: column)
            .padding(20)
            .frame(width: 260, height: 180, alignment: .topLeading)
            .background(Color.black)
        let host = NSHostingView(rootView: root)
        let panel = NSPanel(contentRect: NSRect(x: 30, y: 30, width: 260, height: 180),
                            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isReleasedWhenClosed = false
        panel.contentView = host
        panel.orderFrontRegardless()

        var before: Data?
        func snapshot(_ name: String) -> Data? {
            host.layoutSubtreeIfNeeded()
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return nil }
            host.cacheDisplay(in: host.bounds, to: rep)
            if let png = rep.representation(using: .png, properties: [:]) {
                try? png.write(to: directory.appendingPathComponent(name))
            }
            // Compare rendered pixels, not PNG metadata.
            guard let image = rep.cgImage, let data = image.dataProvider?.data else { return nil }
            let raw = data as Data
            let rowLength = (image.width * image.bitsPerPixel + 7) / 8
            var pixels = Data(capacity: rowLength * image.height)
            for row in 0..<image.height {
                let start = row * image.bytesPerRow
                pixels.append(raw[start..<(start + rowLength)])
            }
            return pixels
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            before = snapshot("before.png")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            let after = snapshot("after.png")
            panel.close()
            guard let before, let after, !before.isEmpty, !after.isEmpty else {
                FileHandle.standardError.write(Data("FAIL: panel pixels could not be captured\n".utf8))
                exit(1)
            }
            guard before != after else {
                FileHandle.standardError.write(Data("FAIL: \(scenario) label stayed frozen without new usage data\n".utf8))
                exit(1)
            }
            print("PASS: \(scenario) label updated without new usage data")
            exit(0)
        }
        app.run()
    }
}
