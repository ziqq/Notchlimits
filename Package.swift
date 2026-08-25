// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NotchLimits",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "NotchLimits",
            path: "Sources/NotchLimits"
        )
    ]
)
