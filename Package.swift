// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Notchlimits",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Notchlimits",
            path: "Sources/Notchlimits"
        )
    ]
)
