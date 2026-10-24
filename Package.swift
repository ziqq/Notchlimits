// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Notchlimits",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
        .package(url: "https://github.com/dduan/TOMLDecoder", exact: "0.4.4")
    ],
    targets: [
        .executableTarget(
            name: "Notchlimits",
            dependencies: [
                .product(name: "Sparkle", package: "Sparkle"),
                .product(name: "TOMLDecoder", package: "TOMLDecoder")
            ],
            path: "Sources/Notchlimits",
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])
            ]
        )
    ]
)
