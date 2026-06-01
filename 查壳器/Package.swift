// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "APKShellInspector",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "APKShellInspectorCore", targets: ["APKShellInspectorCore"]),
        .executable(name: "APKShellInspector", targets: ["APKShellInspectorApp"]),
    ],
    targets: [
        .target(name: "APKShellInspectorCore"),
        .executableTarget(
            name: "APKShellInspectorApp",
            dependencies: ["APKShellInspectorCore"]
        ),
        .testTarget(
            name: "APKShellInspectorCoreTests",
            dependencies: ["APKShellInspectorCore"]
        ),
        .testTarget(
            name: "APKShellInspectorAppTests",
            dependencies: ["APKShellInspectorCore", "APKShellInspectorApp"]
        ),
    ]
)
