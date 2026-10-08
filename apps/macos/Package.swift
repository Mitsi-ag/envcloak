// swift-tools-version: 6.2
// Native-control integration without Xcode's external automation service.
// The shipping app remains the Xcode target; this library excludes its entry.
import PackageDescription

let package = Package(
    name: "EnvCloakNativeTests",
    platforms: [.macOS(.v26)],
    dependencies: [.package(path: "Packages/EnvCloakKit"), .package(path: "Packages/EnvCloakDesign")],
    targets: [
        .target(name: "EnvCloak", dependencies: [.product(name: "EnvCloakKit", package: "EnvCloakKit"),
                                               .product(name: "EnvCloakDesign", package: "EnvCloakDesign")],
                path: "EnvCloak", exclude: ["App/EnvCloakApp.swift"],
                swiftSettings: [.define("ENVCLOAK_SCREEN_TESTS", .when(configuration: .debug))]),
        .testTarget(name: "EnvCloakNativeTests", dependencies: ["EnvCloak"], path: "EnvCloakTests",
                    exclude: ["ClipboardTests.swift", "LaunchTests.swift", "ScreenTests.swift", "SessionTests.swift"])
    ]
)
