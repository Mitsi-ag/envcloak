// swift-tools-version: 6.2
// EnvCloakKit: the app's Swift socket client. Test support is a separate
// target, never a dependency of the shipping library or app.
import PackageDescription

let package = Package(
    name: "EnvCloakKit",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "EnvCloakKit", targets: ["EnvCloakKit"]),
        .library(name: "EnvCloakKitTestSupport", targets: ["EnvCloakKitTestSupport"])
    ],
    targets: [
        .target(
            name: "EnvCloakKit"
        ),
        .target(name: "EnvCloakKitTestSupport"),
        .testTarget(
            name: "EnvCloakKitTests",
            dependencies: ["EnvCloakKit", "EnvCloakKitTestSupport"]
        ),
    ]
)
