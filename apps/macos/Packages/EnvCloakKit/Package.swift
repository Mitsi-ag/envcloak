// swift-tools-version: 6.2
// EnvCloakKit: the app's client for envcloakd (docs/APP.md "The Swift
// client"). Task M3-03 adds the wire format, SecretBuffer, the client-side
// peer checks and the typed calls; M3-02 lays out the package and the
// logging rule every later file follows.
import PackageDescription

let package = Package(
    name: "EnvCloakKit",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "EnvCloakKit", targets: ["EnvCloakKit"])
    ],
    targets: [
        .target(
            name: "EnvCloakKit"
        ),
        .testTarget(
            name: "EnvCloakKitTests",
            dependencies: ["EnvCloakKit"]
        ),
    ]
)
