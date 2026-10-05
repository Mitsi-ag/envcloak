// swift-tools-version: 6.2
// EnvCloakDesign: the brand tokens the app draws with (docs/APP.md
// "Design tokens"). Colours come from the asset catalog, type from the
// bundled Martian Mono, and motion from assets/brand/motion/swiftui/
// EnvCloakMotion.swift, which Sources/EnvCloakDesign/EnvCloakMotion.swift
// links to rather than copies (M3 plan §5 rule 5).
import PackageDescription

let package = Package(
    name: "EnvCloakDesign",
    defaultLocalization: "en",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "EnvCloakDesign", targets: ["EnvCloakDesign"])
    ],
    targets: [
        .target(
            name: "EnvCloakDesign",
            resources: [
                .process("Resources/Colors.xcassets"),
                .copy("Resources/Fonts"),
            ]
        ),
        .testTarget(
            name: "EnvCloakDesignTests",
            dependencies: ["EnvCloakDesign"]
        ),
    ]
)
