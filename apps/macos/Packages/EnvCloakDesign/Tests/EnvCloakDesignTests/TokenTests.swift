import AppKit
import XCTest
@testable import EnvCloakDesign

/// The colour tokens against the table in docs/APP.md "Design tokens",
/// whose every value is checked against docs/BRAND.md §3: each token as the
/// app resolves it in light and dark, and each of its four renditions in
/// the compiled catalog (light and dark, with and without Increase
/// Contrast) as Apple's `assetutil` reads them. So a catalog value that
/// drifts from the table fails, and a table value that drifts from the
/// brand fails.
final class TokenTests: XCTestCase {
    struct Row {
        var light: UInt32
        var dark: UInt32
        /// The token whose values Increase Contrast uses, or nil for the same.
        var contrast: String?
    }

    static let repo = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // EnvCloakDesignTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // EnvCloakDesign
        .deletingLastPathComponent()  // Packages
        .deletingLastPathComponent()  // macos
        .deletingLastPathComponent()  // apps
        .deletingLastPathComponent()

    static func doc(_ path: String) throws -> String {
        try String(contentsOf: repo.appendingPathComponent(path), encoding: .utf8)
    }

    static func hexes(_ cell: Substring) -> [UInt32] {
        cell.matches(of: /#([0-9A-Fa-f]{6})/).compactMap { UInt32($0.output.1, radix: 16) }
    }

    static func cells(_ line: Substring) -> [Substring] {
        let parts = line.split(separator: "|", omittingEmptySubsequences: false)
        return parts.dropFirst().dropLast().map { $0.trimmingCharacters(in: .whitespaces)[...] }
    }

    /// A document the tests read lacks what they check: a failure, never a
    /// skip (a skipped colour test would leave the run reported as passed).
    struct DocumentChanged: Error, CustomStringConvertible {
        var description: String
    }

    /// The "Design tokens" table of docs/APP.md.
    static func table() throws -> [String: Row] {
        let text = try doc("docs/APP.md")
        guard let section = text.range(of: "## Design tokens") else {
            throw DocumentChanged(description: "docs/APP.md has no Design tokens section")
        }
        var rows: [String: Row] = [:]
        for line in text[section.upperBound...].split(separator: "\n") {
            if line.hasPrefix("## ") { break }
            guard line.hasPrefix("| `") else { continue }
            let c = cells(line)
            guard c.count >= 4, let name = c[0].firstMatch(of: /`([a-z]+)`/)?.output.1,
                  let light = hexes(c[1]).first, let dark = hexes(c[2]).first
            else { continue }
            let contrast = c[3].firstMatch(of: /`([a-z]+)`/).map { String($0.output.1) }
            rows[String(name)] = Row(light: light, dark: dark, contrast: contrast)
        }
        return rows
    }

    /// The light and dark hex values BRAND.md gives a row whose first cell
    /// is `label`, in the table whose header starts with `header`.
    static func brand(_ header: String, _ label: String, light: Int, dark: Int) throws -> (UInt32, UInt32)? {
        let text = try doc("docs/BRAND.md")
        var inTable = false
        for line in text.split(separator: "\n") {
            if line.hasPrefix("| \(header)") { inTable = true; continue }
            if inTable && !line.hasPrefix("|") { inTable = false }
            guard inTable else { continue }
            let c = cells(line)
            guard c.count > max(light, dark), c[0] == label[...] else { continue }
            if let l = hexes(c[light]).first, let d = hexes(c[dark]).first { return (l, d) }
        }
        return nil
    }

    func testTheTableNamesEveryTokenAndOnlyThose() throws {
        let rows = try Self.table()
        XCTAssertEqual(Set(rows.keys), Set(ECToken.allCases.map(\.rawValue)))
        for (name, row) in rows {
            if let other = row.contrast {
                XCTAssertNotNil(rows[other], "\(name)'s Increase Contrast names an unknown token \(other)")
            }
        }
    }

    func testTheTableIsTheBrand() throws {
        let rows = try Self.table()
        let neutrals: [String: String] = [
            "background": "Background", "raised": "Raised", "text": "Text",
            "secondary": "Secondary text", "rule": "Rule",
        ]
        for (token, label) in neutrals {
            let brand = try XCTUnwrap(try Self.brand("Token", label, light: 1, dark: 2), label)
            XCTAssertEqual(rows[token]?.light, brand.0, token)
            XCTAssertEqual(rows[token]?.dark, brand.1, token)
        }
        let semantic = ["success": "Success", "warning": "Warning", "danger": "Danger", "info": "Info"]
        for (token, label) in semantic {
            let brand = try XCTUnwrap(try Self.brand("Role", label, light: 1, dark: 3), label)
            XCTAssertEqual(rows[token]?.light, brand.0, token)
            XCTAssertEqual(rows[token]?.dark, brand.1, token)
        }
        let amber = try XCTUnwrap(try Self.brand("Name", "Amber Phosphor", light: 1, dark: 1))
        XCTAssertEqual(rows["amber"]?.light, amber.0)
        XCTAssertEqual(rows["amber"]?.dark, amber.0)
        let ink = try XCTUnwrap(try Self.brand("Name", "Ink", light: 1, dark: 1))
        XCTAssertEqual(rows["plate"]?.light, ink.0)
        let tile = try XCTUnwrap(try Self.doc("docs/BRAND.md").firstMatch(of: /uses a `#([0-9A-F]{6})` tile/))
        XCTAssertEqual(rows["plate"]?.dark, UInt32(tile.output.1, radix: 16))
    }

    /// Light and dark as the app resolves them. (Increase Contrast cannot
    /// be resolved this way: `NSAppearance(named:
    /// .accessibilityHighContrastAqua)` gives plain Aqua unless the
    /// system's Increase Contrast setting is on, measured on macOS 26.4.1,
    /// so the next test reads those renditions from the compiled catalog.)
    @MainActor
    func testEveryTokenResolvesToTheTableInLightAndDark() throws {
        let rows = try Self.table()
        for token in ECToken.allCases {
            let row = try XCTUnwrap(rows[token.rawValue], token.rawValue)
            let color = try XCTUnwrap(token.nsColor, "\(token.rawValue) is missing from the asset catalog")
            for (name, want) in [(NSAppearance.Name.aqua, row.light), (.darkAqua, row.dark)] {
                let appearance = try XCTUnwrap(NSAppearance(named: name))
                var got: UInt32?
                appearance.performAsCurrentDrawingAppearance {
                    if let c = color.usingColorSpace(.sRGB) {
                        got = Self.rgb(c.redComponent, c.greenComponent, c.blueComponent)
                    }
                }
                XCTAssertEqual(got, want, "\(token.rawValue) in \(name.rawValue)")
            }
        }
    }

    /// Every rendition of every token in the compiled catalog, as Apple's
    /// own reader (`assetutil --info`) sees it: light, dark, and Increase
    /// Contrast in each, against the table.
    func testTheCompiledCatalogHoldsEveryAppearanceOfEveryToken() throws {
        let rows = try Self.table()
        let car = try XCTUnwrap(ECDesign.bundle.url(forResource: "Assets", withExtension: "car"))
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["assetutil", "--info", car.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let entries = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        // The catalog's appearance names: none for light, DarkAqua for dark,
        // AccessibilitySystem and AccessibilityDarkAqua for Increase Contrast.
        let slots: [(String?, Bool, Bool)] = [
            (nil, false, false),
            ("NSAppearanceNameDarkAqua", true, false),
            ("NSAppearanceNameAccessibilitySystem", false, true),
            ("NSAppearanceNameAccessibilityDarkAqua", true, true),
        ]
        for token in ECToken.allCases {
            let row = try XCTUnwrap(rows[token.rawValue])
            let renditions = entries.filter { $0["Name"] as? String == token.rawValue && $0["AssetType"] as? String == "Color" }
            XCTAssertEqual(renditions.count, slots.count, "\(token.rawValue): renditions")
            for (appearance, dark, contrast) in slots {
                let source = contrast ? (row.contrast.flatMap { rows[$0] } ?? row) : row
                let want = dark ? source.dark : source.light
                let match = renditions.filter { $0["Appearance"] as? String == appearance }
                XCTAssertEqual(match.count, 1, "\(token.rawValue) \(appearance ?? "light")")
                let parts = (match.first?["Color components"] as? [Double]) ?? []
                XCTAssertEqual(match.first?["Colorspace"] as? String, "srgb")
                XCTAssertEqual(parts.count, 4)
                if parts.count == 4 {
                    XCTAssertEqual(Self.rgb(parts[0], parts[1], parts[2]), want, "\(token.rawValue) \(appearance ?? "light")")
                    XCTAssertEqual(parts[3], 1)
                }
            }
        }
    }

    static func rgb(_ r: Double, _ g: Double, _ b: Double) -> UInt32 {
        UInt32((r * 255).rounded()) << 16 | UInt32((g * 255).rounded()) << 8 | UInt32((b * 255).rounded())
    }

    func testTheMenuBarIconIsATemplateImage() throws {
        let image = try XCTUnwrap(ECImage.menuTemplateNSImage)
        XCTAssertTrue(image.isTemplate)
        XCTAssertEqual(image.size, NSSize(width: 18, height: 18))
    }

    static func srgbChannel(_ byte: UInt32) -> Double {
        let c = Double(byte & 0xFF) / 255.0
        return c <= 0.04045 ? (c / 12.92) : pow((c + 0.055) / 1.055, 2.4)
    }

    static func relativeLuminance(_ rgb: UInt32) -> Double {
        let r = srgbChannel(rgb >> 16)
        let g = srgbChannel(rgb >> 8)
        let b = srgbChannel(rgb)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    static func contrastRatio(_ fg: UInt32, _ bg: UInt32) -> Double {
        let l1 = relativeLuminance(fg)
        let l2 = relativeLuminance(bg)
        return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
    }

    func testWCAGContrastRatiosAcrossLightDarkAndIncreaseContrast() throws {
        let rows = try Self.table()
        let bgLight = try XCTUnwrap(rows["background"]?.light)
        let bgDark = try XCTUnwrap(rows["background"]?.dark)
        let raisedLight = try XCTUnwrap(rows["raised"]?.light)
        let raisedDark = try XCTUnwrap(rows["raised"]?.dark)
        let plateLight = try XCTUnwrap(rows["plate"]?.light)
        let plateDark = try XCTUnwrap(rows["plate"]?.dark)

        // Every text and semantic token must meet >= 4.5:1 against both background and raised in light and dark.
        for token in ["text", "secondary", "success", "warning", "danger", "info"] {
            let row = try XCTUnwrap(rows[token], token)
            XCTAssertGreaterThanOrEqual(
                Self.contrastRatio(row.light, bgLight),
                4.5,
                "\(token) on light background must meet WCAG AA 4.5:1"
            )
            XCTAssertGreaterThanOrEqual(
                Self.contrastRatio(row.light, raisedLight),
                4.5,
                "\(token) on light raised must meet WCAG AA 4.5:1"
            )
            XCTAssertGreaterThanOrEqual(
                Self.contrastRatio(row.dark, bgDark),
                4.5,
                "\(token) on dark background must meet WCAG AA 4.5:1"
            )
            XCTAssertGreaterThanOrEqual(
                Self.contrastRatio(row.dark, raisedDark),
                4.5,
                "\(token) on dark raised must meet WCAG AA 4.5:1"
            )
        }

        // Amber (#FFB000) is high contrast on Ink plate (light and dark) and dark surfaces,
        // and fails 4.5:1 on light background/raised (proving why Amber is forbidden on light surfaces).
        let amber = try XCTUnwrap(rows["amber"])
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(amber.light, plateLight), 4.5, "amber on light plate")
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(amber.dark, plateDark), 4.5, "amber on dark plate")
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(amber.dark, bgDark), 4.5, "amber on dark background")
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(amber.dark, raisedDark), 4.5, "amber on dark raised")
        XCTAssertLessThan(Self.contrastRatio(amber.light, bgLight), 4.5, "amber must not be used on light background")
        XCTAssertLessThan(Self.contrastRatio(amber.light, raisedLight), 4.5, "amber must not be used on light raised")

        // Increase Contrast swaps `secondary` -> `text` (>= 7:1 AAA) and `rule` -> `secondary` (>= 4.5:1 AA).
        let textRow = try XCTUnwrap(rows["text"])
        let secondaryRow = try XCTUnwrap(rows["secondary"])
        let secondaryContrastName = try XCTUnwrap(secondaryRow.contrast)
        let ruleContrastName = try XCTUnwrap(rows["rule"]?.contrast)
        XCTAssertEqual(secondaryContrastName, "text")
        XCTAssertEqual(ruleContrastName, "secondary")

        let incSecondary = try XCTUnwrap(rows[secondaryContrastName])
        let incRule = try XCTUnwrap(rows[ruleContrastName])
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(textRow.light, bgLight), 7.0)
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(textRow.dark, bgDark), 7.0)
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(incSecondary.light, bgLight), 7.0)
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(incSecondary.dark, bgDark), 7.0)
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(incRule.light, bgLight), 4.5)
        XCTAssertGreaterThanOrEqual(Self.contrastRatio(incRule.dark, bgDark), 4.5)
    }

    static let approvedAmberFiles: Set<String> = [
        "Features/Inspector/KeyInspector.swift",
    ]

    static func disallowedAmberUsages(in files: [String: String]) -> [String] {
        let amberTokenPattern = /\.amber(?:$|[^A-Za-z0-9_])/
        let approvedDarkGatePattern = /(?:^|[^A-Za-z0-9_])(colorScheme|scheme)\s*==\s*\.dark\s*\?\s*(ECToken)?\.amber(\.color)?\s*:\s*(ECToken)?\.text(\.color)?(?:$|[^A-Za-z0-9_])/
        var violations: [String] = []
        for (relPath, source) in files.sorted(by: { $0.key < $1.key }) {
            let lines = source.split(separator: "\n", omittingEmptySubsequences: false)
            for (index, line) in lines.enumerated() {
                let codeOnly = line.components(separatedBy: "//").first ?? ""
                let trimmed = codeOnly.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.contains("case amber") { continue }
                let matches = codeOnly.matches(of: amberTokenPattern)
                guard !matches.isEmpty else { continue }
                if !approvedAmberFiles.contains(relPath) {
                    violations.append("\(relPath):\(index + 1): disallowed ECToken.amber usage")
                } else if matches.count != 1 || !codeOnly.contains(approvedDarkGatePattern) {
                    violations.append("\(relPath):\(index + 1): ECToken.amber in \(relPath) must use approved dark-only ternary")
                }
            }
        }
        return violations
    }

    func testAmberTokenAppearsOnlyInApprovedCallSites() throws {
        let appRoot = Self.repo.appendingPathComponent("apps/macos/EnvCloak")
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: appRoot, includingPropertiesForKeys: nil))
        var swiftSources: [String: String] = [:]
        for case let fileURL as URL in enumerator where fileURL.pathExtension == "swift" {
            let relPath = fileURL.path.replacingOccurrences(of: appRoot.path + "/", with: "")
            swiftSources[relPath] = try String(contentsOf: fileURL, encoding: .utf8)
        }
        XCTAssertFalse(swiftSources.isEmpty)
        XCTAssertNotNil(swiftSources["Features/Keys/KeysView.swift"])
        XCTAssertNotNil(swiftSources["Features/Inspector/KeyInspector.swift"])
        let violations = Self.disallowedAmberUsages(in: swiftSources)
        XCTAssertTrue(violations.isEmpty, "Disallowed Amber token usages: \(violations)")

        // Positive control 1: explicit ECToken.amber in KeysView.swift is caught.
        var mutatedExplicit = swiftSources
        mutatedExplicit["Features/Keys/KeysView.swift", default: ""] += "\nlet bad = ECToken.amber.color\n"
        XCTAssertFalse(Self.disallowedAmberUsages(in: mutatedExplicit).isEmpty)

        // Positive control 2: implicit member .amber in KeysView.swift is caught.
        var mutatedImplicit = swiftSources
        mutatedImplicit["Features/Keys/KeysView.swift", default: ""] += "\nlet bad: ECToken = .amber\n"
        XCTAssertFalse(Self.disallowedAmberUsages(in: mutatedImplicit).isEmpty)

        // Positive control 3: inverted ternary in KeyInspector.swift is caught.
        var mutatedInverted = swiftSources
        mutatedInverted["Features/Inspector/KeyInspector.swift", default: ""] +=
            "\nlet inverted = colorScheme == .dark ? ECToken.text.color : ECToken.amber.color\n"
        XCTAssertFalse(Self.disallowedAmberUsages(in: mutatedInverted).isEmpty)

        // Positive control 4: trailing comment bypass in KeyInspector.swift is caught.
        var mutatedComment = swiftSources
        mutatedComment["Features/Inspector/KeyInspector.swift", default: ""] +=
            "\nlet bypass = ECToken.amber.color // colorScheme == .dark\n"
        XCTAssertFalse(Self.disallowedAmberUsages(in: mutatedComment).isEmpty)
    }
}
