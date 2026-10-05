import AppKit
import CryptoKit
import SwiftUI
import XCTest
@testable import EnvCloakDesign

/// The bundled Martian Mono: the file google/fonts publishes (pinned by its
/// digest, docs/APP.md "Design tokens"), registered for the process, the
/// face `ECFont` asks for, and its licence travelling with it.
final class FontTests: XCTestCase {
    /// SHA-256 of MartianMono[wdth,wght].ttf at google/fonts commit
    /// c8bba5c4a69195e4fabc69d75136814c65fe0cf5.
    static let digest = "c3467843ec1c2574b05fbcfd7147c7bfbcf63ddca8fc2bcb9d117f1bfb1b22e7"

    func testTheBundledFontIsThePinnedFile() throws {
        let url = try XCTUnwrap(ECFonts.martianMonoURL)
        let data = try Data(contentsOf: url)
        let hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, Self.digest)
    }

    func testTheFontIsRegisteredAndIsTheFaceECFontAsksFor() throws {
        XCTAssertTrue(ECFonts.martianMonoRegistered)
        let descriptor = NSFontDescriptor(fontAttributes: [.family: ECFonts.martianMonoFamily])
        let font = try XCTUnwrap(NSFont(descriptor: descriptor, size: 12))
        XCTAssertEqual(font.familyName, ECFonts.martianMonoFamily, "the fallback face was drawn instead")
        let axes = (CTFontCopyVariationAxes(font as CTFont) as? [[String: Any]]) ?? []
        let tags = Set(axes.compactMap { ($0[kCTFontVariationAxisIdentifierKey as String] as? NSNumber)?.uint32Value })
        XCTAssertTrue(tags.contains(0x7767_6874), "no weight axis")  // 'wght'
        XCTAssertTrue(tags.contains(0x7764_7468), "no width axis")  // 'wdth'
        for axis in axes {
            let tag = (axis[kCTFontVariationAxisIdentifierKey as String] as? NSNumber)?.uint32Value
            let low = (axis[kCTFontVariationAxisMinimumValueKey as String] as? NSNumber)?.doubleValue ?? .nan
            let high = (axis[kCTFontVariationAxisMaximumValueKey as String] as? NSNumber)?.doubleValue ?? .nan
            if tag == 0x7764_7468 { XCTAssertTrue((low...high).contains(87.5), "width 87.5 out of range") }
            if tag == 0x7767_6874 { XCTAssertTrue((low...high).contains(400) && (low...high).contains(500)) }
        }
    }

    func testTheLicenceIsTheBrandsCopy() throws {
        let bundled = try Data(contentsOf: try XCTUnwrap(ECFonts.martianMonoLicenceURL))
        let brand = try Data(contentsOf: TokenTests.repo.appendingPathComponent("assets/brand/fonts/MartianMono-OFL.txt"))
        XCTAssertEqual(bundled, brand)
        XCTAssertTrue(String(decoding: bundled, as: UTF8.self).contains("SIL OPEN FONT LICENSE Version 1.1"))
    }
}
