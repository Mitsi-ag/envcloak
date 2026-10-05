import AppKit
import EnvCloakDesign
import XCTest

/// Hosted in EnvCloak.app: these run inside the launched app, so they see
/// the bundle, the scenes and the resources as a person's launch does.
final class LaunchTests: XCTestCase {
    /// Keys that would give another program a way in that skips the app's
    /// gated sheets (SPEC §12 "No side doors"), or hand the app input from
    /// outside: URL schemes, AppleScript, Services, documents to open,
    /// Handoff activities.
    static let sideDoorKeys = [
        "CFBundleURLTypes",
        "NSAppleScriptEnabled",
        "OSAScriptingDefinition",
        "NSServices",
        "CFBundleDocumentTypes",
        "UTExportedTypeDeclarations",
        "NSUserActivityTypes",
    ]

    static func sideDoors(in info: [String: Any]) -> [String] {
        sideDoorKeys.filter { info[$0] != nil }
    }

    func testTheHostIsTheApp() {
        XCTAssertEqual(Bundle.main.bundleIdentifier, "ai.envcloak.app")
        XCTAssertEqual(Bundle.main.object(forInfoDictionaryKey: "LSMinimumSystemVersion") as? String, "26.0")
    }

    @MainActor
    func testTheMainWindowOpens() {
        let opened = expectation(description: "the main window is on screen")
        let deadline = Date(timeIntervalSinceNow: 20)
        func poll() {
            if NSApp.windows.contains(where: { $0.title == "EnvCloak" && $0.isVisible }) {
                opened.fulfill()
            } else if Date() < deadline {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { poll() }
            }
        }
        poll()
        wait(for: [opened], timeout: 25)
    }

    /// About opens from the app menu only; SwiftUI would also list a
    /// `Window` scene in the Window menu unless its commands are removed.
    @MainActor
    func testAboutIsInTheMenuBarOnce() throws {
        func titles(_ menu: NSMenu) -> [String] {
            menu.items.flatMap { [$0.title] + ($0.submenu.map(titles) ?? []) }
        }
        let menu = try XCTUnwrap(NSApp.mainMenu)
        XCTAssertEqual(titles(menu).filter { $0 == "About EnvCloak" }.count, 1)
    }

    func testTheBundleHasNoSideDoor() throws {
        let info = try XCTUnwrap(Bundle.main.infoDictionary)
        XCTAssertEqual(Self.sideDoors(in: info), [])
        // Positive control: the same check finds each key when it is there.
        for key in Self.sideDoorKeys {
            var planted = info
            planted[key] = ["planted"]
            XCTAssertEqual(Self.sideDoors(in: planted), [key])
        }
    }

    func testTheBrandResourcesAreBundled() throws {
        XCTAssertTrue(ECFonts.martianMonoRegistered)
        for token in ECToken.allCases {
            XCTAssertNotNil(token.nsColor, token.rawValue)
        }
        XCTAssertNotNil(ECImage.menuTemplateNSImage)
        let icon = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "CFBundleIconName") as? String)
        XCTAssertEqual(icon, "EnvCloak")
    }
}
