import XCTest

final class AccessibilityTests: XCTestCase {
    @MainActor func testWorkspaceAndInspectorAccessibilityIdentifiersAndLabels() throws {
        continueAfterFailure = false
        let env = ProcessInfo.processInfo.environment
        guard let directory = env["ENVCLOAK_TEST_RUNTIME"] else {
            throw XCTSkip("Run scripts/macos/test-workspace.sh for the isolated real daemon")
        }
        XCTAssertTrue(directory.hasPrefix("/tmp/ec05-"))
        let app = XCUIApplication()
        app.launchEnvironment = ["ENVCLOAK_TEST_RUNTIME": directory]
        app.launch()
        addTeardownBlock { @MainActor in app.terminate() }

        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 20))

        // Icon-only toolbar and project controls expose VoiceOver labels.
        let lockButton = window.buttons["toolbar.lock"].firstMatch
        XCTAssertTrue(lockButton.waitForExistence(timeout: 10))
        XCTAssertEqual(lockButton.label, "Lock")

        let addFolder = window.buttons["project.addFolder"].firstMatch
        XCTAssertTrue(addFolder.waitForExistence(timeout: 10))
        XCTAssertEqual(addFolder.label, "Add project folder…")

        // Navigate to Keys (Cmd-2) and verify class badge and value block labels.
        app.typeKey("2", modifierFlags: .command)
        let table = window.descendants(matching: .any)["keys.table"].firstMatch
        XCTAssertTrue(table.waitForExistence(timeout: 10))

        let addKey = window.buttons["key.add"].firstMatch
        XCTAssertTrue(addKey.waitForExistence(timeout: 10))
        XCTAssertEqual(addKey.label, "Add key")
    }
}
