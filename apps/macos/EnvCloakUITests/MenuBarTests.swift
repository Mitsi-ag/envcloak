import XCTest

final class MenuBarTests: XCTestCase {
    @MainActor func testMenuBarToggleRendersInSettings() throws {
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
        app.typeKey(",", modifierFlags: .command)

        let toggle = window.descendants(matching: .any)["settings.menuBar"].firstMatch
        XCTAssertTrue(toggle.waitForExistence(timeout: 10), window.debugDescription)
    }
}
