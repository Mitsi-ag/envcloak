import XCTest

final class NavigationTests: XCTestCase {
    @MainActor func testProjectsKeysAndRevokeAgainstRealDaemon() throws {
        continueAfterFailure = false
        let env = ProcessInfo.processInfo.environment
        guard let directory = env["ENVCLOAK_TEST_RUNTIME"], let project = env["ENVCLOAK_TEST_PROJECT"] else {
            throw XCTSkip("Run scripts/macos/test-workspace.sh for the isolated real daemon")
        }
        XCTAssertTrue(directory.hasPrefix("/tmp/ec05-"))
        let app = XCUIApplication()
        app.launchEnvironment = ["ENVCLOAK_TEST_RUNTIME": directory]
        app.launch()
        addTeardownBlock { @MainActor in app.terminate() }
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 20))
        app.typeKey("2", modifierFlags: .command)
        XCTAssertTrue(window.descendants(matching: .any)["keys.table"].firstMatch.waitForExistence(timeout: 10), window.debugDescription)
        XCTAssertTrue(window.staticTexts["fixture"].firstMatch.exists)
        app.typeKey("1", modifierFlags: .command)
        let projectButton = window.buttons["project.open." + project].firstMatch
        XCTAssertTrue(projectButton.waitForExistence(timeout: 10), window.debugDescription)
        app.activate()
        projectButton.click()
        XCTAssertTrue(window.descendants(matching: .any)["project.title"].firstMatch.waitForExistence(timeout: 10), window.debugDescription)
        XCTAssertTrue(window.staticTexts["Resolves"].waitForExistence(timeout: 10), window.debugDescription)
        let revoke = window.buttons["Revoke"]
        XCTAssertTrue(revoke.waitForExistence(timeout: 10))
        revoke.click()
        XCTAssertTrue(window.staticTexts["No grants in force"].waitForExistence(timeout: 10))
        // The Python fixture independently checks grants.list after this test.
        app.typeKey("3", modifierFlags: .command)
        XCTAssertTrue(window.staticTexts["Arrives with Touch ID approvals"].exists)
    }
}
