import XCTest

final class ApprovalWindowTests: XCTestCase {
    @MainActor func testApprovalsViewOpensAndRendersWaitingAndInForceSections() throws {
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
        app.typeKey("3", modifierFlags: .command)

        let list = window.descendants(matching: .any)["approvals.list"].firstMatch
        XCTAssertTrue(list.waitForExistence(timeout: 10), window.debugDescription)
        XCTAssertTrue(window.staticTexts["Waiting"].waitForExistence(timeout: 10))
        XCTAssertTrue(window.staticTexts["In force"].waitForExistence(timeout: 10))
    }
}
