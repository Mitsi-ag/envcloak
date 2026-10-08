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
        XCTAssertLessThanOrEqual(window.frame.width, 1024, "the fixture must exercise the small desktop layout")
        XCTAssertLessThanOrEqual(window.frame.height, 700, "the fixture must leave room for the menu bar and Dock")
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
        let reachable = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isHittable == true"), object: revoke)
        XCTAssertEqual(XCTWaiter.wait(for: [reachable], timeout: 10), .completed,
                       "Revoke exists but is not reachable: button=\(revoke.frame), window=\(window.frame)")
        revoke.click()
        XCTAssertTrue(window.staticTexts["No grants in force"].waitForExistence(timeout: 10))
        // The Python fixture independently checks grants.list after this test.
        app.typeKey("3", modifierFlags: .command)
        let approvals = window.descendants(matching: .any)["sidebar.Approvals"].firstMatch
        XCTAssertTrue(approvals.waitForExistence(timeout: 10))
        XCTAssertTrue(approvals.staticTexts["Arrives with Touch ID approvals"].exists)
        assertElementLabel("Approvals. Arrives with Touch ID approvals", identifier: "feature.unavailable", in: window)
    }

    @MainActor private func assertElementLabel(_ text: String, identifier: String, in window: XCUIElement,
                                               file: StaticString = #filePath, line: UInt = #line) {
        // Same contract as ScreenTests: unique identifier, exact own label.
        let matches = window.descendants(matching: .any).matching(identifier: identifier)
        let element = matches.firstMatch
        XCTAssertTrue(element.waitForExistence(timeout: 10), file: file, line: line)
        XCTAssertEqual(matches.count, 1, file: file, line: line)
        let labelled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", text), object: element)
        XCTAssertEqual(XCTWaiter.wait(for: [labelled], timeout: 10), .completed, file: file, line: line)
        XCTAssertEqual(element.label, text, file: file, line: line)
    }
}
