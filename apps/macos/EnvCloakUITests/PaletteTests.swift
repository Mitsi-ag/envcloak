import XCTest

final class PaletteTests: XCTestCase {
    @MainActor func testCommandPaletteOpensOnCommandKAndFiltersPrefixes() throws {
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
        app.typeKey("k", modifierFlags: .command)

        let search = window.descendants(matching: .any)["palette.search"].firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 10), window.debugDescription)
        search.typeText(">")
        XCTAssertTrue(window.descendants(matching: .any)["palette.item.cmd.addKey"].firstMatch.waitForExistence(timeout: 5))
    }
}
