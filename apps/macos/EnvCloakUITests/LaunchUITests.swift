import XCTest

/// The app launched the way a person launches it, driven through the
/// accessibility tree: the main window, then About from the app menu.
/// XCUITest runs on main, nightly and manual CI runs until it is shown
/// stable on pull requests (M3 plan K3-07).
final class LaunchUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsTheMainWindowAndAbout() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        let window = app.windows["EnvCloak"]
        XCTAssertTrue(window.waitForExistence(timeout: 30), "the main window did not open")
        XCTAssertTrue(window.staticTexts["envcloak status"].exists)

        app.menuBars.menuBarItems["EnvCloak"].click()
        app.menuBars.menuItems["About EnvCloak"].click()
        let about = app.windows["About EnvCloak"]
        XCTAssertTrue(about.waitForExistence(timeout: 10), "About did not open")
        XCTAssertTrue(about.staticTexts["about.licence.font"].exists)
        XCTAssertTrue(about.staticTexts["about.version"].exists)
    }
}
