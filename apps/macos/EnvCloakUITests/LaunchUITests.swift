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
        // A teardown block runs after a failed assertion too, which a
        // `defer` does not when continueAfterFailure is false (the failure
        // ends the test without unwinding it), so the app never outlives
        // its test.
        addTeardownBlock { @MainActor in app.terminate() }

        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 30), "the main window did not open")
        XCTAssertTrue(window.staticTexts["Projects"].firstMatch.exists)

        let appMenu = app.menuBars.menuBarItems["EnvCloak"]
        appMenu.click()
        // One "About EnvCloak" in the whole menu bar: the About scene adds
        // no Window-menu item of its own.
        XCTAssertEqual(app.menuBars.menuItems.matching(NSPredicate(format: "title == %@", "About EnvCloak")).count, 1)
        appMenu.menus.menuItems["About EnvCloak"].click()
        let about = app.windows["About EnvCloak"]
        XCTAssertTrue(about.waitForExistence(timeout: 10), "About did not open")
        XCTAssertTrue(about.staticTexts["about.licence.font"].exists)
        XCTAssertTrue(about.staticTexts["about.version"].exists)
    }
}
