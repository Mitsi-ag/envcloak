import AppKit
import CryptoKit
import XCTest

final class PasteTests: XCTestCase {
    @MainActor func testEU1PasteBindingAndSweep() throws {
        continueAfterFailure = false
        let env = ProcessInfo.processInfo.environment
        guard let home = env["ENVCLOAK_TEST_HOME"], let runtime = env["ENVCLOAK_TEST_RUNTIME"],
              let cli = env["ENVCLOAK_TEST_CLI"], let repo = env["ENVCLOAK_TEST_REPO"] else {
            throw XCTSkip("Run scripts/macos/test-eu1.sh with its isolated real daemon")
        }
        XCTAssertTrue(home.hasPrefix("/tmp/ec05-"))
        let app = XCUIApplication()
        app.launchEnvironment = ["HOME": home, "CFFIXED_USER_HOME": home, "TMPDIR": home + "/tmp/",
            "ENVCLOAK_TEST_RUNTIME": runtime, "ENVCLOAK_TEST_CLI": cli, "ENVCLOAK_TEST_HOME": home]
        app.launch()
        addTeardownBlock { @MainActor in app.terminate() }
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let canary = ["sk", "proj", UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")].joined(separator: "-")
        let board = NSPasteboard.general
        board.clearContents(); XCTAssertTrue(board.setString(canary + "\r\n", forType: .string))
        app.typeKey("n", modifierFlags: .command)
        let field = app.secureTextFields["paste.value"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.click(); app.typeKey("v", modifierFlags: .command)
        XCTAssertTrue(app.staticTexts["Removed one final line ending."].waitForExistence(timeout: 5))
        XCTAssertNil(board.string(forType: .string), "pasted input must leave the pasteboard")
        let name = app.textFields["paste.name"]
        name.click(); name.typeText("eu-one")
        let variable = app.textFields["paste.variable"]
        variable.click(); variable.typeText("OPENAI_API_KEY")
        app.buttons["paste.save"].click()
        XCTAssertTrue(app.staticTexts["paste.saved"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["paste.saved"].label.contains("openai"))
        app.buttons["paste.bind"].click()
        try bind(app, project: "workspace-fixture", variable: "OPENAI_API_KEY", key: nil)
        try check(cli: cli, home: home, project: "workspace-fixture", variable: "OPENAI_API_KEY", slug: "eu-one")
        try openProject(app, home: home, name: "billing-fixture")
        app.buttons["binding.add"].click()
        try bind(app, project: "billing-fixture", variable: "OPENAI_API_KEY", key: "eu-one")
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: "eu-one")
        // An ordinary add on an existing variable is the Change key operation.
        app.buttons["binding.add"].click()
        try bind(app, project: "billing-fixture", variable: "OPENAI_API_KEY", key: "fixture")
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: "fixture")
        let manifest = URL(fileURLWithPath: home + "/billing-fixture/envcloak.toml")
        let original = try Data(contentsOf: manifest)
        let cell = app.tables["project.bindings"].staticTexts["OPENAI_API_KEY"].firstMatch
        XCTAssertTrue(cell.waitForExistence(timeout: 10)); cell.click()
        app.typeKey(.delete, modifierFlags: [])
        let absent = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            guard let bytes = try? Data(contentsOf: manifest) else { return false }
            return !bytes.elementsEqual(original)
        }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [absent], timeout: 10), .completed)
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: nil)
        app.typeKey("z", modifierFlags: .command)
        let restored = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            guard let bytes = try? Data(contentsOf: manifest) else { return false }
            return SHA256.hash(data: bytes) == SHA256.hash(data: original)
        }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [restored], timeout: 10), .completed)
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: "fixture")
        let running = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: "ai.envcloak.app").first {
            $0.bundleURL?.path.hasSuffix("/m306-ui/Build/Products/Debug/EnvCloak.app") == true
        })
        let pid = running.processIdentifier
        // A graceful quit exercises the saved application state writer too.
        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 15))
        try sweep(repo: repo, home: home, pid: pid, canary: canary)
    }
}
