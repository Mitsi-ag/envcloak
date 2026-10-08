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
        XCTAssertEqual(env["ENVCLOAK_TEST_STORY"], "eu1", "EU-1 requires its two-project fixture")
        let app = XCUIApplication()
        app.launchEnvironment = ["HOME": home, "CFFIXED_USER_HOME": home, "TMPDIR": home + "/tmp/",
            "ENVCLOAK_TEST_RUNTIME": runtime, "ENVCLOAK_TEST_CLI": cli, "ENVCLOAK_TEST_HOME": home]
        app.launch()
        addTeardownBlock { @MainActor in
            if (self.testRun?.totalFailureCount ?? 0) > 0 {
                self.recordPasteState(app)
                self.recordBindingState(app, step: "teardown")
            }
            app.terminate()
        }
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        for project in ["workspace-fixture", "billing-fixture"] {
            try check(cli: cli, home: home, project: project, variable: "OPENAI_API_KEY", slug: nil)
        }
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
        XCTAssertEqual(name.value as? String, "eu-one", "Name input did not reach the sheet")
        XCTAssertEqual(variable.value as? String, "OPENAI_API_KEY", "Variable input did not reach the sheet")
        app.buttons["paste.save"].click()
        XCTAssertTrue(app.staticTexts["paste.saved"].waitForExistence(timeout: 15), "Save did not produce a confirmed result")
        // macOS static text exposes its content as AXValue, not AXLabel.
        XCTAssertEqual(app.staticTexts["paste.saved"].value as? String, "Saved as eu-one. openai, live.")
        app.buttons["paste.bind"].click()
        try bind(app, project: "workspace-fixture", variable: "OPENAI_API_KEY", key: nil)
        try check(cli: cli, home: home, project: "workspace-fixture", variable: "OPENAI_API_KEY", slug: "eu-one")
        try openProject(app, home: home, name: "billing-fixture")
        app.buttons["binding.add"].click()
        try bind(app, project: "billing-fixture", variable: "OPENAI_API_KEY", key: "eu-one")
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: "eu-one")
        let changedCell = try selectBindingVariable(app, variable: "OPENAI_API_KEY")
        changedCell.rightClick()
        let change = app.menuItems.matching(NSPredicate(format: "title == %@", "Change key…")).firstMatch
        try requireBinding(change.waitForExistence(timeout: 5), app: app, step: "Change key menu")
        change.click()
        try bind(app, project: "billing-fixture", variable: "OPENAI_API_KEY", key: "fixture")
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: "fixture")
        let manifest = URL(fileURLWithPath: home + "/billing-fixture/envcloak.toml")
        let original = try Data(contentsOf: manifest)
        _ = try selectBindingVariable(app, variable: "OPENAI_API_KEY")
        app.typeKey(.delete, modifierFlags: [])
        let absent = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            guard let bytes = try? Data(contentsOf: manifest) else { return false }
            return !bytes.elementsEqual(original)
        }, object: nil)
        try requireBinding(XCTWaiter.wait(for: [absent], timeout: 10) == .completed, app: app, step: "Delete writes manifest")
        try check(cli: cli, home: home, project: "billing-fixture", variable: "OPENAI_API_KEY", slug: nil)
        // Validate the command that Command-Z will dispatch, after the
        // focused sheet editor has gone and the table has processed Delete.
        app.menuBars.menuBarItems["Edit"].click()
        let undo = app.menuItems.matching(NSPredicate(format: "title == %@", "Undo Binding")).firstMatch
        try requireBinding(undo.waitForExistence(timeout: 5) && undo.isEnabled, app: app, step: "Undo Binding available")
        app.typeKey(.escape, modifierFlags: [])
        app.typeKey("z", modifierFlags: .command)
        let restored = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            guard let bytes = try? Data(contentsOf: manifest) else { return false }
            return SHA256.hash(data: bytes) == SHA256.hash(data: original)
        }, object: nil)
        try requireBinding(XCTWaiter.wait(for: [restored], timeout: 10) == .completed, app: app, step: "Command-Z exact undo")
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

    @MainActor private func recordPasteState(_ app: XCUIApplication) {
        let state: String
        if app.state == .notRunning || app.state == .unknown {
            state = "EU-1 failure: application state \(app.state); no running app or visible sheet."
        } else {
            let sheet = app.sheets.firstMatch
            let saved = app.staticTexts["paste.saved"]
            let error = app.staticTexts["paste.error"]
            state = """
            EU-1 failure: visible paste state
            saved exists: \(saved.exists); label: \(saved.exists ? saved.label : "<absent>"); value: \(saved.exists ? String(describing: saved.value) : "<absent>")
            error exists: \(error.exists); text: \(error.exists ? String(describing: error.value) : "<absent>")
            sheet accessibility tree:
            \(sheet.exists ? sheet.debugDescription : "<no sheet>\n" + app.windows.debugDescription)
            """
        }
        // Only this isolated generated-value fixture prints a tree. Capture
        // before termination, including when an assertion aborts the test.
        print(state)
        let attachment = XCTAttachment(string: state)
        attachment.name = "EU-1 visible sheet state"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
