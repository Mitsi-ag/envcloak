import XCTest

extension PasteTests {
    @MainActor func openProject(_ app: XCUIApplication, home: String, name: String) throws {
        app.typeKey("1", modifierFlags: .command)
        let button = app.buttons["project.open." + home + "/" + name]
        XCTAssertTrue(button.waitForExistence(timeout: 10)); button.click()
        XCTAssertTrue(app.buttons["binding.add"].waitForExistence(timeout: 10))
    }

    @MainActor func bind(_ app: XCUIApplication, project: String, variable: String, key: String?) throws {
        let picker = app.popUpButtons["binding.project"]
        XCTAssertTrue(picker.waitForExistence(timeout: 10))
        picker.click(); app.menuItems[project].firstMatch.click()
        let field = app.textFields["binding.variable"]
        field.click(); field.typeKey("a", modifierFlags: .command); field.typeText(variable)
        if let key {
            app.popUpButtons["binding.key"].click()
            let item = app.menuItems.matching(NSPredicate(format: "label BEGINSWITH %@", key + " ·")).firstMatch
            XCTAssertTrue(item.waitForExistence(timeout: 5)); item.click()
        }
        let save = app.buttons["binding.save"]
        XCTAssertTrue(save.isEnabled); save.click()
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: save)
        XCTAssertEqual(XCTWaiter.wait(for: [gone], timeout: 15), .completed)
    }

    func check(cli: String, home: String, project: String, variable: String, slug: String?) throws {
        let task = Process(); task.executableURL = URL(fileURLWithPath: cli)
        task.arguments = ["check", "--json"]
        task.currentDirectoryURL = URL(fileURLWithPath: home + "/" + project)
        task.environment = ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": home + "/tmp/"]
        task.standardInput = FileHandle.nullDevice
        let output = Pipe(); task.standardOutput = output; task.standardError = FileHandle.nullDevice
        try task.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit(); XCTAssertEqual(task.terminationStatus, 0)
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let bindings = try XCTUnwrap((parsed["references"] as? [String: Any])?["bindings"] as? [[String: Any]])
        let row = bindings.first { $0["env_name"] as? String == variable }
        if let slug {
            XCTAssertEqual(row?["reference"] as? String, slug)
            XCTAssertEqual(row?["status"] as? String, "ok")
        } else { XCTAssertNil(row) }
    }
}
