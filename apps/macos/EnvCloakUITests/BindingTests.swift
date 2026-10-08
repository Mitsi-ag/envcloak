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
        try requireBinding(picker.waitForExistence(timeout: 10), app: app, step: "project picker")
        picker.click()
        let projectItem = picker.menuItems.matching(NSPredicate(format: "title == %@", project)).firstMatch
        try requireBinding(projectItem.waitForExistence(timeout: 5), app: app, step: "project menu")
        projectItem.click()
        let field = app.textFields["binding.variable"]
        field.click(); field.typeKey("a", modifierFlags: .command); field.typeText(variable)
        try requireBinding(field.value as? String == variable, app: app, step: "variable input")
        if let key {
            let keyPicker = app.popUpButtons["binding.key"]
            try requireBinding(keyPicker.isEnabled, app: app, step: "key list available")
            keyPicker.click()
            // The macOS menu's AXTitle holds this metadata; AXLabel is empty.
            let item = keyPicker.menuItems.matching(NSPredicate(format: "title BEGINSWITH %@", key + " ·")).firstMatch
            try requireBinding(item.waitForExistence(timeout: 5), app: app, step: "key menu: " + key)
            item.click()
            try requireBinding((keyPicker.value as? String)?.hasPrefix(key + " ·") == true, app: app, step: "selected key")
        }
        let save = app.buttons["binding.save"]
        try requireBinding(save.isEnabled, app: app, step: "save enabled"); save.click()
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: save)
        try requireBinding(XCTWaiter.wait(for: [gone], timeout: 15) == .completed, app: app, step: "save confirmed")
    }

    @MainActor func selectBindingVariable(_ app: XCUIApplication, variable: String) throws -> XCUIElement {
        // SwiftUI's macOS Table is exposed as AXOutline on the pinned runner.
        let row = app.outlines["project.bindings"].outlineRows.containing(.staticText, identifier: "binding.variable." + variable).firstMatch
        try requireBinding(row.waitForExistence(timeout: 10), app: app, step: "binding row: " + variable)
        // A clipped OutlineRow can advertise a hit point at the scroll
        // view's right border. Target its visible variable cell instead.
        let cell = row.staticTexts["binding.variable." + variable]
        try requireBinding(cell.isHittable, app: app, step: "binding variable hittable")
        cell.click()
        let selected = XCTNSPredicateExpectation(predicate: NSPredicate(format: "selected == true"), object: row)
        try requireBinding(XCTWaiter.wait(for: [selected], timeout: 5) == .completed, app: app, step: "binding row selected")
        return cell
    }

    @MainActor func requireBinding(_ condition: Bool, app: XCUIApplication, step: String,
                                   file: StaticString = #filePath, line: UInt = #line) throws {
        if !condition {
            recordBindingState(app, step: step)
            XCTFail("Binding step failed: " + step, file: file, line: line)
            throw NSError(domain: "EU1Binding", code: 1)
        }
    }

    @MainActor func recordBindingState(_ app: XCUIApplication, step: String) {
        var state = "EU-1 binding failure: " + step + "\n"
        if let root = try? app.snapshot() {
            func descendants(_ node: any XCUIElementSnapshot) -> [any XCUIElementSnapshot] {
                [node] + node.children.flatMap(descendants)
            }
            func tree(_ node: any XCUIElementSnapshot, depth: Int = 0) -> String {
                let own = String(repeating: "  ", count: depth) + "\(node.elementType) id=\(node.identifier) title=\(node.title) label=\(node.label) enabled=\(node.isEnabled) selected=\(node.isSelected) frame=\(node.frame)\n"
                return own + node.children.map { tree($0, depth: depth + 1) }.joined()
            }
            let nodes = descendants(root)
            let sheet = nodes.first { $0.elementType == .sheet }
            state += "binding sheet accessibility tree (no values):\n" + (sheet.map { tree($0) } ?? "<no sheet>\n")
            let outline = nodes.first { $0.identifier == "project.bindings" && $0.elementType == .outline }
            state += "binding outline accessibility tree (no values):\n" + (outline.map { tree($0) } ?? "<no outline>\n")
            let picker = nodes.first { $0.identifier == "binding.key" && $0.elementType == .popUpButton }
            let labels = picker.map { descendants($0).filter { $0.elementType == .menuItem }.map { $0.title.isEmpty ? $0.label : $0.title } } ?? []
            state += "key picker menu labels: \(labels)\n"
        } else { state += "<accessibility snapshot unavailable>\n" }
        // The binding form holds metadata only. Never read AXValue while
        // dumping a tree, even if a failure leaves a different sheet open.
        print(state)
        let attachment = XCTAttachment(string: state)
        attachment.name = "EU-1 binding sheet state"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    func check(cli: String, home: String, project: String, variable: String, slug: String?) throws {
        let task = Process(); task.executableURL = URL(fileURLWithPath: cli)
        task.arguments = ["check", "--json"]
        task.currentDirectoryURL = URL(fileURLWithPath: home + "/" + project)
        task.environment = ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": home + "/tmp/"]
        task.standardInput = FileHandle.nullDevice
        let output = Pipe(); let errors = Pipe()
        task.standardOutput = output; task.standardError = errors
        try task.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = errors.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        // check.rs emits metadata-only CheckReport JSON and a fixed failure
        // message, never values. Its stderr is bounded to that failure line.
        let diagnostic = "envcloak check in \(project): exit \(task.terminationStatus)\nstdout:\n\(String(decoding: bytes, as: UTF8.self))\nstderr:\n\(String(decoding: stderr, as: UTF8.self))"
        if task.terminationStatus != 0 { print(diagnostic) }
        XCTAssertEqual(task.terminationStatus, 0, diagnostic)
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let bindings = try XCTUnwrap((parsed["references"] as? [String: Any])?["bindings"] as? [[String: Any]])
        let baseline = project == "billing-fixture" ? "BASE" : "VARIABLE"
        XCTAssertEqual(Set(bindings.compactMap { $0["env_name"] as? String }), Set(slug == nil ? [baseline] : [baseline, variable]), diagnostic)
        XCTAssertEqual(bindings.first { $0["env_name"] as? String == baseline }?["reference"] as? String, "fixture", diagnostic)
        let row = bindings.first { $0["env_name"] as? String == variable }
        if let slug {
            XCTAssertEqual(row?["reference"] as? String, slug, diagnostic)
            XCTAssertEqual(row?["status"] as? String, "ok", diagnostic)
        } else { XCTAssertNil(row, diagnostic) }
    }
}
