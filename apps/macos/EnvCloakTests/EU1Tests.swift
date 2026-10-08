import AppKit
import CryptoKit
import EnvCloakKit
import SwiftUI
import XCTest
@testable import EnvCloak

/// Native secure control and real-daemon acceptance without the external
/// automation service. XCUITest remains a separate, required UI receipt.
@MainActor final class EU1Tests: XCTestCase {
    func testPasteBindingsUndoAndSweepAgainstRealDaemon() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let home = env["ENVCLOAK_TEST_HOME"], let cli = env["ENVCLOAK_TEST_CLI"],
              let repo = env["ENVCLOAK_TEST_REPO"] else {
            throw XCTSkip("Run test-eu1.sh --hosted with the private real-daemon fixture")
        }
        _ = NSApplication.shared
        let session = ScreenTestBootstrap.session()
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        let canary = ["sk", "proj", UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")].joined(separator: "-")
        let model = PasteModel()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 650), styleMask: [.titled], backing: .buffered, defer: false)
        let host = NSHostingView(rootView: PasteSheet(session: session, useInProject: { _ in }, model: model))
        window.contentView = host; window.makeKeyAndOrderFront(nil)
        NSApp.setValue(true, forKey: "accessibilityEnhancedUserInterface")
        defer { window.orderOut(nil); window.contentView = nil }
        host.layoutSubtreeIfNeeded()
        let field = try await waitField(host)
        let board = NSPasteboard.general
        board.clearContents(); XCTAssertTrue(board.setString(canary + "\r\n", forType: .string))
        XCTAssertTrue(window.makeFirstResponder(field))
        let keyDown = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero,
            modifierFlags: .command, timestamp: 0, windowNumber: window.windowNumber,
            context: nil, characters: "v", charactersIgnoringModifiers: "v", isARepeat: false, keyCode: 9))
        XCTAssertTrue(window.performKeyEquivalent(with: keyDown))
        XCTAssertEqual(model.count, canary.count)
        XCTAssertTrue(model.droppedLineEnding)
        XCTAssertNil(board.string(forType: .string))
        XCTAssertEqual(field.stringValue, "")
        model.name = "eu-one"; model.variable = "OPENAI_API_KEY"
        await model.save(session)
        let saved = try XCTUnwrap(model.saved)
        XCTAssertEqual(saved.item.provider?.escaped, "openai")
        XCTAssertEqual(saved.item.slug.escaped, "eu-one")
        XCTAssertTrue(session.items.rows.contains { $0.slug.escaped == "eu-one" })
        try await assertPasteValue("Saved as eu-one. openai, live.", identifier: "paste.saved", in: window)
        let first = DaemonText(home + "/workspace-fixture")
        let second = DaemonText(home + "/billing-fixture")
        for project in [first, second] {
            try check(cli: cli, home: home, project: project.escaped, slug: nil)
        }
        let bindingsWindow = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1024, height: 674), styleMask: [.titled], backing: .buffered, defer: false)
        bindingsWindow.isReleasedWhenClosed = false
        var environmentManager: UndoManager?
        bindingsWindow.contentView = NSHostingView(rootView: ProjectDetail(session: session, directory: second, selectedKey: .constant(nil))
            .background(UndoEnvironmentProbe { environmentManager = $0 })
            .frame(width: 1024, height: 674))
        bindingsWindow.makeKeyAndOrderFront(nil)
        bindingsWindow.contentView?.layoutSubtreeIfNeeded()
        defer { bindingsWindow.close() }
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            MainActor.assumeIsolated { environmentManager != nil }
        }, object: nil)
        await fulfillment(of: [ready], timeout: 5)
        let manager = try XCTUnwrap(environmentManager)
        XCTAssertTrue(manager === bindingsWindow.undoManager)
        for project in [first, second] {
            let ok = await session.bindings.apply(BindingEdit(project: project, profile: nil, envName: "OPENAI_API_KEY", reference: "eu-one", previous: nil), session: session, manager: manager)
            XCTAssertTrue(ok, session.notice ?? "missing notice")
            try check(cli: cli, home: home, project: project.escaped, slug: "eu-one")
        }
        let mounted = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            MainActor.assumeIsolated {
                bindingTable(in: bindingsWindow).flatMap { bindingVariableRow("OPENAI_API_KEY", table: $0) } != nil
            }
        }, object: nil)
        await fulfillment(of: [mounted], timeout: 5)
        try selectNativeBindingVariable("OPENAI_API_KEY", in: bindingsWindow)
        try await waitForBindingSelection("OPENAI_API_KEY", in: bindingsWindow)
        let changed = await session.bindings.apply(BindingEdit(project: second, profile: nil, envName: "OPENAI_API_KEY", reference: "fixture", previous: .init("eu-one")), session: session, manager: manager)
        XCTAssertTrue(changed)
        try check(cli: cli, home: home, project: second.escaped, slug: "fixture")
        let manifest = URL(fileURLWithPath: second.escaped + "/envcloak.toml")
        let original = try Data(contentsOf: manifest)
        try await waitForBindingSelection("OPENAI_API_KEY", in: bindingsWindow)
        let current = try XCTUnwrap(session.projects.opened)
        let removal = try XCTUnwrap(current.removal(of: "OPENAI_API_KEY", profile: nil))
        let removed = await session.bindings.apply(removal, session: session, manager: manager)
        XCTAssertTrue(removed)
        try check(cli: cli, home: home, project: second.escaped, slug: nil)
        let remaining = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            MainActor.assumeIsolated {
                guard let table = bindingTable(in: bindingsWindow) else { return false }
                return table.numberOfRows == 1 && table.selectedRowIndexes.isEmpty
            }
        }, object: nil)
        await fulfillment(of: [remaining], timeout: 5)
        XCTAssertTrue(manager.canUndo)
        XCTAssertEqual(manager.undoMenuItemTitle, "Undo Binding")
        XCTAssertTrue(bindingsWindow.firstResponder?.undoManager === manager)
        // Dispatch the same selector as Edit > Undo through the window,
        // after the selected row and its table have been destroyed.
        // Physical Command-Z and the focused menu remain XCUITest checks.
        XCTAssertTrue(bindingsWindow.tryToPerform(NSSelectorFromString("undo:"), with: nil))
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while ContinuousClock.now < deadline {
            if let data = try? Data(contentsOf: manifest), SHA256.hash(data: data) == SHA256.hash(data: original) { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertTrue(SHA256.hash(data: try Data(contentsOf: manifest)) == SHA256.hash(data: original))
        let confirmed = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            MainActor.assumeIsolated { session.notice == "Binding undone. The original envcloak.toml bytes were restored." }
        }, object: nil)
        await fulfillment(of: [confirmed], timeout: 5)
        try check(cli: cli, home: home, project: second.escaped, slug: "fixture")
        // A duplicate slug is refused by the real daemon. Neither the model
        // nor the mounted sheet may retain the previous success.
        var duplicate = canary
        model.receive(&duplicate)
        await model.save(session)
        XCTAssertNil(model.saved)
        XCTAssertEqual(model.count, 0)
        try await assertPasteValue("The save outcome could not be confirmed. Check Keys before pasting again. Names shaped like a key are refused.",
                                   identifier: "paste.error", in: window)
        XCTAssertTrue(pasteElements("paste.saved", in: window).isEmpty)
        model.reset(); window.orderOut(nil)
        try sweep(repo: repo, home: home, canary: canary)
    }

    private func attribute(_ object: NSObject, _ name: String) -> Any? {
        let selector = NSSelectorFromString(name)
        return object.responds(to: selector) ? object.perform(selector)?.takeUnretainedValue() : nil
    }

    private func pasteElements(_ identifier: String, in window: NSWindow) -> [NSObject] {
        var seen = Set<ObjectIdentifier>()
        func walk(_ object: NSObject, depth: Int) -> [NSObject] {
            guard depth < 40, seen.insert(ObjectIdentifier(object)).inserted else { return [] }
            let children = ["accessibilityChildren", "accessibilityRows", "accessibilityContents"]
                .flatMap { attribute(object, $0) as? [NSObject] ?? [] }
            let own = attribute(object, "accessibilityIdentifier") as? String == identifier ? [object] : []
            return own + children.flatMap { walk($0, depth: depth + 1) }
        }
        // Match XCUITest's public tree. Only the identified element's own
        // value counts, never a native subview or descendant's text.
        return walk(window, depth: 0)
    }

    private func assertPasteValue(_ expected: String, identifier: String, in window: NSWindow) async throws {
        for _ in 0..<100 {
            let elements = pasteElements(identifier, in: window)
            if elements.count == 1, attribute(elements[0], "accessibilityValue") as? String == expected { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        let observed = pasteElements(identifier, in: window).map {
            "label=\(String(describing: attribute($0, "accessibilityLabel"))), value=\(String(describing: attribute($0, "accessibilityValue")))"
        }
        XCTFail("Missing exact value for \(identifier): \(expected); observed \(observed)")
    }

    private func waitField(_ root: NSView) async throws -> SecurePasteField {
        func find(_ view: NSView) -> SecurePasteField? {
            if let field = view as? SecurePasteField { return field }
            return view.subviews.lazy.compactMap(find).first
        }
        for _ in 0..<100 {
            root.layoutSubtreeIfNeeded()
            if let field = find(root) { return field }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTFail("Native secure field did not mount")
        throw EnvCloakError.protocolError
    }

    private func check(cli: String, home: String, project: String, slug: String?) throws {
        let task = Process(); task.executableURL = URL(fileURLWithPath: cli)
        task.arguments = ["check", "--json"]; task.currentDirectoryURL = URL(fileURLWithPath: project)
        task.environment = ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": home + "/tmp/"]
        task.standardInput = FileHandle.nullDevice
        let errors = Pipe(); task.standardError = errors
        let output = Pipe(); task.standardOutput = output
        try task.run(); let data = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = errors.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
        // check.rs reports metadata only; stderr is its fixed failure line.
        let diagnostic = "envcloak check in \(project): exit \(task.terminationStatus)\nstdout:\n\(String(decoding: data, as: UTF8.self))\nstderr:\n\(String(decoding: stderr, as: UTF8.self))"
        if task.terminationStatus != 0 { print(diagnostic) }
        XCTAssertEqual(task.terminationStatus, 0, diagnostic)
        let result = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let bindings = try XCTUnwrap((result["references"] as? [String: Any])?["bindings"] as? [[String: Any]])
        let baseline = project.hasSuffix("/billing-fixture") ? "BASE" : "VARIABLE"
        XCTAssertEqual(Set(bindings.compactMap { $0["env_name"] as? String }), Set(slug == nil ? [baseline] : [baseline, "OPENAI_API_KEY"]), diagnostic)
        XCTAssertEqual(bindings.first { $0["env_name"] as? String == baseline }?["reference"] as? String, "fixture", diagnostic)
        let row = bindings.first { $0["env_name"] as? String == "OPENAI_API_KEY" }
        if let slug {
            XCTAssertEqual(row?["reference"] as? String, slug, diagnostic)
            XCTAssertEqual(row?["status"] as? String, "ok", diagnostic)
        } else { XCTAssertNil(row, diagnostic) }
    }

    private func sweep(repo: String, home: String, canary: String) throws {
        let task = Process(); task.executableURL = URL(fileURLWithPath: repo + "/scripts/macos/sweep.sh")
        task.arguments = ["--home", home, "--pid", String(ProcessInfo.processInfo.processIdentifier)]
        task.environment = ["HOME": home, "PATH": "/usr/bin:/bin:/opt/homebrew/bin"]
        let input = Pipe(); let output = Pipe(); task.standardInput = input; task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        try task.run(); try input.fileHandleForWriting.write(contentsOf: Data(canary.utf8)); try input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        // The independent fixture controller checks raw counts after XCTest
        // returns. Even a leak ends with a failing process status there.
        var receipt = report
        receipt["exit"] = task.terminationStatus
        let encoded = try JSONSerialization.data(withJSONObject: receipt)
        try encoded.write(to: URL(fileURLWithPath: home + "/eu1-sweep.json"))
    }
}

// Native AppKit selection exercises SwiftUI's binding and reload lifetime.
// Physical hit testing remains the XCUITest's responsibility.
@MainActor func bindingTable(in window: NSWindow) -> NSTableView? {
    func find(_ view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        return view.subviews.lazy.compactMap(find).first
    }
    return window.contentView.flatMap(find)
}

@MainActor func bindingVariableRow(_ variable: String, table: NSTableView) -> Int? {
    func contains(_ object: NSObject, seen: inout Set<ObjectIdentifier>) -> Bool {
        guard seen.insert(ObjectIdentifier(object)).inserted else { return false }
        func attribute(_ name: String) -> Any? {
            let selector = NSSelectorFromString(name)
            return object.responds(to: selector) ? object.perform(selector)?.takeUnretainedValue() : nil
        }
        if attribute("accessibilityIdentifier") as? String == "binding.variable." + variable { return true }
        var children = attribute("accessibilityChildren") as? [NSObject] ?? []
        if let view = object as? NSView { children += view.subviews }
        return children.contains { contains($0, seen: &seen) }
    }
    return (0..<table.numberOfRows).first { index in
        var seen = Set<ObjectIdentifier>()
        return table.view(atColumn: 0, row: index, makeIfNecessary: true).map { contains($0, seen: &seen) } == true
    }
}

@MainActor func selectNativeBindingVariable(_ variable: String, in window: NSWindow) throws {
    let table = try XCTUnwrap(bindingTable(in: window))
    let row = try XCTUnwrap(bindingVariableRow(variable, table: table))
    table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
}

@MainActor func waitForBindingSelection(_ variable: String, in window: NSWindow) async throws {
    let selected = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
        MainActor.assumeIsolated {
            guard let table = bindingTable(in: window), let row = bindingVariableRow(variable, table: table) else { return false }
            return table.selectedRowIndexes == IndexSet(integer: row)
        }
    }, object: nil)
    let result = await XCTWaiter.fulfillment(of: [selected], timeout: 5)
    XCTAssertEqual(result, .completed, "Native table must select only " + variable)
}

/// Read the actual hosting environment; never install a test UndoManager.
private struct UndoEnvironmentProbe: NSViewRepresentable {
    @Environment(\.undoManager) private var manager
    let receive: (UndoManager?) -> Void
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) { receive(manager) }
}
