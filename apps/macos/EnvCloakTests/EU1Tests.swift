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
        let manager = UndoManager(); manager.groupsByEvent = false
        let first = DaemonText(home + "/workspace-fixture")
        let second = DaemonText(home + "/billing-fixture")
        for project in [first, second] {
            try check(cli: cli, home: home, project: project.escaped, slug: nil)
        }
        for project in [first, second] {
            manager.beginUndoGrouping()
            let ok = await session.bindings.apply(BindingEdit(project: project, profile: nil, envName: "OPENAI_API_KEY", reference: "eu-one", previous: nil), session: session, manager: manager)
            manager.endUndoGrouping(); XCTAssertTrue(ok, session.notice ?? "missing notice")
            try check(cli: cli, home: home, project: project.escaped, slug: "eu-one")
        }
        manager.beginUndoGrouping()
        let changed = await session.bindings.apply(BindingEdit(project: second, profile: nil, envName: "OPENAI_API_KEY", reference: "fixture", previous: .init("eu-one")), session: session, manager: manager)
        manager.endUndoGrouping(); XCTAssertTrue(changed)
        try check(cli: cli, home: home, project: second.escaped, slug: "fixture")
        let manifest = URL(fileURLWithPath: second.escaped + "/envcloak.toml")
        let original = try Data(contentsOf: manifest)
        manager.beginUndoGrouping()
        let removed = await session.bindings.apply(BindingEdit(project: second, profile: nil, envName: "OPENAI_API_KEY", reference: nil, previous: .init("fixture")), session: session, manager: manager)
        manager.endUndoGrouping(); XCTAssertTrue(removed)
        try check(cli: cli, home: home, project: second.escaped, slug: nil)
        manager.undo()
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while ContinuousClock.now < deadline {
            if let data = try? Data(contentsOf: manifest), SHA256.hash(data: data) == SHA256.hash(data: original) { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertTrue(SHA256.hash(data: try Data(contentsOf: manifest)) == SHA256.hash(data: original))
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
