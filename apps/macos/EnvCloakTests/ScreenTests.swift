import AppKit
import SwiftUI
import XCTest
@testable import EnvCloak
@testable import EnvCloakKit

@MainActor final class ScreenTests: XCTestCase {
    #if ENVCLOAK_SCREEN_TESTS
    func testAutomationWindowFitsSmallAndOffsetDisplays() {
        // Geometry in points, including a small CI desktop with menu and
        // Dock space removed and displays left of or above the primary.
        for bounds in [
            NSRect(x: 0, y: 64, width: 1024, height: 680),
            NSRect(x: -1280, y: 36, width: 1280, height: 960),
            NSRect(x: 100, y: 1100, width: 1728, height: 1000),
        ] {
            let frame = ScreenTestBootstrap.windowFrame(in: bounds)
            XCTAssertTrue(bounds.contains(frame), "automation window \(frame) exceeds usable display \(bounds)")
            XCTAssertGreaterThanOrEqual(frame.width, 900)
            XCTAssertGreaterThanOrEqual(frame.height, 560)
            // Exercise the constrained layout on large local displays too.
            XCTAssertLessThanOrEqual(frame.width, 1024)
            XCTAssertLessThanOrEqual(frame.height, 700)
        }
    }
    #endif

    private func host<V: View>(_ view: V) -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 740), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: view.frame(width: 1180, height: 740))
        window.setContentSize(NSSize(width: 1180, height: 740))
        window.makeKeyAndOrderFront(nil)
        window.contentView?.layoutSubtreeIfNeeded()
        NSApp.setValue(true, forKey: "accessibilityEnhancedUserInterface")
        addTeardownBlock { @MainActor in window.close() }
        return window
    }

    private func labels(_ object: Any) -> [String] {
        var seen = Set<ObjectIdentifier>()
        func walk(_ object: Any, depth: Int) -> [String] {
            guard depth < 40, let node = object as? NSObject, seen.insert(ObjectIdentifier(node)).inserted else { return [] }
            // SwiftUI nodes implement the accessors without declaring
            // AppKit's full protocol. Native table cells are virtualized.
            func attribute(_ name: String) -> Any? {
                let selector = NSSelectorFromString(name)
                guard node.responds(to: selector) else { return nil }
                return node.perform(selector)?.takeUnretainedValue()
            }
            let own = ["accessibilityLabel", "accessibilityValue", "accessibilityTitle"].compactMap { attribute($0) as? String }
            var children = ["accessibilityChildren", "accessibilityRows", "accessibilityContents"].flatMap { (attribute($0) as? [Any]) ?? [] }
            if let view = node as? NSView { children += view.subviews }
            if let window = node as? NSWindow, let view = window.contentView { children.append(view) }
            return own + children.flatMap { walk($0, depth: depth + 1) }
        }
        return walk(object, depth: 0)
    }

    private func assertVisible(_ text: String, in window: NSWindow, file: StaticString = #filePath, line: UInt = #line) async {
        let found = XCTNSPredicateExpectation(predicate: NSPredicate { [self, window] _, _ in
            MainActor.assumeIsolated { labels(window).contains(text) }
        }, object: nil)
        await fulfillment(of: [found], timeout: 5)
        XCTAssertTrue(labels(window).contains(text), "missing accessibility text: " + text + " found=" + labels(window).joined(separator: " | "), file: file, line: line)
    }

    func testConnectionStatesHaveAccessibleCopyAndActions() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        for (state, title, action) in [
            (ConnectionState.noDaemon, "No daemon answered, so no key was released.", "Start background process"),
            (.unverified(.peerUID), "EnvCloak could not verify its background process, so nothing was sent to it.", "Show details"),
            (.noVault, "No vault yet.", "Copy command"),
            (.locked, "EnvCloak is locked. Agents get no keys until you unlock.", "Copy envcloak unlock"),
            (.readOnly, "The vault failed its integrity check, so it is open read-only.", "How to recover"),
            (.unavailable, "The vault is unavailable.", "Copy envcloak status"),
        ] {
            session.state = state
            let window = host(ConnectionView(session: session))
            await assertVisible(title, in: window)
            await assertVisible(action, in: window)
            window.close()
        }
        session.state = .connecting
        let connecting = host(ConnectionView(session: session))
        await assertVisible("Connecting to EnvCloak's background process", in: connecting)
        let banner = host(DevelopmentBanner())
        await assertVisible("Daemon identity unverified", in: banner)
        await assertVisible("Open guarantees", in: banner)
    }

    func testGate31HostileProjectNameAndSlugOnAccessibilityTree() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll(); await session.openProject(DaemonText("/tmp/project"))
        let project = host(ProjectDetail(session: session, directory: DaemonText("/tmp/project"), selectedKey: .constant(nil)))
        await assertVisible("project\\u{202e}\\u{1b}[31m", in: project)
        XCTAssertFalse(labels(project).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
        let keys = host(KeyInspector(session: session, slug: session.items.rows.first?.slug, route: .constant(.keys(.all))))
        await assertVisible("fixture-0\\u{202e}\\u{1b}[31m", in: keys)
        XCTAssertFalse(labels(keys).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
    }

    func testAliasProjectShowsGrantsAndBindingAccess() async throws {
        let root = URL(fileURLWithPath: "/tmp/ec05-alias-" + UUID().uuidString.prefix(8))
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data("fixture".utf8).write(to: project.appendingPathComponent("envcloak.toml"))
        let alias = root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: project)
        let client = ScriptedClient(); await client.plainSlugs(); await client.configure(grants: 1)
        let session = VaultSession(client: client); await session.poll()
        let window = host(ProjectDetail(session: session, directory: DaemonText(alias.path), selectedKey: .constant(nil)))
        await assertVisible("Revoke", in: window)
        XCTAssertTrue(labels(window).contains { $0.hasPrefix("Grant recorded for Fixture grant") })
        XCTAssertFalse(labels(window).contains("No grants in force"))
    }

    func testInspectorActionsAreUnavailableOrFieldQualified() async throws {
        let client = ScriptedClient(); await client.plainSlugs()
        let session = VaultSession(client: client); await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        let reveal = host(InspectorActionSheet(action: .reveal, item: item, field: nil))
        await assertVisible("Reveal is unavailable in this build.", in: reveal)
        XCTAssertFalse(labels(reveal).contains("Copy command"))
        reveal.close()
        let replace = host(InspectorActionSheet(action: .replace, item: item, field: DaemonText("secondary")))
        await assertVisible("envcloak rotate 'fixture-0#secondary'", in: replace)
        await assertVisible("Copy command", in: replace)
        replace.close()
        let inspector = host(KeyInspector(session: session, slug: item.slug, route: .constant(.keys(.all))))
        await assertVisible("Field to replace", in: inspector)
    }

    func testUpgradeReadOnlyBannerKeepsWorkspaceVisible() async {
        let client = ScriptedClient(); await client.configure(readOnly: true)
        let session = VaultSession(client: client); await session.poll()
        let window = host(MainView(session: session))
        await assertVisible("The vault opened read-only because an upgrade failed.", in: window)
        await assertVisible("Keys and projects are still readable. Changes are disabled. The next unlock retries the upgrade.", in: window)
        await assertVisible("project, /tmp/project, 0 adopted bindings", in: window)
        XCTAssertFalse(labels(window).contains("How to recover"))
        XCTAssertFalse(labels(window).contains("Metadata unavailable"))
    }

    func testReadOnlyBannerExplainsMetadataRefusal() async {
        let client = ScriptedClient(); await client.configure(integrity: "tampered")
        let session = VaultSession(client: client); await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        let window = host(MainView(session: session))
        await assertVisible("The vault failed its integrity check, so it is open read-only.", in: window)
        await assertVisible("How to recover", in: window)
        await assertVisible("Metadata unavailable", in: window)
        XCTAssertFalse(labels(window).contains("No projects yet."))
    }

    func testInspectorFetchesAndEscapesFullMetadata() async {
        let client = ScriptedClient(); let session = VaultSession(client: client); await session.poll()
        let window = host(KeyInspector(session: session, slug: session.items.rows.first?.slug, route: .constant(.keys(.all))))
        await assertVisible("Notes 1\\u{202e}", in: window)
        await assertVisible("api.example.invalid", in: window)
        XCTAssertFalse(labels(window).contains { $0.contains("\u{202e}") })
    }

    func testHiddenProjectsAndFailedProjectSearchAreExplicit() async {
        let client = ScriptedClient(); await client.pages("hidden-one-page")
        let session = VaultSession(client: client); await session.poll()
        let projects = host(ProjectsOverview(session: session, route: .constant(.projects)))
        await assertVisible("Folder path hidden: it looks like a key or token", in: projects)
        XCTAssertFalse(labels(projects).contains("No projects yet."))
        await client.configure(projectFailure: true)
        await client.pages("single")
        await session.projects.refetch(.projects)
        let keys = host(KeysView(session: session, filter: .all, query: "PrOjEcT:fixture provider:example", scope: nil, grouping: .constant(.none), selectedKey: .constant(nil)))
        await assertVisible("Keys could not be refreshed", in: keys)
        XCTAssertFalse(labels(keys).contains("No matching keys"))
    }

    func testUnavailableRowsAreAccessible() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        let window = host(MainView(session: session, initialRoute: .settings))
        await assertVisible("project\\u{202e}\\u{1b}[31m", in: window)
        await assertVisible("Arrives with Touch ID approvals", in: window)
        await assertVisible("Spend · M4", in: window)
        await assertVisible("Devices · M5", in: window)
        await assertVisible("Leak checks arrive with envcloak doctor", in: window)
    }

    func testTwoThousandKeysRenderAndScrollWithoutLoader() async {
        let client = ScriptedClient(); await client.configure(itemCount: 2000)
        let session = VaultSession(client: client)
        let start = ContinuousClock.now
        await session.poll()
        let window = host(KeysView(session: session, filter: .all, query: "", scope: nil, grouping: .constant(.none), selectedKey: .constant(nil)))
        await assertVisible("2,000 keys", in: window)
        func table(_ view: NSView) -> NSTableView? {
            if let table = view as? NSTableView { return table }
            return view.subviews.lazy.compactMap(table).first
        }
        let native = try? XCTUnwrap(window.contentView.flatMap(table))
        XCTAssertNotNil(native)
        XCTAssertEqual(native?.numberOfRows, 2000)
        native?.scrollRowToVisible(1999)
        window.contentView?.layoutSubtreeIfNeeded()
        XCTAssertFalse(labels(window).contains { $0.contains("Connecting") || $0 == "Loading" })
        let elapsed = start.duration(to: .now)
        XCTAssertLessThan(elapsed, .seconds(10))
        let measurement = XCTAttachment(string: "2000 keys, first render and native scroll: \(elapsed)")
        measurement.lifetime = .keepAlways
        add(measurement)
    }
}
