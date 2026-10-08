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

    private func nodes(_ object: Any, includingNativeViews: Bool = true) -> [NSObject] {
        var seen = Set<ObjectIdentifier>()
        func walk(_ object: Any, depth: Int) -> [NSObject] {
            guard depth < 40, let node = object as? NSObject, seen.insert(ObjectIdentifier(node)).inserted else { return [] }
            // SwiftUI nodes implement the accessors without declaring
            // AppKit's full protocol. Native table cells are virtualized.
            func attribute(_ name: String) -> Any? {
                let selector = NSSelectorFromString(name)
                guard node.responds(to: selector) else { return nil }
                return node.perform(selector)?.takeUnretainedValue()
            }
            var children = ["accessibilityChildren", "accessibilityRows", "accessibilityContents"].flatMap { (attribute($0) as? [Any]) ?? [] }
            if includingNativeViews, let view = node as? NSView { children += view.subviews }
            if includingNativeViews, let window = node as? NSWindow, let view = window.contentView { children.append(view) }
            return [node] + children.flatMap { walk($0, depth: depth + 1) }
        }
        return walk(object, depth: 0)
    }

    private func labels(_ object: Any) -> [String] {
        nodes(object).flatMap { node in
            ["accessibilityLabel", "accessibilityValue", "accessibilityTitle"].compactMap { name in
                let selector = NSSelectorFromString(name)
                guard node.responds(to: selector) else { return nil }
                return node.perform(selector)?.takeUnretainedValue() as? String
            }
        }
    }

    private func identified(_ id: String, in window: NSWindow, accessibilityOnly: Bool = false) -> [NSObject] {
        nodes(window, includingNativeViews: !accessibilityOnly).filter { node in
            let selector = NSSelectorFromString("accessibilityIdentifier")
            return node.responds(to: selector) && node.perform(selector)?.takeUnretainedValue() as? String == id
        }
    }

    private func assertScoped(_ text: String, identifier: String, in window: NSWindow,
                              file: StaticString = #filePath, line: UInt = #line) async {
        let found = XCTNSPredicateExpectation(predicate: NSPredicate { [self, window] _, _ in
            MainActor.assumeIsolated { identified(identifier, in: window).contains { labels($0).contains { $0.contains(text) } } }
        }, object: nil)
        await fulfillment(of: [found], timeout: 5)
        XCTAssertTrue(identified(identifier, in: window).contains { labels($0).contains { $0.contains(text) } },
                      "missing scoped accessibility text: " + identifier + " / " + text, file: file, line: line)
    }

    private func assertElementLabel(_ text: String, identifier: String, in window: NSWindow,
                                    file: StaticString = #filePath, line: UInt = #line) async {
        // Match XCUITest: one element with this identifier, and its own label.
        // Only the public accessibility tree is searched, without native view
        // subviews. Descendants, values and titles cannot supply the label.
        func matches() -> Bool {
            let elements = identified(identifier, in: window, accessibilityOnly: true)
            guard elements.count == 1, let element = elements.first else { return false }
            let selector = NSSelectorFromString("accessibilityLabel")
            return element.responds(to: selector) && element.perform(selector)?.takeUnretainedValue() as? String == text
        }
        let found = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            MainActor.assumeIsolated { matches() }
        }, object: nil)
        await fulfillment(of: [found], timeout: 5)
        XCTAssertTrue(matches(), "missing exact element label: " + identifier + " / " + text, file: file, line: line)
    }

    private func assertDisabled(_ title: String, in window: NSWindow, file: StaticString = #filePath, line: UInt = #line) {
        let states: [Bool] = nodes(window).compactMap { node in
            let selector = NSSelectorFromString("accessibilityLabel")
            guard node.responds(to: selector), node.perform(selector)?.takeUnretainedValue() as? String == title,
                  node.responds(to: NSSelectorFromString("isAccessibilityEnabled")) || node.responds(to: NSSelectorFromString("accessibilityEnabled")) else { return nil }
            return node.value(forKey: "accessibilityEnabled") as? Bool
        }
        XCTAssertFalse(states.isEmpty, "Missing enabled-state oracle for " + title, file: file, line: line)
        XCTAssertTrue(states.allSatisfy { !$0 }, title + " must be disabled", file: file, line: line)
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

    func testGate31AllMetadataSurfacesEscapeHostileText() async throws {
        let client = ScriptedClient(); await client.hostileMetadata()
        let session = VaultSession(client: client); await session.poll()
        let directory = try XCTUnwrap(session.projects.rows.first?.dir)
        await session.openProject(directory)
        let project = try XCTUnwrap(session.projects.opened)
        let surfaces: [(AnyView, [String])] = [
            (AnyView(KeysView(session: session, filter: .all, query: "", scope: nil, grouping: .constant(.none), selectedKey: .constant(nil))),
             ["fixture-0\\u{202e}\\u{1b}[31m", "Fixture 0\\u{202e}\\u{1b}[31m", "example\\u{202e}\\u{1b}[31m", "fixture@example.invalid\\u{202e}\\u{1b}[31m"]),
            (AnyView(ProjectsOverview(session: session, route: .constant(.projects))),
             ["project\\u{202e}\\u{1b}[31m, /tmp/project\\u{202e}\\u{1b}[31m, 1 adopted bindings"]),
            (AnyView(BindingsTable(session: session, project: project, profile: nil, selectedKey: .constant(nil))),
             ["VARIABLE\\u{202e}\\u{1b}[31m", "envcloak://fixture-0\\u{202e}\\u{1b}[31m", "example\\u{202e}\\u{1b}[31m, fixture@example.invalid\\u{202e}\\u{1b}[31m"]),
            (AnyView(GrantRows(session: session, directory: nil, slug: nil)),
             ["Fixture grant\\u{202e}\\u{1b}[31m", "/tmp/project\\u{202e}\\u{1b}[31m"]),
            (AnyView(MainView(session: session, initialRoute: .settings)),
             ["project\\u{202e}\\u{1b}[31m"]),
        ]
        for (view, expected) in surfaces {
            let window = host(view)
            for text in expected { await assertVisible(text, in: window) }
            XCTAssertFalse(labels(window).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
            window.close()
        }
    }

    func testGate31UnopenedBasenameOnSidebarOverviewScopeAndSubtitle() async throws {
        let client = ScriptedClient(); await client.unopenedBasenameFixture()
        let session = VaultSession(client: client); await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.opened?.title, "Benign manifest name")
        let directory = try XCTUnwrap(session.projects.rows.last?.dir)
        XCTAssertNotEqual(directory, session.projects.opened?.directory)
        let escaped = "second\\u{202e}\\u{1b}[31m"
        XCTAssertEqual(session.projects.title(directory), escaped)
        XCTAssertEqual(Route.project(directory).title, escaped)
        // A separate opened project's benign manifest name cannot satisfy
        // any assertion for this unopened directory's fallback basename.
        let overview = host(ProjectsOverview(session: session, route: .constant(.projects)))
        await assertVisible(escaped + ", /tmp/" + escaped + ", 0 adopted bindings", in: overview)
        XCTAssertFalse(labels(overview).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
        overview.close()
        session.setScope(directory)
        let workspace = host(MainView(session: session, initialRoute: .keys(.all)))
        await assertScoped(escaped, identifier: "sidebar.project." + directory.escaped, in: workspace)
        await assertScoped(escaped, identifier: "workspace.scope", in: workspace)
        XCTAssertEqual(workspace.subtitle, escaped)
        XCTAssertFalse(labels(workspace).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
        workspace.close()
        // items.check may omit project_name. Its detail fallback uses the
        // selected directory, independently of the canonical grant path.
        await client.unopenedBasenameFixture(name: nil)
        await session.openProject(directory)
        XCTAssertEqual(session.projects.opened?.title, escaped)
        let detail = host(ProjectDetail(session: session, directory: directory, selectedKey: .constant(nil)))
        await assertScoped(escaped, identifier: "project.title", in: detail)
        XCTAssertFalse(labels(detail).contains { $0.contains("\u{202e}") || $0.contains("\u{1b}") })
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

    func testClipboardControlsAreDisabledAndExplained() async throws {
        let client = ScriptedClient(); let session = VaultSession(client: client); await session.poll()
        let directory = DaemonText("/tmp/folder" + String(Unicode.Scalar(27)) + "[201~fixture")
        let project = host(ProjectDetail(session: session, directory: directory, selectedKey: .constant(nil)))
        await assertVisible(TerminalCopy.refusalMessage, in: project)
        assertDisabled("Open in Terminal", in: project)
        assertDisabled("Copy path", in: project)
        project.close()
        let item = try XCTUnwrap(session.items.rows.first)
        let inspector = host(KeyInspector(session: session, slug: item.slug, route: .constant(.keys(.all))))
        await assertVisible(TerminalCopy.refusalMessage, in: inspector)
        assertDisabled("Replace…", in: inspector)
        assertDisabled("Remove key…", in: inspector)
        inspector.close()
        for action in [InspectorAction.replace, .remove] {
            let sheet = host(InspectorActionSheet(action: action, item: item, field: DaemonText("secondary")))
            await assertVisible(TerminalCopy.refusalMessage, in: sheet)
            XCTAssertFalse(labels(sheet).contains("Copy command"))
            sheet.close()
        }
    }

    func testUpgradeReadOnlyBannerKeepsWorkspaceVisible() async {
        let client = ScriptedClient(); await client.configure(grants: 1, readOnly: true)
        let session = VaultSession(client: client); await session.poll()
        let window = host(MainView(session: session))
        await assertVisible("The vault opened read-only because an upgrade failed.", in: window)
        await assertVisible("Keys and projects are still readable. Changes are disabled. The next unlock retries the upgrade.", in: window)
        await assertVisible("project, /tmp/project, 0 adopted bindings", in: window)
        XCTAssertFalse(labels(window).contains("How to recover"))
        XCTAssertFalse(labels(window).contains("Metadata unavailable"))
        assertDisabled("Add project folder…", in: window)
        let grants = host(GrantRows(session: session, directory: nil, slug: nil))
        await assertVisible("Revoke", in: grants)
        assertDisabled("Revoke", in: grants)
        let inspector = host(KeyInspector(session: session, slug: session.items.rows.first?.slug, route: .constant(.keys(.all))))
        await assertVisible("Replace…", in: inspector)
        assertDisabled("Replace…", in: inspector)
        assertDisabled("Remove key…", in: inspector)
    }

    func testScopeSaveWarningKeepsNonemptyOverview() async throws {
        let fixture = try ScopeWriteFixture()
        let client = ScriptedClient(); let session = VaultSession(client: client, folders: fixture.folders)
        try fixture.block(); await session.poll()
        let window = host(MainView(session: session))
        await assertVisible("The project scope applies for this session but could not be saved. EnvCloak will retry.", in: window)
        await assertVisible("project, /tmp/project, 0 adopted bindings", in: window)
        await assertVisible("All projects", in: window)
        XCTAssertFalse(labels(window).contains("Projects could not be refreshed"))
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
        for title in ["Approvals", "Activity", "Agents"] {
            await assertScoped("Arrives with Touch ID approvals", identifier: "sidebar." + title, in: window)
        }
        await assertVisible("Spend · M4", in: window)
        await assertVisible("Devices · M5", in: window)
        await assertVisible("Leak checks arrive with envcloak doctor", in: window)
        window.close()
        for (route, expected) in [
            (Route.approvals, "Approvals. Arrives with Touch ID approvals"),
            (.activity, "Activity. Arrives with Touch ID approvals"),
            (.agents, "Agents. Arrives with Touch ID approvals"),
            (.keys(.exposed), "Keys. Leak checks arrive with envcloak doctor"),
            (.later(.spend), "Spend. Spend arrives in M4"),
            (.later(.devices), "Devices. Devices arrive in M5"),
            (.later(.dashboard), "Dashboard. Spend arrives in M4"),
        ] {
            let detail = host(MainView(session: session, initialRoute: route))
            // Fixed expected labels are independent of Route's implementation.
            await assertElementLabel(expected, identifier: "feature.unavailable", in: detail)
            detail.close()
        }
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
