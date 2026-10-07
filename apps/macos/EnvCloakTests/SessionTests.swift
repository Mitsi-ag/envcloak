import Foundation
import XCTest
import EnvCloakKitTestSupport
@testable import EnvCloak
@testable import EnvCloakKit

/// Scripted metadata passes through FakeDaemon and the real socket client. No fixture reads the account's runtime path.
actor ScriptedClient: WorkspaceClient {
    var counts: [String: Int] = [:]
    var head: UInt64 = 1
    var grants = 0
    var pending = 0
    var vault = "unlocked"
    var integrity = "ok"
    var failure: EnvCloakError?
    var projectFailure = false
    var itemCount = 1
    var pageMode = "single"
    var revokeFailure = false
    func pages(_ mode: String) { pageMode = mode }
    func loseRevokeResponse() { revokeFailure = true }
    func configure(head: UInt64? = nil, grants: Int? = nil, pending: Int? = nil,
                   vault: String? = nil, integrity: String? = nil, failure: EnvCloakError? = nil,
                   projectFailure: Bool = false, itemCount: Int = 1) {
        if let head { self.head = head }
        if let grants { self.grants = grants }
        if let pending { self.pending = pending }
        if let vault { self.vault = vault }
        if let integrity { self.integrity = integrity }
        self.failure = failure; self.projectFailure = projectFailure; self.itemCount = itemCount
    }
    func calls(_ name: String) -> Int { counts[name, default: 0] }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        counts[M.name, default: 0] += 1
        if let failure { throw failure }
        let result: [String: Any]
        switch M.name {
        case "status": result = [
            "daemon": ["version": "fixture", "pid": 42, "hardening": ["core_dumps_off": true, "non_dumpable": false], "runtime_dir_fallback": false],
            "vault": ["state": vault, "integrity": integrity, "read_only": integrity != "ok", "busy": false, "failed_unlocks": 0],
            "lock": ["last_reason": "sleep", "idle_limit_secs": 3600],
            "approvals": ["grants": grants, "pending": pending, "proof_failures": 0, "proof_wait_secs": 0],
            "audit": ["open": true, "head_seq": head, "unanchored": 0, "anchor_failed": false, "queued": 0, "dropped": 0]]
        case "items.list": result = ["items": (0..<itemCount).map { i -> [String: Any] in
            ["id": "item-\(i)", "slug": "fixture-\(i)\u{202e}\u{1b}[31m", "class": "secret", "title": "Fixture \(i)",
             "provider": "example", "classification": "test", "env_hint": "VARIABLE", "allow_short": false,
             "fields": [["name": "value", "prior_count": 0, "created_secs": 1, "updated_secs": 1]],
             "created_secs": 1, "updated_secs": 1, "account": ["email": "fixture@example.invalid"]]
        }]
        case "projects.list":
            if projectFailure { throw EnvCloakError.protocolError }
            let nextPage = (method as? ProjectsList)?.after != nil
            if pageMode == "fail-second" && nextPage { throw EnvCloakError.protocolError }
            let next: Any = pageMode != "single" && (!nextPage || pageMode == "repeat")
                ? ["last_seen": 2, "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"] : NSNull()
            result = ["projects": [["dir": nextPage ? "/tmp/second" : "/tmp/project", "manifest_sha256": String(repeating: "a", count: 64), "bindings": [], "last_seen_secs": nextPage ? 1 : 2]], "next": next]

        case "items.check": result = ["project_dir": "/tmp/project", "project_name": "project\u{202e}\u{1b}[31m", "bindings": [
            ["env_name": "VARIABLE", "reference": "envcloak://fixture", "status": "ok"],
            ["profile": "test", "env_name": "VARIABLE", "reference": "envcloak://second", "status": "unknown_item"]], "refs": []]
        case "grants.list": result = ["grants": []]
        case "grants.revoke":
            if revokeFailure { throw EnvCloakError.protocolError }
            result = ["revoked": 1]
        case "lock": vault = "locked"; result = ["was_unlocked": true]
        default: throw EnvCloakError.protocolError
        }
        let data = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": result])
        let text = String(decoding: data, as: UTF8.self)
        let directory = "/tmp/ec05-fake-" + UUID().uuidString.prefix(8)
        let daemon = try FakeDaemon(directory: directory) { _ in FakeDaemon.frame(text) }
        defer { daemon.stop() }
        let client = DaemonClient(directory: directory)
        return try await client.call(method)
    }
}

final class SessionTests: XCTestCase {
    @MainActor func testOnlyChangedStoresRefetch() async {
        let client = ScriptedClient()
        let session = VaultSession(client: client)
        await session.poll()
        await session.poll()
        let initial = await client.calls("items.list")
        XCTAssertEqual(initial, 1)
        await client.configure(pending: 1)
        await session.poll()
        let pending = await client.calls("items.list")
        XCTAssertEqual(pending, 1)
        await client.configure(grants: 1)
        await session.poll()
        let grantCalls = await client.calls("grants.list")
        let itemCalls = await client.calls("items.list")
        XCTAssertEqual(grantCalls, 2)
        XCTAssertEqual(itemCalls, 1)
        await client.configure(head: 2)
        await session.poll()
        let changed = await client.calls("items.list")
        let projects = await client.calls("projects.list")
        XCTAssertEqual(changed, 2)
        XCTAssertEqual(projects, 2)
    }

    @MainActor func testFailureClearsDerivedStateAndReconnectRefetches() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 1)
        await client.configure(failure: .daemonUnavailable)
        await session.poll()
        XCTAssertEqual(session.state, .noDaemon)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        await client.configure()
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 1)
        let calls = await client.calls("items.list")
        XCTAssertEqual(calls, 2)
    }

    @MainActor func testFailedRefreshIsRetriedWithoutAdvancingSignal() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await client.configure(head: 2, projectFailure: true)
        await session.poll()
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertNotNil(session.projects.failure)
        await client.configure(head: 2)
        await session.poll()
        XCTAssertEqual(session.projects.rows.count, 1)
    }

    @MainActor func testStatesAndLockedReason() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        XCTAssertEqual(session.state, .connecting)
        for (wire, expected) in [("absent", ConnectionState.noVault), ("locked", .locked), ("unlocked", .ready), ("unavailable", .unavailable)] {
            await client.configure(vault: wire)
            await session.poll()
            XCTAssertEqual(session.state, expected)
        }
        await client.configure(vault: "unlocked", integrity: "tampered")
        await session.poll()
        XCTAssertEqual(session.state, .readOnly)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertEqual(session.lockReason, "Locked when this Mac slept")
        await client.configure(failure: .daemonUnverified(.peerUID))
        await session.poll()
        XCTAssertEqual(session.state, .unverified(.peerUID))
    }

    @MainActor func testTwoThousandKeysAndTokenSearch() async {
        let client = ScriptedClient(); await client.configure(itemCount: 2000)
        let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 2000)
        XCTAssertEqual(session.filteredKeys(query: "provider:example account:fixture@example.invalid class:test", filter: .all, scope: nil).count, 2000)
        XCTAssertEqual(session.filteredKeys(query: "Fixture 1999", filter: .all, scope: nil).count, 1)
        XCTAssertEqual(session.filteredKeys(query: "class:live", filter: .all, scope: nil).count, 0)
    }

    @MainActor func testGate31ProjectNameAndSlugEscaped() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.opened?.title, "project\\u{202e}\\u{1b}[31m")
        XCTAssertEqual(session.items.rows.first?.slug.escaped, "fixture-0\\u{202e}\\u{1b}[31m")
        XCTAssertEqual(session.projects.opened?.bindings(profile: "test").first?.status, .unknownItem)
    }

    @MainActor func testPagesAreCompleteOrExplicitlyFailed() async {
        for mode in ["two", "repeat", "fail-second"] {
            let client = ScriptedClient(); await client.pages(mode)
            let store = ProjectsStore(client: client, folders: nil)
            await store.refetch(.projects)
            if mode == "two" {
                XCTAssertEqual(store.rows.map(\.dir.escaped), ["/tmp/project", "/tmp/second"])
                XCTAssertNil(store.failure)
            } else {
                XCTAssertTrue(store.rows.isEmpty)
                XCTAssertEqual(store.failure, .protocolError)
            }
        }
    }

    @MainActor func testLockDiscardsAnInFlightRefresh() async {
        let barrier = ItemBarrierClient()
        let session = VaultSession(client: barrier)
        let polling = Task { await session.poll() }
        await barrier.arrived()
        await session.lock()
        await barrier.release()
        await polling.value
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertTrue(session.grants.rows.isEmpty)
    }

    @MainActor func testGroupingAndUnsafeLinks() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .provider).map(\.title), ["example"])
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .account).map(\.title), ["fixture@example.invalid"])
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .project).map(\.title), ["No adopted project"])
        XCTAssertEqual(MetadataRequest.slug(DaemonText("fixture#field")), DaemonText("fixture"))
        XCTAssertNotNil(MetadataRequest.safeLink(DaemonText("https://example.invalid/docs")))
        for bad in ["file:///tmp/example", "javascript:alert(1)", "https://user:password@example.invalid", "https://example.invalid/\n"] {
            XCTAssertNil(MetadataRequest.safeLink(DaemonText(bad)))
        }
    }

    @MainActor func testLostRevokeResponseIsUnknownAndReconciled() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await client.loseRevokeResponse()
        await session.revoke(DaemonText("fixture-grant"))
        XCTAssertEqual(session.notice, "The revoke outcome could not be confirmed. Grants have been refreshed.")
        let calls = await client.calls("grants.list")
        XCTAssertEqual(calls, 2)
        XCTAssertFalse(session.actionInProgress)
    }

    @MainActor func testManifestEditsHaveTheirOwnRefreshSignal() async throws {
        let directory = URL(fileURLWithPath: "/tmp/ec05-manifest-" + UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let manifest = directory.appendingPathComponent("envcloak.toml")
        try Data("first".utf8).write(to: manifest)
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll(); await session.openProject(DaemonText(directory.path))
        await session.poll()
        let before = await client.calls("items.check")
        XCTAssertEqual(before, 1)
        try Data("other".utf8).write(to: manifest, options: .atomic)
        await session.poll()
        let after = await client.calls("items.check")
        XCTAssertEqual(after, 2)
        let items = await client.calls("items.list")
        XCTAssertEqual(items, 1)
    }

    @MainActor func testAddedFoldersPersistOnlyPathsAndRefuseUnavailableStorage() throws {
        let directory = URL(fileURLWithPath: "/tmp/ec05-folders-" + UUID().uuidString.prefix(8))
        let file = directory.appendingPathComponent("project-folders.json")
        let folders = try ProjectFolders(file: file)
        let store = ProjectsStore(client: nil, folders: folders)
        let project = directory.appendingPathComponent("project")
        try store.add(project)
        try store.add(project)
        XCTAssertEqual(try JSONDecoder().decode([String].self, from: Data(contentsOf: file)), [project.path])
        XCTAssertEqual(try ProjectFolders(file: file).paths, [DaemonText(project.path)])
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let unavailable = ProjectsStore(client: nil, folders: nil)
        XCTAssertThrowsError(try unavailable.add(project))
        XCTAssertTrue(unavailable.added.isEmpty)
    }

    func testUnavailableRoutesNeverAdvertiseShippedFeatures() {
        for route in [Route.approvals, .activity, .agents] {
            XCTAssertEqual(route.unavailableMessage, "Arrives with Touch ID approvals")
        }
        XCTAssertEqual(Route.keys(.exposed).unavailableMessage, "Leak checks arrive with envcloak doctor")
        XCTAssertEqual(Route.later(.spend).unavailableMessage, "Spend arrives in M4")
        XCTAssertEqual(Route.later(.devices).unavailableMessage, "Devices arrive in M5")
    }
}

actor ItemBarrierClient: WorkspaceClient {
    let client = ScriptedClient()
    var entered = false
    var arrival: CheckedContinuation<Void, Never>?
    var waiter: CheckedContinuation<Void, Never>?
    func arrived() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { waiter?.resume(); waiter = nil }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        if M.name == "items.list" {
            await withCheckedContinuation {
                waiter = $0; entered = true; arrival?.resume(); arrival = nil
            }
        }
        return try await client.call(method)
    }
}
