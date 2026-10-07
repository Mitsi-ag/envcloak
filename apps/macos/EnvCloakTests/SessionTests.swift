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
    var idleLimit: UInt64 = 3600
    var lockReason = "sleep"
    nonisolated let socketPath: DaemonText? = DaemonText("/tmp/ec05-fixture\u{202e}/envcloakd.sock")
    func idle(_ seconds: UInt64) { idleLimit = seconds; lockReason = "idle" }
    var failure: EnvCloakError?
    var projectFailure = false
    var itemCount = 1
    var pageMode = "single"
    var revokeFailure = false
    var hostileSlugs = true
    func plainSlugs() { hostileSlugs = false }
    var showFailure = false
    var wrongDetail = false
    func detailResponse(fails: Bool = false, wrong: Bool = false) { showFailure = fails; wrongDetail = wrong }
    var adoptedBinding = false
    func adoptBinding() { adoptedBinding = true }
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
    private func item(_ i: Int) -> [String: Any] {
        ["id": "item-\(i)", "slug": "fixture-\(i)" + (hostileSlugs ? "\u{202e}\u{1b}[31m" : ""), "class": "secret", "title": "Fixture \(i)",
         "provider": "example", "classification": "test", "env_hint": "VARIABLE", "allow_short": false,
         "fields": ["value", "secondary"].map { ["name": $0, "prior_count": 0, "created_secs": 1, "updated_secs": 1] as [String: Any] },
         "last_used_secs": 123, "created_secs": 1, "updated_secs": 1, "account": ["email": "fixture@example.invalid"]]
    }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        counts[M.name, default: 0] += 1
        if let failure { throw failure }
        let result: [String: Any]
        switch M.name {
        case "status": result = [
            "daemon": ["version": "fixture", "pid": 42, "hardening": ["core_dumps_off": true, "non_dumpable": false], "runtime_dir_fallback": false],
            "vault": ["state": vault, "integrity": integrity, "read_only": integrity != "ok", "busy": false, "failed_unlocks": 0],
            "lock": ["last_reason": lockReason, "idle_limit_secs": idleLimit],
            "approvals": ["grants": grants, "pending": pending, "proof_failures": 0, "proof_wait_secs": 0],
            "audit": ["open": true, "head_seq": head, "unanchored": 0, "anchor_failed": false, "queued": 0, "dropped": 0]]
        case "items.list": result = ["items": (0..<itemCount).map { item($0) }]
        case "items.show":
            if showFailure { throw EnvCloakError.protocolError }
            let index = (method as? ItemsShow)?.slug.hasPrefix("fixture-1") == true ? 1 : 0
            var full = item(wrongDetail ? 99 : index)
            full["detail"] = ["allowed_hosts": ["api.example.invalid"], "tags": ["fixture"],
                              "links": ["docs": "https://example.invalid/docs"], "last_used_secs": 123,
                              "notes": "Notes \(head)\u{202e}"] as [String: Any]
            result = full
        case "projects.list":
            if projectFailure { throw EnvCloakError.protocolError }
            let nextPage = (method as? ProjectsList)?.after != nil
            if pageMode == "fail-second" && nextPage { throw EnvCloakError.protocolError }
            let next: Any = !["single", "hidden-one-page", "duplicate-real"].contains(pageMode) && (!nextPage || pageMode == "repeat")
                ? ["last_seen": 2, "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"] : NSNull()
            let directory = pageMode.hasPrefix("hidden") ? "[not shown: looks like a key or token]" : (nextPage ? "/tmp/second" : "/tmp/project")
            let row: [String: Any] = ["dir": directory, "manifest_sha256": String(repeating: "a", count: 64), "bindings": adoptedBinding ? [["env_name": "VARIABLE", "reference": "envcloak://fixture-0\u{202e}\u{1b}[31m"]] : [], "last_seen_secs": nextPage ? 1 : 2]
            result = ["projects": ["hidden-one-page", "duplicate-real"].contains(pageMode) ? [row, row] : [row], "next": next]

        case "items.check": result = ["project_dir": "/tmp/project", "project_name": "project\u{202e}\u{1b}[31m", "bindings": [
            ["env_name": "VARIABLE", "reference": hostileSlugs ? "envcloak://fixture" : "envcloak://fixture-0", "status": "ok"],
            ["profile": "test", "env_name": "VARIABLE", "reference": "envcloak://second", "status": "unknown_item"]], "refs": []]
        case "grants.list": result = ["grants": grants == 0 ? [] : [[
            "id": "fixture-grant", "kind": "terminal", "label": "Fixture grant", "root_pid": 42,
            "project_dir": "/tmp/project", "bindings": [["env_name": "VARIABLE", "slug": "fixture-0", "live": false]],
            "mode": "inject", "uses": "session", "created_secs": 1, "remaining_secs": 3600]]]
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
    @MainActor func testHiddenPathsAreRowsNotDirectoryIdentities() async {
        for mode in ["hidden-one-page", "hidden-pages"] {
            let client = ScriptedClient(); await client.pages(mode)
            let store = ProjectsStore(client: client, folders: nil)
            await store.refetch(.projects)
            XCTAssertNil(store.failure)
            XCTAssertEqual(store.rows.count, 2)
            XCTAssertEqual(store.inventory.count, 2)
            XCTAssertEqual(Set(store.inventory.map(\.id)).count, 2)
            XCTAssertTrue(store.directories.isEmpty)
            XCTAssertTrue(store.inventory.allSatisfy { $0.directory == nil })
        }
        let client = ScriptedClient(); await client.pages("duplicate-real")
        let store = ProjectsStore(client: client, folders: nil)
        await store.refetch(.projects)
        XCTAssertEqual(store.failure, .protocolError)
        XCTAssertTrue(store.rows.isEmpty)
    }

    @MainActor func testAliasUsesCheckedIdentityAndKeepsNavigationPath() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await session.openProject(DaemonText("/tmp/selected-alias"))
        XCTAssertEqual(session.projects.opened?.directory, DaemonText("/tmp/selected-alias"))
        XCTAssertEqual(session.projects.opened?.grantDirectory, DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.canonicalDirectory(DaemonText("/tmp/selected-alias")), DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.title(DaemonText("/tmp/project")), "project\\u{202e}\\u{1b}[31m")
    }

    @MainActor func testProjectSearchDependencyNeverReportsFalseAbsence() async {
        let client = ScriptedClient(); await client.adoptBinding()
        let session = VaultSession(client: client)
        await client.configure(projectFailure: true)
        await session.poll()
        for query in ["project:fixture", "PROJECT:fixture", "class:test  project:fixture", "project:"] {
            XCTAssertTrue(session.keysUnavailable(query: query, scope: nil))
        }
        XCTAssertTrue(session.keysUnavailable(query: "", scope: DaemonText("/tmp/project")))
        for query in ["", "provider:example", "project", "unknown:project:fixture"] {
            XCTAssertFalse(session.keysUnavailable(query: query, scope: nil))
        }
        for query in ["provider:example", "account:fixture@example.invalid", "class:test", "Fixture"] {
            XCTAssertFalse(session.keysUnavailable(query: query, scope: nil))
            XCTAssertEqual(session.filteredKeys(query: query, filter: .all, scope: nil).count, 1)
        }
        await client.configure()
        await session.poll()
        XCTAssertFalse(session.keysUnavailable(query: "project:project", scope: nil))
        XCTAssertEqual(session.filteredKeys(query: "project:project", filter: .all, scope: nil).count, 1)
        XCTAssertEqual(session.filteredKeys(query: "project:missing", filter: .all, scope: nil).count, 0)
    }

    @MainActor func testSelectedMetadataUsesShowAndRefreshes() async throws {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(item.detail)
        XCTAssertEqual(item.last_used_secs, 123)
        await session.selectKey(item.slug)
        XCTAssertEqual(session.items.selectedItem?.detail?.notes?.escaped, "Notes 1\\u{202e}")
        XCTAssertEqual(session.items.selectedItem?.detail?.allowed_hosts.first?.escaped, "api.example.invalid")
        await client.configure(head: 2)
        await session.poll()
        XCTAssertEqual(session.items.selectedItem?.detail?.notes?.escaped, "Notes 2\\u{202e}")
        let shows = await client.calls("items.show")
        XCTAssertEqual(shows, 2)
        await client.detailResponse(fails: true)
        await session.selectKey(nil); await session.selectKey(item.slug)
        XCTAssertNil(session.items.selectedItem)
        XCTAssertEqual(session.items.detailFailure, .protocolError)
        await client.detailResponse(wrong: true)
        await session.selectKey(item.slug)
        XCTAssertNil(session.items.selectedItem)
        XCTAssertEqual(session.items.detailFailure, .protocolError)
    }

    @MainActor func testSelectionLockAndCancellationDiscardLateDetails() async throws {
        for operation in ["selection", "lock", "cancel"] {
            let barrier = ItemBarrierClient(method: "items.show")
            await barrier.client.configure(itemCount: 2)
            let session = VaultSession(client: barrier); await session.poll()
            let slug = try XCTUnwrap(session.items.rows.first?.slug)
            let load = Task { await session.selectKey(slug) }
            await barrier.arrived()
            if operation == "lock" { await session.lock() }
            else if operation == "selection" { await session.selectKey(nil) }
            else { load.cancel() }
            await barrier.release(); await load.value
            XCTAssertNil(session.items.selectedItem, operation)
        }
    }

    @MainActor func testInvalidProjectSelectionDiscardsEarlierCheck() async {
        let barrier = ItemBarrierClient(method: "items.check")
        let store = ProjectsStore(client: barrier, folders: nil)
        let load = Task { await store.open(DaemonText("/tmp/first")) }
        await barrier.arrived()
        await store.open(DaemonText("not a path"))
        await barrier.release(); await load.value
        XCTAssertNil(store.opened)
        XCTAssertEqual(store.checkFailure, .protocolError)
        XCTAssertNil(store.openedDirectory)
        await store.refetch(.projects)
        XCTAssertNil(store.opened)
    }

    @MainActor func testFailedInventoryInvalidatesConcurrentDetailReads() async throws {
        let check = ItemBarrierClient(method: "items.check")
        let projects = ProjectsStore(client: check, folders: nil)
        let opening = Task { await projects.open(DaemonText("/tmp/project")) }
        await check.arrived()
        await check.client.configure(projectFailure: true)
        await projects.refetch(.projects)
        await check.release(); await opening.value
        XCTAssertNotNil(projects.failure)
        XCTAssertNil(projects.opened)

        let client = FailingRefreshClient()
        let items = ItemsStore(client: client); await items.refetch(.items)
        let slug = try XCTUnwrap(items.rows.first?.slug)
        let refreshing = Task { await items.refetch(.items) }
        await client.arrived()
        await items.select(slug)
        XCTAssertNotNil(items.selectedItem)
        await client.release(); await refreshing.value
        XCTAssertNotNil(items.failure)
        XCTAssertTrue(items.rows.isEmpty)
        XCTAssertNil(items.selectedItem)
    }

    @MainActor func testReadOnlyHonorsDaemonRefusalAndLockedWins() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await client.configure(integrity: "tampered")
        await session.poll()
        XCTAssertFalse(session.state.canReadMetadata)
        XCTAssertTrue(session.state.canLock)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        let lists = await client.calls("items.list")
        XCTAssertEqual(lists, 0)
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertNil(session.projects.opened)
        await session.revoke(DaemonText("fixture"))
        let revokes = await client.calls("grants.revoke")
        XCTAssertEqual(revokes, 0)
        await client.configure(vault: "locked")
        await session.poll()
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertNil(session.projects.opened)
    }

    @MainActor func testIdleDurationsAndVerificationDetailsAreExact() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        for (seconds, words) in [(UInt64(30), "30 seconds"), (60, "1 minute"), (90, "1 minute 30 seconds"), (3599, "59 minutes 59 seconds"), (3600, "1 hour"), (5400, "1 hour 30 minutes")] {
            await client.idle(seconds); await session.poll()
            XCTAssertEqual(session.lockReason, "Locked after " + words + " idle")
        }
        await client.configure(failure: .daemonUnverified(.peerUID)); await session.poll()
        XCTAssertEqual(session.verificationDetails, "Failed check: peerUID. Socket: /tmp/ec05-fixture\\u{202e}/envcloakd.sock")
    }

    @MainActor func testScopeRestoresPerViewerAndSurvivesFailedRefresh() async throws {
        let root = URL(fileURLWithPath: "/tmp/ec05-scope-" + UUID().uuidString.prefix(8))
        let file = root.appendingPathComponent("viewer-a/projects.json")
        let folders = try ProjectFolders(file: file)
        try folders.saveScope(DaemonText("/tmp/project"))
        let client = ScriptedClient()
        let store = ProjectsStore(client: client, folders: try ProjectFolders(file: file))
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        XCTAssertNil(try ProjectFolders(file: root.appendingPathComponent("viewer-b/projects.json")).scope)
        await client.configure(projectFailure: true); await store.refetch(.projects)
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        store.clear()
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        await client.configure(); await store.refetch(.projects)
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        XCTAssertThrowsError(try folders.saveScope(DaemonText("relative")))
        XCTAssertThrowsError(try folders.saveScope(DaemonText("/tmp/bad\0path")))
        await client.pages("hidden-one-page"); await store.refetch(.projects)
        XCTAssertNil(store.scope)
        XCTAssertNil(try ProjectFolders(file: file).scope)
    }

    @MainActor func testCopiedCommandsAreAcceptedByBuiltDispatcher() async throws {
        guard let executable = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_CLI"] else {
            throw XCTSkip("Set ENVCLOAK_TEST_CLI to the built CLI for the dispatcher oracle")
        }
        let client = ScriptedClient(); await client.plainSlugs()
        let session = VaultSession(client: client); await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(InspectorAction.reveal.commandWords(item: item, field: nil))
        XCTAssertNil(InspectorAction.replace.commandWords(item: item, field: nil))
        XCTAssertNil(InspectorAction.replace.commandWords(item: item, field: DaemonText("missing")))
        let replace = try XCTUnwrap(InspectorAction.replace.commandWords(item: item, field: DaemonText("secondary")))
        XCTAssertEqual(replace, ["rotate", "fixture-0#secondary"])
        let remove = try XCTUnwrap(InspectorAction.remove.commandWords(item: item, field: nil))
        var commands = CopiedCommand.allCases.map(\.commandWords)
        commands += [replace, remove, ["daemon", "install", "--daemon", "/tmp/ec05-missing/daemon"]]
        for (index, arguments) in commands.enumerated() {
            let home = URL(fileURLWithPath: "/tmp/ec05-command-" + UUID().uuidString.prefix(8))
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let process = Process(); process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments; process.currentDirectoryURL = home
            process.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "TMPDIR": home.path,
                                   "XDG_CONFIG_HOME": home.path, "XDG_DATA_HOME": home.path, "XDG_STATE_HOME": home.path,
                                   "XDG_CACHE_HOME": home.path, "XDG_RUNTIME_DIR": home.path]
            process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run()
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while process.isRunning, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
            if process.isRunning { process.terminate(); XCTFail("command timed out: \(index)") }
            process.waitUntilExit()
            XCTAssertNotEqual(process.terminationStatus, 2, "dispatcher rejected command \(index)")
            XCTAssertNotEqual(process.terminationStatus, 125, "unavailable command \(index)")
            if arguments == CopiedCommand.recoveryHelp.commandWords { XCTAssertEqual(process.terminationStatus, 0) }
        }
    }

    @MainActor func testStartActionRunsStatusInstallerAndReconciles() async throws {
        for succeeds in [true, false] {
            let home = "/tmp/ec05-installer-" + UUID().uuidString.prefix(8)
            try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let executable = home + "/cli"
            try ("#!/bin/sh\ntest \"$#\" -eq 4 && test \"$1\" = daemon && test \"$2\" = install && test \"$3\" = --daemon || exit 2\nprintf 'installed'\nexit " + (succeeds ? "0" : "1") + "\n").write(toFile: executable, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable)
            let runner = CLIRunner(executable: executable, home: String(home), timeout: .seconds(2))
            let client = ScriptedClient(); let session = VaultSession(client: client); session.state = .noDaemon
            await WorkspaceActions.startDaemon(session) { try await WorkspaceActions.installDaemon(using: runner, daemonPath: "/tmp/fixture-daemon") }
            let polls = await client.calls("status")
            XCTAssertEqual(polls, succeeds ? 1 : 0)
            XCTAssertEqual(session.state, succeeds ? .ready : .noDaemon)
            XCTAssertEqual(session.notice == nil, succeeds)
            XCTAssertFalse(session.actionInProgress)
        }
    }

    func testRepeatedDisplayTextNeverDefinesRowIdentity() {
        let hidden = DaemonText("[not shown: looks like a key or token]")
        let rows = DisplayRow.of([hidden, hidden, DaemonText("same"), DaemonText("same")])
        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(Set(rows.map(\.id)).count, 4)
        XCTAssertEqual(rows.map(\.value), [hidden, hidden, DaemonText("same"), DaemonText("same")])
    }

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
    let methodName: String
    init(method: String = "items.list") { methodName = method }
    var entered = false
    var arrival: CheckedContinuation<Void, Never>?
    var waiter: CheckedContinuation<Void, Never>?
    func arrived() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { waiter?.resume(); waiter = nil }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        if M.name == methodName && !entered {
            await withCheckedContinuation {
                waiter = $0; entered = true; arrival?.resume(); arrival = nil
            }
        }
        return try await client.call(method)
    }
}

actor FailingRefreshClient: WorkspaceClient {
    let client = ScriptedClient()
    var lists = 0
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
            lists += 1
            if lists > 1 {
                await withCheckedContinuation {
                    waiter = $0; entered = true; arrival?.resume(); arrival = nil
                }
                throw EnvCloakError.protocolError
            }
        }
        return try await client.call(method)
    }
}
