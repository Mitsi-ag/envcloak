import Darwin
import Foundation
import XCTest
import EnvCloakKitTestSupport
@testable import EnvCloakKit

final class PeerTests: XCTestCase, @unchecked Sendable {
    func root() throws -> String {
        let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp"
        let path = base + "/p" + String(UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return path
    }
    func testGate20And21RefusalSendsZeroBytesAndNeverRepairs() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run") { _ in nil }
        defer { daemon.stop() }
        let client = DaemonClient(directory: daemon.directory)
        for mode: mode_t in [0o770, 0o707] {
            XCTAssertEqual(chmod(daemon.directory, mode), 0)
            do { _ = try await client.call(Status()); XCTFail("unsafe directory accepted") }
            catch { XCTAssertEqual(error, .daemonUnverified(.directoryMode)) }
            var s = stat()
            XCTAssertEqual(lstat(daemon.directory, &s), 0)
            XCTAssertEqual(s.st_mode & 0o777, mode)
        }
        XCTAssertEqual(chmod(daemon.directory, 0o700), 0)
        XCTAssertEqual(symlink(daemon.directory, root + "/link"), 0)
        do { _ = try await DaemonClient(directory: root + "/link").call(Status()); XCTFail("symlink accepted") }
        catch { XCTAssertEqual(error, .daemonUnverified(.directoryType)) }
        let fileDir = root + "/file"
        try FileManager.default.createDirectory(atPath: fileDir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertTrue(FileManager.default.createFile(atPath: fileDir + "/envcloakd.sock", contents: Data()))
        do { _ = try await DaemonClient(directory: fileDir).call(Status()); XCTFail("regular file accepted") }
        catch { XCTAssertEqual(error, .daemonUnverified(.socketType)) }
        daemon.stop()
        XCTAssertEqual(daemon.received.flatMap { $0 }.count, 0)
    }

    func testVerifiedCallAndFreshChecksForValue() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run") { bytes in
            let request = try! JSONSerialization.jsonObject(with: Data(bytes)) as! [String: Any]
            let id = request["id"] as! UInt64
            return FakeDaemon.frame("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"result\":{\"revoked\":0}}")
        }
        defer { daemon.stop() }
        let client = DaemonClient(directory: daemon.directory)
        let direct = try Connection(directory: daemon.directory, timeout: .seconds(2))
        let outgoing = try GrantsRevoke().request(id: 9)
        try outgoing.write(using: direct.write)
        let incoming = try Frame.read(using: direct.read)
        let _: RevokedView = try incoming.response(id: 9)
        let revoked = try await client.call(GrantsRevoke())
        XCTAssertEqual(revoked.revoked, 0)
        XCTAssertEqual(chmod(daemon.directory, 0o770), 0)
        var value = try SecretBuffer()
        try value.append(contentsOf: Array(UUID().uuidString.utf8))
        do { _ = try await client.call(ItemsAdd(value: consume value)); XCTFail("value sent after chmod") }
        catch { XCTAssertEqual(error, .daemonUnverified(.directoryMode)) }
        XCTAssertEqual(daemon.received.count, 2)
        XCTAssertGreaterThan(daemon.received.first?.count ?? 0, 4)
    }

    func testMissingListenerUnavailableAndSocketOptionsSet() throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        XCTAssertThrowsError(try Connection(directory: root + "/missing", timeout: .seconds(1))) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnavailable)
        }
        let daemon = try FakeDaemon(directory: root + "/run") { _ in nil }
        defer { daemon.stop() }
        let connection = try Connection(directory: daemon.directory, timeout: .seconds(1))
        try Peer.verifyUID(fd: connection.fd, expected: geteuid())
        XCTAssertThrowsError(try Peer.verifyUID(fd: connection.fd, expected: geteuid() + 1)) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.peerUID))
        }
        XCTAssertThrowsError(try Peer.verifyUID(fd: -1, expected: 0)) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.peerUID))
        }
        XCTAssertNotEqual(fcntl(connection.fd, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNotEqual(fcntl(connection.fd, F_GETFL) & O_NONBLOCK, 0)
        var noSignal: Int32 = 0
        var optionSize = socklen_t(MemoryLayout.size(ofValue: noSignal))
        XCTAssertEqual(getsockopt(connection.fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, &optionSize), 0)
        XCTAssertEqual(noSignal, 1)
        for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
            var value = timeval()
            var size = socklen_t(MemoryLayout.size(ofValue: value))
            XCTAssertEqual(getsockopt(connection.fd, SOL_SOCKET, option, &value, &size), 0)
            XCTAssertGreaterThan(value.tv_sec, 0)
        }
    }
    func testLockSlotCancelsObsoleteAndQueuedCallsThenFreshCallWorks() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let arrived = expectation(description: "ordinary request arrived")
        let queued = expectation(description: "second ordinary request queued")
        let release = DispatchSemaphore(value: 0)
        let daemon = try FakeDaemon(directory: root + "/run") { bytes in
            let request = try! JSONSerialization.jsonObject(with: Data(bytes)) as! [String: Any]
            let id = request["id"] as! UInt64
            let method = request["method"] as! String
            if method == "grants.list" {
                arrived.fulfill()
                _ = release.wait(timeout: .now() + 5)
                return FakeDaemon.frame("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"result\":{\"grants\":[]}}")
            }
            let result = method == "lock" ? "{\"was_unlocked\":true}" : "{\"revoked\":0}"
            return FakeDaemon.frame("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"result\":\(result)}")
        }
        defer { release.signal(); daemon.stop() }
        let client = DaemonClient(directory: daemon.directory)
        await client.observeQueue { queued.fulfill() }
        let ordinary = Task { try await client.call(GrantsList()) }
        await fulfillment(of: [arrived], timeout: 3)
        let second = Task { try await client.call(GrantsRevoke()) }
        await fulfillment(of: [queued], timeout: 3)
        let locked = try await client.call(Lock())
        XCTAssertTrue(locked.was_unlocked)
        release.signal()
        for task in [Task { try await ordinary.value.grants.count }, Task { Int(try await second.value.revoked) }] {
            do { _ = try await task.value; XCTFail("obsolete call published") }
            catch { XCTAssertEqual(error as? EnvCloakError, .protocolError) }
        }
        XCTAssertEqual(daemon.received.count, 2)
        release.signal()
        let fresh = try await client.call(GrantsRevoke())
        XCTAssertEqual(fresh.revoked, 0)
        XCTAssertEqual(daemon.received.count, 3)
    }

    func testPeerParentSocketModeAndHostilePaths() throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run") { _ in nil }
        defer { daemon.stop() }
        XCTAssertThrowsError(try Peer.check(directory: daemon.directory, uid: geteuid() + 1)) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.directoryOwner))
        }
        XCTAssertEqual(chmod(root, 0o777), 0)
        XCTAssertThrowsError(try Peer.check(directory: daemon.directory, uid: geteuid())) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.parent))
        }
        XCTAssertEqual(chmod(root, 0o1777), 0)
        _ = try Peer.check(directory: daemon.directory, uid: geteuid())
        XCTAssertEqual(chmod(daemon.directory + "/envcloakd.sock", 0o666), 0)
        XCTAssertThrowsError(try Peer.check(directory: daemon.directory, uid: geteuid())) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.socketMode))
        }
        for path in ["relative", "/a\0b", "/a/../b", daemon.directory + "/", "/" + String(repeating: "x", count: 104), "/" + String(repeating: "é", count: 60)] {
            XCTAssertThrowsError(try Peer.check(directory: path, uid: geteuid())) {
                XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.path))
            }
        }
    }

    func testWholeCallDeadlineAndCancellationCloseHungPeer() async throws {
        for cancel in [false, true] {
            let root = try root()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let arrived = expectation(description: "request reached hung peer")
            let release = DispatchSemaphore(value: 0)
            let daemon = try FakeDaemon(directory: root + "/run") { _ in
                arrived.fulfill()
                _ = release.wait(timeout: .now() + 5)
                return nil
            }
            defer { release.signal(); daemon.stop() }
            let client = DaemonClient(directory: daemon.directory, timeout: .milliseconds(300))
            let start = ContinuousClock.now
            let task = Task { try await client.call(GrantsList()) }
            await fulfillment(of: [arrived], timeout: 2)
            if cancel { task.cancel() }
            do { _ = try await task.value; XCTFail("hung peer reported success") }
            catch { XCTAssertEqual(error as? EnvCloakError, .protocolError) }
            XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        }
    }

    func testFailedConnectReleasesItsOwnedDescriptor() throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run") { _ in nil }
        daemon.stop()
        // The socket node remains, but there is no listener. The failure
        // happens after the client allocates its descriptor.
        func openDescriptors() -> Set<Int32> {
            Set((0..<512).filter { fcntl(Int32($0), F_GETFD) >= 0 }.map(Int32.init))
        }
        let before = openDescriptors()
        for _ in 0..<64 {
            XCTAssertThrowsError(try Connection(directory: daemon.directory, timeout: .seconds(1))) {
                XCTAssertEqual($0 as? EnvCloakError, .daemonUnavailable)
            }
        }
        XCTAssertEqual(openDescriptors(), before)
    }

    func testGate20And21UIDCallSiteRefusesBeforeSending() async throws {
        try await refusedBeforeSending(.daemonUnverified(.peerUID), hooks: PeerTestHooks(peerUID: geteuid() + 1), method: Status())
    }

    func testGate20And21EveryNodeRuleRefusesBeforeSending() async throws {
        let cases: [(PeerNode, PeerCheck, @Sendable (inout stat) -> Void)] = [
            (.directory, .directoryType, { $0.st_mode = S_IFREG | 0o700 }),
            (.directory, .directoryOwner, { $0.st_uid = geteuid() + 1 }),
            (.directory, .directoryMode, { $0.st_mode |= 0o020 }),
            (.parent, .parent, { $0.st_mode = S_IFREG | 0o700 }),
            (.parent, .parent, { $0.st_uid = geteuid() + 1 }),
            (.parent, .parent, { $0.st_mode = S_IFDIR | 0o777 }),
            (.socket, .socketType, { $0.st_mode = S_IFREG | 0o600 }),
            (.socket, .socketOwner, { $0.st_uid = geteuid() + 1 }),
            (.socket, .socketMode, { $0.st_mode |= 0o004 }),
        ]
        for (node, check, alter) in cases {
            try await refusedBeforeSending(.daemonUnverified(check), hooks: PeerTestHooks(metadata: { kind, value in
                if kind == node { alter(&value) }
            }), method: Status())
        }
    }

    func testRootOwnedAndStickyParentsHaveVerifiedPositiveControls() async throws {
        for (owner, mode): (uid_t, mode_t) in [(0, 0o700), (0, 0o1777), (geteuid(), 0o1777)] {
            let root = try root()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let daemon = try FakeDaemon(directory: root + "/run", handler: Self.rpcRefusal)
            defer { daemon.stop() }
            await PeerProbe.$hooks.withValue(PeerTestHooks(metadata: { node, value in
                if node == .parent { value.st_uid = owner; value.st_mode = S_IFDIR | mode }
            })) {
                do { _ = try await DaemonClient(directory: daemon.directory).call(Status()); XCTFail("fixture error ignored") }
                catch { XCTAssertEqual(error as? EnvCloakError, .rpc(.vaultLocked, nil)) }
            }
            XCTAssertEqual(daemon.received.count, 1)
            XCTAssertGreaterThan(daemon.received.first?.count ?? 0, 4)
        }
    }

    private func refusedBeforeSending<M: DaemonMethod>(_ expected: EnvCloakError, hooks: PeerTestHooks, method: M) async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run", handler: Self.rpcRefusal)
        defer { daemon.stop() }
        await PeerProbe.$hooks.withValue(hooks) {
            do { _ = try await DaemonClient(directory: daemon.directory, timeout: nil).call(method); XCTFail("unverified call succeeded") }
            catch { XCTAssertEqual(error as? EnvCloakError, expected) }
        }
        daemon.stop()
        XCTAssertEqual(daemon.received.flatMap { $0 }.count, 0)
    }

    private static let rpcRefusal: @Sendable ([UInt8]) -> [UInt8]? = { bytes in
        let request = try! JSONSerialization.jsonObject(with: Data(bytes)) as! [String: Any]
        let id = request["id"] as! UInt64
        return FakeDaemon.frame("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"error\":{\"code\":-32002,\"message\":\"\",\"data\":{\"kind\":\"vault_locked\"}}}")
    }

    func testGate20And21PostConnectReplacementAndModeChanges() async throws {
        for swap in [false, true] {
            let root = try root()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let daemon = try FakeDaemon(directory: root + "/run", handler: Self.rpcRefusal)
            let replacement = try FakeDaemon(directory: root + "/other", handler: Self.rpcRefusal)
            defer { daemon.stop(); replacement.stop() }
            let hooks = PeerTestHooks(afterConnect: {
                let result = swap
                    ? rename(replacement.directory + "/envcloakd.sock", daemon.directory + "/envcloakd.sock")
                    : chmod(daemon.directory, 0o750)
                XCTAssertEqual(result, 0)
            })
            await PeerProbe.$hooks.withValue(hooks) {
                do { _ = try await DaemonClient(directory: daemon.directory).call(Status()); XCTFail("changed peer accepted") }
                catch { XCTAssertEqual(error as? EnvCloakError, .daemonUnverified(.changed)) }
            }
            daemon.stop(); replacement.stop()
            XCTAssertEqual((daemon.received + replacement.received).flatMap { $0 }.count, 0)
        }
    }

    func testSnapshotComparisonCoversEveryIdentityFieldOfBothNodes() throws {
        let changes: [(inout stat) -> Void] = [
            { $0.st_dev += 1 }, { $0.st_ino += 1 }, { $0.st_uid += 1 }, { $0.st_mode ^= 0o100 },
        ]
        let root = try root()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let daemon = try FakeDaemon(directory: root + "/run") { _ in nil }
        defer { daemon.stop() }
        let before = try Peer.check(directory: daemon.directory, uid: geteuid())
        XCTAssertTrue(Peer.unchanged(before, before))
        for change in changes {
            var directory = before.directory, socket = before.socket
            change(&directory)
            XCTAssertFalse(Peer.unchanged(before, PeerSnapshot(directory: directory, socket: socket)))
            directory = before.directory
            change(&socket)
            XCTAssertFalse(Peer.unchanged(before, PeerSnapshot(directory: directory, socket: socket)))
        }
    }

    func testConnectTimeoutIsUnavailableAndSendsNothing() async throws {
        let clock = TestClock()
        let hooks = PeerTestHooks(afterConnect: { clock.advance(.seconds(11)) }, now: { clock.now })
        try await refusedBeforeSending(.daemonUnavailable, hooks: hooks, method: Status())
        try await refusedBeforeSending(.daemonUnavailable, hooks: hooks, method: AuditVerify())
        try await refusedBeforeSending(.daemonUnavailable, hooks: hooks, method: BackupCreate())
        for code in [ENOENT, ECONNREFUSED, ETIMEDOUT] {
            XCTAssertEqual(Peer.failure(.socketType, code: code), .daemonUnavailable)
        }
        XCTAssertEqual(Peer.failure(.socketType, code: EACCES), .daemonUnverified(.socketType))
    }

    func testRPCCompletionAfterDeadlineNeverReportsSuccess() async throws {
        for expired in [false, true] {
            let root = try root()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let clock = TestClock()
            let daemon = try FakeDaemon(directory: root + "/run") { bytes in
                let request = try! JSONSerialization.jsonObject(with: Data(bytes)) as! [String: Any]
                return FakeDaemon.frame("{\"jsonrpc\":\"2.0\",\"id\":\(request["id"] as! UInt64),\"result\":{\"revoked\":0}}")
            }
            defer { daemon.stop() }
            await PeerProbe.$hooks.withValue(PeerTestHooks(beforeResult: {
                if expired { clock.advance(.seconds(11)) }
            }, now: { clock.now })) {
                do {
                    let response = try await DaemonClient(directory: daemon.directory, timeout: nil).call(GrantsRevoke())
                    XCTAssertFalse(expired)
                    XCTAssertEqual(response.revoked, 0)
                } catch { XCTAssertTrue(expired); XCTAssertEqual(error as? EnvCloakError, .protocolError) }
            }
            XCTAssertEqual(daemon.received.count, 1)
        }
    }

    func testMethodBudgetsAndLatePollNeverPublishAnExpiredResponse() async throws {
        func check<M: DaemonMethod>(_ method: M, elapsed: Duration, expected: EnvCloakError) async throws {
            let root = try root()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let clock = TestClock()
            let daemon = try FakeDaemon(directory: root + "/run") { bytes in
                clock.advance(elapsed)
                return Self.rpcRefusal(bytes)
            }
            defer { daemon.stop() }
            await PeerProbe.$hooks.withValue(PeerTestHooks(now: { clock.now })) {
                do { _ = try await DaemonClient(directory: daemon.directory, timeout: nil).call(method); XCTFail("fixture error ignored") }
                catch { XCTAssertEqual(error as? EnvCloakError, expected, M.name) }
            }
            XCTAssertEqual(daemon.received.count, 1)
        }
        try await check(AuditVerify(), elapsed: .seconds(11), expected: .rpc(.vaultLocked, nil))
        try await check(BackupCreate(), elapsed: .seconds(11), expected: .rpc(.vaultLocked, nil))
        try await check(AuditVerify(), elapsed: .seconds(301), expected: .protocolError)
        try await check(BackupCreate(), elapsed: .seconds(301), expected: .protocolError)
        try await check(Status(), elapsed: .seconds(11), expected: .protocolError)
        for name in [Status.name, Lock.name, ItemsList.name, ItemsShow.name, ItemsCheck.name, ItemsAdd.name, GrantsList.name, GrantsRevoke.name, Deny.name] {
            XCTAssertEqual(DaemonClient.methodTimeout(name), .seconds(10))
        }
    }

}

final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    func advance(_ duration: Duration) { lock.withLock { instant = instant.advanced(by: duration) } }
}
