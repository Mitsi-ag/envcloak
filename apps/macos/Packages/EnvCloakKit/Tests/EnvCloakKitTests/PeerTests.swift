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
        XCTAssertGreaterThan(daemon.received[0].count, 4)
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
        XCTAssertNotEqual(fcntl(connection.fd, F_GETFD) & FD_CLOEXEC, 0)
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
        XCTAssertEqual(chmod(root, 0o1700), 0)
        _ = try Peer.check(directory: daemon.directory, uid: geteuid())
        XCTAssertEqual(chmod(daemon.directory + "/envcloakd.sock", 0o666), 0)
        XCTAssertThrowsError(try Peer.check(directory: daemon.directory, uid: geteuid())) {
            XCTAssertEqual($0 as? EnvCloakError, .daemonUnverified(.socketMode))
        }
        for path in ["relative", "/a\0b", "/a/../b", "/" + String(repeating: "x", count: 104)] {
            XCTAssertThrowsError(try Peer.check(directory: path, uid: geteuid()))
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

}
