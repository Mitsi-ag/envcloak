import Foundation
import XCTest
@testable import EnvCloakKit

final class LiveDaemonTests: XCTestCase, @unchecked Sendable {
    func testCurrentTreeDaemonStatusLockAndReadRefusals() async throws {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_RUNTIME"] else {
            throw XCTSkip("Run scripts/macos/test-kit.sh for the isolated real daemon")
        }
        let client = DaemonClient(directory: directory)
        let status = try await client.call(Status())
        XCTAssertEqual(status.vault.state, .absent)
        XCTAssertGreaterThan(status.daemon.pid, 0)
        XCTAssertNotEqual(status.daemon.version, "unrecognized")
        XCTAssertEqual(status.approvals.grants, 0)
        let lock = try await client.call(Lock())
        XCTAssertFalse(lock.was_unlocked)
        let grants = try await client.call(GrantsList())
        XCTAssertTrue(grants.grants.isEmpty)
        let revoked = try await client.call(GrantsRevoke())
        XCTAssertEqual(revoked.revoked, 0)
        for long in [false, true] {
            do { _ = try await client.call(ItemsList(long: long)); XCTFail("absent vault listed") }
            catch { XCTAssertEqual(error, .rpc(.noVault, nil)) }
        }
        do { _ = try await client.call(ItemsShow(slug: "fixture")); XCTFail("absent item shown") }
        catch { XCTAssertEqual(error, .rpc(.noVault, nil)) }
        do { _ = try await client.call(AuditVerify()); XCTFail("absent audit verified") }
        catch { XCTAssertEqual(error, .rpc(.noVault, nil)) }
        do { _ = try await client.call(BackupCreate()); XCTFail("absent vault backed up") }
        catch { XCTAssertEqual(error, .rpc(.noVault, nil)) }
    }
}
