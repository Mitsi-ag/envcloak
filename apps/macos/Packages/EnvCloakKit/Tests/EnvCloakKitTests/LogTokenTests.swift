import XCTest
@testable import EnvCloakKit

/// The log's fixed words. What may be interpolated into a log message at
/// all is scripts/macos/check-swift.sh's rule (only `.logToken`); these
/// tests pin the names that rule and docs/APP.md use.
final class LogTokenTests: XCTestCase {
    private enum Probe: String, LogToken {
        case marker = "ec-log-probe"
    }

    func testATokenIsItsRawValue() {
        XCTAssertEqual(Probe.marker.logToken, "ec-log-probe")
    }

    func testTheSubsystemAndCategoriesAreFixed() {
        XCTAssertEqual(ECLog.subsystem, "ai.envcloak.app")
        XCTAssertEqual(ECLogCategory.app.rawValue, "app")
        XCTAssertEqual(ECLogCategory.client.rawValue, "client")
    }
}
