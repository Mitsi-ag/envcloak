import XCTest

/// Tests that need this Mac's hardware or the founder's signing (the Secure
/// Enclave, the keychain group, SMAppService). They are in no CI scheme;
/// scripts/macos/hardware-tests.sh (task M3-10) runs them on the founder's
/// Mac and reports each skip as a skip, never as a pass.
final class HardwareTests: XCTestCase {
    func testHardwareSuiteArrivesWithM3_10() throws {
        throw XCTSkip("no hardware test exists before task M3-10")
    }
}
