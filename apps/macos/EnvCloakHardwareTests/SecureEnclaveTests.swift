import Foundation
import LocalAuthentication
import XCTest
@testable import EnvCloak
@testable import EnvCloakKit

final class SecureEnclaveTests: XCTestCase {
    func testSecureEnclaveKeyGenerationAndContextFactoryOnHardware() throws {
        guard ProcessInfo.processInfo.environment["ENVCLOAK_HARDWARE_TESTS"] == "1" else {
            throw XCTSkip("Set ENVCLOAK_HARDWARE_TESTS=1 on a Mac with Secure Enclave and Touch ID to run hardware tests")
        }

        let storage = DataProtectionKeychainBlobStorage(
            service: "ai.envcloak.hardware-test." + UUID().uuidString,
            enabled: true
        )
        let keyStore = KeyStore(storage: storage)
        addTeardownBlock {
            try? keyStore.deleteKeys()
        }

        let enrolled = try keyStore.loadOrCreatePublicKeys(touchIDOnly: false)
        let unlockBytes = try XCTUnwrap(HexCoding.decode(enrolled.unlockPublicKeyHex, expectedByteCount: 65))
        let approveBytes = try XCTUnwrap(HexCoding.decode(enrolled.approvePublicKeyHex, expectedByteCount: 65))
        XCTAssertEqual(unlockBytes.first, 0x04)
        XCTAssertEqual(approveBytes.first, 0x04)
        XCTAssertNotEqual(
            enrolled.unlockPublicKeyHex,
            enrolled.approvePublicKeyHex,
            "Unlock and approval keys must be distinct Secure Enclave keys"
        )
        XCTAssertTrue(keyStore.hasEnrolledKeys())

        let factory = ContextFactory()
        let context = factory.make(reason: ContextFactory.unlockReason)
        defer { context.invalidate() }
        XCTAssertEqual(context.touchIDAuthenticationAllowableReuseDuration, 0)
    }
}
