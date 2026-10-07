#if ENVCLOAK_SCREEN_TESTS
#if !DEBUG
#error("Screen test hosts must never ship")
#endif
import Foundation
@testable import EnvCloakKit

/// Present only in the explicitly compiled XCTest host. Release refuses
/// this flag. Normal Debug and Release builds have no runtime override.
@MainActor enum ScreenTestBootstrap {
    static func session() -> VaultSession {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_RUNTIME"],
              directory.hasPrefix("/tmp/ec05-"), !directory.contains("..") else {
            return VaultSession(client: nil)
        }
        return VaultSession(client: SocketWorkspaceClient(client: DaemonClient(directory: directory)))
    }
}
#endif
