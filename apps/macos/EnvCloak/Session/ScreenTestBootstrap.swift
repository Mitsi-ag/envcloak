#if ENVCLOAK_SCREEN_TESTS
#if !DEBUG
#error("Screen test hosts must never ship")
#endif
import AppKit
@testable import EnvCloakKit

/// Present only in the explicitly compiled XCTest host. Release refuses
/// this flag. Normal Debug and Release builds have no runtime override.
@MainActor enum ScreenTestBootstrap {
    static func positionWindow() async {
        // Keep UI automation independent of the person's restored window
        // size, monitor arrangement and focus. Only this test app moves.
        for _ in 0..<20 {
            if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == WindowID.main }),
               let screen = NSScreen.screens.first {
                let bounds = screen.visibleFrame
                window.setFrame(NSRect(x: bounds.midX - 590, y: bounds.midY - 370, width: 1180, height: 740), display: true)
                window.makeKeyAndOrderFront(nil)
                NSApp.activate()
                return
            }
            do { try await Task.sleep(for: .milliseconds(10)) } catch { return }
        }
    }

    static func session() -> VaultSession {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_RUNTIME"],
              directory.hasPrefix("/tmp/ec05-"), !directory.contains("..") else {
            return VaultSession(client: nil)
        }
        return VaultSession(client: SocketWorkspaceClient(client: DaemonClient(directory: directory)))
    }
}
#endif
