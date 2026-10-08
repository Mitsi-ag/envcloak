#if ENVCLOAK_SCREEN_TESTS
#if !DEBUG
#error("Screen test hosts must never ship")
#endif
import AppKit
@testable import EnvCloakKit

/// Present only in the explicitly compiled XCTest host. Release refuses
/// this flag. Normal Debug and Release builds have no runtime override.
@MainActor enum ScreenTestBootstrap {
    static func windowFrame(in bounds: NSRect) -> NSRect {
        // Exercise the small desktop layout even on a larger development
        // display. The usable frame excludes the menu bar and Dock.
        let width = min(1024, bounds.width)
        let height = min(700, bounds.height)
        return NSRect(x: bounds.midX - width / 2, y: bounds.midY - height / 2, width: width, height: height)
    }

    static func positionWindow() async {
        // Keep UI automation independent of the person's restored window
        // size, monitor arrangement and focus. Only this test app moves.
        for _ in 0..<20 {
            if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == WindowID.main }),
               let screen = NSScreen.screens.first {
                let bounds = screen.visibleFrame
                window.setFrame(windowFrame(in: bounds), display: true)
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
        do {
            let folders = try ProjectFolders(file: URL(fileURLWithPath: directory).appendingPathComponent("test-folders.json"))
            let runner: CLIRunner?
            if let executable = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_CLI"],
               let home = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_HOME"], home.hasPrefix("/tmp/ec05-") {
                runner = CLIRunner(executable: executable, home: home, timeout: .seconds(30))
            } else { runner = nil }
            return VaultSession(client: SocketWorkspaceClient(client: DaemonClient(directory: directory)), folders: folders, runner: runner)
        } catch {
            let session = VaultSession(client: nil)
            session.state = .unavailable
            return session
        }
    }
}
#endif
