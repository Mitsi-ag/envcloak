import AppKit
import EnvCloakKit
import Foundation

@MainActor enum WorkspaceActions {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
    static func openTerminal() {
        let url = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }
    static func showFolder(_ path: DaemonText) {
        if let url = MetadataRequest.directoryURL(path) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    }
    static func openFolderInTerminal(_ path: DaemonText) {
        // Never hand an untrusted path to Terminal's document opener:
        // a replaced folder could instead be an executable .command file.
        copy(MetadataRequest.changeDirectoryCommand(path))
        openTerminal()
    }
    static func addFolder(_ session: VaultSession, selected: @escaping @MainActor (DaemonText) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.allowsMultipleSelection = false
        panel.prompt = "Add project folder"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                try session.projects.add(url)
                selected(DaemonText(url.path))
            } catch { session.notice = "The project folder could not be saved. Try again." }
        }
    }
    static func startDaemon(_ session: VaultSession) async {
        guard !session.actionInProgress else { return }
        session.actionInProgress = true
        defer { session.actionInProgress = false }
        do {
            let cli = try CLIRunner()
            let daemon = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd")
            _ = try await cli.run(arguments: ["daemon", "install", "--daemon", daemon.path], workingDirectory: "/")
            await session.poll()
            if session.state == .noDaemon { session.notice = "The background process was installed but has not answered yet." }
        } catch { session.notice = "The background process could not be started. Try envcloak daemon install in Terminal." }
    }
}
