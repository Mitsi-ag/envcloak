import AppKit
import EnvCloakKit
import Foundation

@MainActor enum WorkspaceActions {
    @discardableResult static func copy(_ text: String, to board: NSPasteboard = .general) -> Bool {
        guard let safe = TerminalCopy(text) else { return false }
        return copy(safe, to: board)
    }
    @discardableResult static func copy(_ text: TerminalCopy, to board: NSPasteboard = .general) -> Bool {
        text.copy(to: board)
    }
    @discardableResult static func copyPath(_ path: DaemonText, to board: NSPasteboard = .general) -> Bool {
        guard let safe = MetadataRequest.clipboardPath(path) else { return false }
        return copy(safe, to: board)
    }
    static func openTerminal() {
        let url = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }
    static func showFolder(_ path: DaemonText) {
        if let url = MetadataRequest.directoryURL(path) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    }
    @discardableResult static func openFolderInTerminal(_ path: DaemonText, to board: NSPasteboard = .general,
                                                      open: @MainActor () -> Void = openTerminal) -> Bool {
        // Never hand an untrusted path to Terminal's document opener:
        // a replaced folder could instead be an executable .command file.
        guard let command = MetadataRequest.changeDirectoryCommand(path), copy(command, to: board) else { return false }
        open()
        return true
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
    static func installBundledDaemon() async throws {
        let cli = try CLIRunner()
        let daemon = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd")
        try await installDaemon(using: cli, daemonPath: daemon.path)
    }
    static func installDaemon(using cli: CLIRunner, daemonPath: String) async throws {
        try await cli.installDaemon(at: daemonPath)
    }
    static func startDaemon(_ session: VaultSession, install: @MainActor () async throws -> Void = installBundledDaemon) async {
        guard !session.actionInProgress else { return }
        session.actionInProgress = true
        defer { session.actionInProgress = false }
        do {
            session.notice = nil
            try await install()
            await session.poll()
            if session.state == .noDaemon { session.notice = "The background process was installed but has not answered yet." }
        } catch { session.notice = "The background process could not be started. Try envcloak daemon install in Terminal." }
    }
}

enum InspectorAction: String, Identifiable {
    case reveal, replace, remove
    var id: String { rawValue }
    func commandWords(item: ItemView, field: DaemonText?) -> [String]? {
        switch self {
        case .reveal: return nil
        case .replace:
            guard let field, item.fields.contains(where: { $0.name == field }),
                  let target = MetadataRequest.replaceTarget(slug: item.slug, field: field) else { return nil }
            return ["rotate", target]
        case .remove:
            guard MetadataRequest.canCopy(item.slug) else { return nil }
            return ["rm", MetadataRequest.path(item.slug)]
        }
    }
    func command(item: ItemView, field: DaemonText?) -> TerminalCopy? {
        guard let words = commandWords(item: item, field: field), let text = MetadataRequest.terminalCommand(words) else { return nil }
        return TerminalCopy(text)
    }
}

enum CopiedCommand: CaseIterable {
    case initialize, createVault, unlock, status, recoveryHelp
    var commandWords: [String] {
        switch self {
        case .initialize: ["init"]
        case .createVault: ["vault", "create"]
        case .unlock: ["unlock"]
        case .status: ["status"]
        case .recoveryHelp: ["recover", "--help"]
        }
    }
    var text: String { "envcloak " + commandWords.joined(separator: " ") }
}
