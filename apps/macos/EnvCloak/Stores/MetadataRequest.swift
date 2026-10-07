import AppKit
import EnvCloakKit
import Foundation

/// Raw metadata is used only as protocol input or a filesystem location.
/// All labels use DaemonText.escaped. No shell is used for any action.
enum MetadataRequest {
    static func check(_ directory: DaemonText) -> ItemsCheck {
        ItemsCheck(manifest: URL(fileURLWithPath: directory.unescaped).appendingPathComponent("envcloak.toml").path)
    }
    static func revoke(_ id: DaemonText) -> GrantsRevoke { GrantsRevoke(grant: id.unescaped) }
    static func show(_ slug: DaemonText) -> ItemsShow { ItemsShow(slug: slug.unescaped) }
    static func directoryURL(_ path: DaemonText) -> URL? {
        guard path.unescaped.hasPrefix("/"), !path.unescaped.utf8.contains(0) else { return nil }
        return URL(fileURLWithPath: path.unescaped, isDirectory: true)
    }
    static func basename(_ path: DaemonText) -> String {
        Escape.display(URL(fileURLWithPath: path.unescaped).lastPathComponent)
    }
    static func slug(_ reference: DaemonText) -> DaemonText? {
        let text = reference.unescaped
        let referenceText = text.hasPrefix("envcloak://") ? String(text.dropFirst(11)) : text
        let parts = referenceText.split(separator: "#", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), !parts[0].isEmpty else { return nil }
        return DaemonText(String(parts[0]))
    }
    static func safeLink(_ text: DaemonText?) -> URL? {
        guard let raw = text?.unescaped, let url = URL(string: raw),
              url.scheme == "https", url.host != nil, url.user == nil, url.password == nil,
              !raw.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return url
    }
    static func terminalCommand(_ arguments: [String]) -> String? {
        guard arguments.allSatisfy(TerminalCopy.isSafe) else { return nil }
        // The verb comes from InspectorAction, the target is always quoted.
        return "envcloak " + arguments.enumerated().map { index, argument in
            index == 0 ? argument : "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }
    static func replaceTarget(slug: DaemonText, field: DaemonText) -> String? {
        guard canCopy(slug), canCopy(field) else { return nil }
        return slug.unescaped + "#" + field.unescaped
    }
    static func changeDirectoryCommand(_ directory: DaemonText) -> String? {
        guard canCopy(directory) else { return nil }
        return "cd -- '" + directory.unescaped.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    static func canCopy(_ text: DaemonText) -> Bool { TerminalCopy.isSafe(text.unescaped) }
    static func clipboardPath(_ directory: DaemonText) -> TerminalCopy? { TerminalCopy(directory.unescaped) }
    static func path(_ directory: DaemonText) -> String { directory.unescaped }
}

/// Views can display or copy this text, but cannot obtain its raw String.
struct TerminalCopy {
    private let text: String
    static let refusalMessage = "Copying to Terminal is unavailable because this text contains control or directional characters."
    static func isSafe(_ text: String) -> Bool {
        !text.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0) || $0.value == 0x2028 || $0.value == 0x2029
        }
    }
    init?(_ text: String) {
        guard Self.isSafe(text) else { return nil }
        self.text = text
    }
    var display: String { Escape.display(text) }
    @MainActor func copy(to board: NSPasteboard) -> Bool {
        board.clearContents()
        return board.setString(text, forType: .string)
    }
}
