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
    static func terminalCommand(_ verb: String, slug: DaemonText) -> String {
        // POSIX shell single-quote escaping, including a quote in a slug.
        "envcloak " + verb + " '" + slug.unescaped.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    static func changeDirectoryCommand(_ directory: DaemonText) -> String {
        "cd -- '" + directory.unescaped.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    static func path(_ directory: DaemonText) -> String { directory.unescaped }
}
