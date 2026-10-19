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
    static let hiddenMarker = "[not shown: looks like a key or token]"
    static func replaceTarget(slug: DaemonText, field: DaemonText) -> String? {
        guard canCopy(slug), canCopy(field) else { return nil }
        return slug.unescaped + "#" + field.unescaped
    }
    static func changeDirectoryCommand(_ directory: DaemonText) -> String? {
        let raw = directory.unescaped
        guard canCopy(directory), raw.hasPrefix("/"), !raw.contains(hiddenMarker) else { return nil }
        return "cd -- '" + raw.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    static func rotateSlugCommand(_ slug: DaemonText) -> TerminalCopy? {
        let raw = slug.unescaped
        guard canCopy(slug), !raw.isEmpty, !raw.contains(hiddenMarker),
              let text = terminalCommand(["rotate", raw]) else { return nil }
        return TerminalCopy(text)
    }
    static func deletePlaintextCommand(_ directory: DaemonText) -> TerminalCopy? {
        guard let cd = changeDirectoryCommand(directory) else { return nil }
        return TerminalCopy(cd + " && envcloak init --delete-plaintext")
    }
    static func canCopy(_ text: DaemonText) -> Bool { TerminalCopy.isSafe(text.unescaped) }
    static func clipboardPath(_ directory: DaemonText) -> TerminalCopy? { TerminalCopy(directory.unescaped) }
    static func path(_ directory: DaemonText) -> String { directory.unescaped }
    static func raw(_ text: DaemonText) -> String { text.unescaped }
    static func pendingGet(_ id: DaemonText) -> AppPendingGet { AppPendingGet(request: id.unescaped) }
    static func deny(_ id: DaemonText) -> Deny { Deny(request: id.unescaped) }
    static func unlockBegin(unlockerID: DaemonText? = nil) -> AppUnlockBegin { AppUnlockBegin(unlocker_id: unlockerID?.unescaped) }
    static func unlockFinish(requestID: DaemonText, sealed: String) -> AppUnlock { AppUnlock(request_id: requestID.unescaped, sealed: sealed) }
    static func enrollBegin(unlockPublicKeyHex: String, approvePublicKeyHex: String, label: String = "This Mac") -> AppUnlockerEnrollBegin {
        AppUnlockerEnrollBegin(unlock_pub: unlockPublicKeyHex, approve_pub: approvePublicKeyHex, label: label)
    }
    static func enrollPoll(_ request: DaemonText) -> AppUnlockerEnroll { AppUnlockerEnroll(request: request.unescaped) }
    static func approve(request: DaemonText, options: ApprovalOptions, digestHex: String, signatureHex: String) -> AppApprove {
        AppApprove(request: request.unescaped, options: options, digest: digestHex, signature: signatureHex)
    }
    static func standingRevoke(_ id: DaemonText) -> StandingRevoke { StandingRevoke(id: id.unescaped, all: false) }
    static func proposalEdit(project: DaemonText, proposal: Proposal) -> BindingEdit {
        let profile: String? = switch proposal.source {
        case .profile(let name): name.unescaped
        case .env, .envFile, .ref: nil
        }
        let reference: String = if let field = proposal.test_field, !field.unescaped.isEmpty {
            proposal.test_slug.unescaped + "#" + field.unescaped
        } else {
            proposal.test_slug.unescaped
        }
        return BindingEdit(
            project: project,
            profile: profile,
            envName: proposal.env_name.unescaped,
            reference: reference,
            previous: nil
        )
    }
    static func enrollApprovalCommand(request: DaemonText) -> TerminalCopy? {
        guard canCopy(request), let text = terminalCommand(["approve", request.unescaped]) else { return nil }
        return TerminalCopy(text)
    }
}

/// Views can display or copy this text, but cannot obtain its raw String.
struct TerminalCopy {
    private let text: String
    static let refusalMessage = "Copying to Terminal is unavailable because this text contains control or directional characters."
    static func isSafe(_ text: String) -> Bool {
        !text.unicodeScalars.contains { scalar in
            CharacterSet.controlCharacters.contains(scalar) ||
            scalar.value == 0x2028 || scalar.value == 0x2029 ||
            (0x200B...0x200F).contains(scalar.value) ||
            (0x202A...0x202E).contains(scalar.value) ||
            (0x2060...0x206F).contains(scalar.value)
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
