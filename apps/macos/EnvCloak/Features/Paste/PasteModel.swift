import AppKit
import EnvCloakKit
import Observation

@Observable @MainActor final class PasteModel {
    @ObservationIgnored private var draft: PasteDraft?
    var name = ""
    var account = ""
    var variable = ""
    var count = 0
    var envName: String?
    var droppedLineEnding = false
    var notice: String?
    var clipboardNotice: String?
    var saved: AddedView?
    var busy = false

    func receive(_ text: inout String) {
        draft = nil; count = 0; envName = nil; notice = nil; saved = nil; droppedLineEnding = false
        do {
            let incoming = try PasteDraft(taking: &text)
            count = incoming.characters
            envName = incoming.envName
            droppedLineEnding = incoming.droppedLineEnding
            draft = consume incoming
        } catch PasteError.multipleLines {
            notice = "This looks like several lines of an env file. Import files with envcloak import instead."
        } catch { notice = "The key could not be read. Paste one nonempty value of at most 64 KiB." }
    }

    func useEnvLine() {
        guard var incoming = draft.take() else { return }
        do {
            try incoming.useEnvLine()
            variable = incoming.envName ?? ""
            count = incoming.characters
            envName = nil
            draft = consume incoming
        } catch { count = 0; envName = nil; notice = "The env line has no value." }
    }

    func keepPasted() { envName = nil }

    func save(_ session: VaultSession) async {
        guard !busy, envName == nil, let incoming = draft.take() else { return }
        busy = true; notice = nil
        defer { busy = false; count = 0 }
        do {
            saved = try await session.add(ItemsAdd(value: incoming.takeValue(),
                slug: name.isEmpty ? nil : name, account: account.isEmpty ? nil : account,
                envHint: variable.isEmpty ? nil : variable))
        } catch {
            // The request may have committed before a connection failed.
            notice = "The save outcome could not be confirmed. Check Keys before pasting again. Names shaped like a key are refused."
        }
    }

    func reset() {
        draft = nil; name = ""; account = ""; variable = ""; count = 0
        envName = nil; saved = nil; notice = nil; clipboardNotice = nil; droppedLineEnding = false
    }
}
