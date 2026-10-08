import EnvCloakKit
import Foundation

/// Only metadata identifiers are registered with UndoManager. Source bytes
/// belong to the receipt's wiping storage and expire with this session.
@MainActor final class BindingHistory {
    private let runner: CLIRunner?
    private var records: [(UUID, BindingEdit, UndoReceipt)] = []
    private var busy = false
    private var epoch = 0
    init(runner: CLIRunner? = try? CLIRunner()) { self.runner = runner }
    func clear() { epoch += 1; records = [] }

    func apply(_ edit: BindingEdit, session: VaultSession, manager: UndoManager?) async -> Bool {
        guard !busy, session.state == .ready, let runner, let args = edit.cliArguments else {
            session.notice = "The binding could not be edited. Check its variable, key and project."; return false
        }
        guard records.count < 32 else {
            session.notice = "The undo history is full. Close and reopen the window before another edit."; return false
        }
        let captured = epoch
        busy = true; defer { busy = false }
        do {
            let (_, receipt) = try await runner.recordBinding(arguments: args, workingDirectory: MetadataRequest.path(edit.project))
            guard epoch == captured, session.state == .ready else {
                session.notice = "The binding was saved, but the session changed. Reopen the project to inspect it."
                return false
            }
            if receipt.available {
                let id = UUID()
                records.append((id, edit, receipt))
                manager?.registerUndo(withTarget: self) { target in
                    Task { @MainActor in await target.undo(id, session: session) }
                }
                manager?.setActionName("Binding")
            }
            await session.openProject(edit.project)
            session.notice = "Saved to envcloak.toml. The next run still asks for approval."
            return true
        } catch {
            await session.openProject(edit.project)
            session.notice = "The edit outcome could not be confirmed. Inspect the refreshed file before retrying. Undo is unavailable for this attempt."
            return false
        }
    }

    private func undo(_ id: UUID, session: VaultSession) async {
        guard !busy, session.state == .ready, let runner, let last = records.last, last.0 == id else {
            session.notice = "Undo is unavailable. Wait for the current edit and use the latest binding action."; return
        }
        busy = true; defer { busy = false }
        records.removeLast()
        do {
            try await runner.undoBinding(last.2, workingDirectory: MetadataRequest.path(last.1.project))
            await session.openProject(last.1.project)
            session.notice = "Binding undone. The original envcloak.toml bytes were restored."
        } catch {
            await session.openProject(last.1.project)
            session.notice = "Undo stopped. The file may have changed or the write could not be confirmed. Inspect it before another edit."
        }
    }
}
