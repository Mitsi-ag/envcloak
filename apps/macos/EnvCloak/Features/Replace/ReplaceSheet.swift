import EnvCloakDesign
import EnvCloakKit
import Observation
import SwiftUI

@Observable @MainActor final class KeyWriteModel {
    @ObservationIgnored private var draft: PasteDraft?
    let slug: DaemonText
    var selectedField: DaemonText?
    var target: AppItemsTargetView?
    var count = 0
    var envName: String?
    var droppedLineEnding = false
    var notice: String?
    var clipboardNotice: String?
    var busy = false
    var completed = false

    init(slug: DaemonText, field: DaemonText?) {
        self.slug = slug
        self.selectedField = field
    }

    func loadTarget(_ session: VaultSession) async {
        notice = nil
        do {
            target = try await session.fetchWriteTarget(slug: slug, field: selectedField)
        } catch {
            target = nil
            notice = "Key write details could not be loaded. Try again."
        }
    }

    func receive(_ text: inout String) {
        draft = nil; count = 0; envName = nil; notice = nil; droppedLineEnding = false
        do {
            let incoming = try PasteDraft(taking: &text)
            count = incoming.characters
            envName = incoming.envName
            droppedLineEnding = incoming.droppedLineEnding
            draft = consume incoming
        } catch PasteError.multipleLines {
            notice = "This looks like several lines of an env file. Paste a single key value."
        } catch {
            notice = "The key could not be read. Paste one nonempty value of at most 64 KiB."
        }
    }

    func useEnvLine() {
        guard var incoming = draft.take() else { return }
        do {
            try incoming.useEnvLine()
            count = incoming.characters
            envName = nil
            draft = consume incoming
        } catch {
            count = 0; envName = nil; notice = "The env line has no value."
        }
    }

    func keepPasted() {
        envName = nil
    }

    func submitRotation(_ session: VaultSession) async {
        guard !busy, envName == nil, let target, let incoming = draft.take() else { return }
        busy = true; notice = nil
        defer { busy = false }
        do {
            _ = try await session.rotateItemWithTouchID(target: target, newValue: incoming.value)
            count = 0
            completed = true
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            draft = consume incoming
            notice = "Touch ID was cancelled. The key value was not replaced."
        } catch {
            draft = consume incoming
            let failureNotice = session.notice ?? "The key value could not be replaced."
            await loadTarget(session)
            notice = failureNotice
        }
    }

    func submitRemoval(_ session: VaultSession) async {
        guard !busy, let target else { return }
        busy = true; notice = nil
        defer { busy = false }
        do {
            _ = try await session.removeItemWithTouchID(target: target)
            completed = true
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            notice = "Touch ID was cancelled. The key was not removed."
        } catch {
            let failureNotice = session.notice ?? "The key could not be removed."
            await loadTarget(session)
            notice = failureNotice
        }
    }


    func reset() {
        draft = nil; count = 0; envName = nil; droppedLineEnding = false
        notice = nil; clipboardNotice = nil; busy = false
    }
}

struct ReplaceSheet: View {
    let session: VaultSession
    let item: ItemView
    let initialField: DaemonText?
    @Environment(\.dismiss) private var dismiss
    @State private var model: KeyWriteModel

    init(session: VaultSession, item: ItemView, field: DaemonText?, model: KeyWriteModel? = nil) {
        self.session = session
        self.item = item
        self.initialField = field
        _model = State(initialValue: model ?? KeyWriteModel(slug: item.slug, field: field ?? item.fields.first?.name))
    }

    private var usedProjectNames: [String] {
        session.usedBy(item.slug).map { session.projects.title($0.dir) }
    }

    private var usedEnvNames: [String] {
        let names = session.usedBy(item.slug).flatMap { project in
            project.bindings
                .filter { MetadataRequest.slug($0.reference) == item.slug }
                .map(\.envName.escaped)
        }
        return Array(Set(names)).sorted()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Replace the value of \(item.slug.escaped)")
                .font(.title3)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("replace.title")

            if item.fields.count > 1 {
                Picker("Field", selection: $model.selectedField) {
                    ForEach(DisplayRow.of(item.fields)) { row in
                        Text(row.value.name.escaped).tag(Optional(row.value.name))
                    }
                }
                .onChange(of: model.selectedField) { _, _ in
                    Task { await model.loadTarget(session) }
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                if !usedProjectNames.isEmpty {
                    let vars = usedEnvNames.isEmpty ? (item.env_hint?.escaped ?? "VALUE") : usedEnvNames.joined(separator: ", ")
                    Text("Used by \(usedProjectNames.joined(separator: " and ")) as \(vars).")
                        .foregroundStyle(ECToken.text.color)
                } else {
                    Text("Not currently bound to a project.")
                        .foregroundStyle(ECToken.secondary.color)
                }
                let grantCount = model.target?.grants ?? 0
                Text("\(grantCount) \(grantCount == 1 ? "grant" : "grants") in force keep working with the new value.")

                    .foregroundStyle(ECToken.secondary.color)
                Text("The current value is kept as an earlier value. EnvCloak keeps 3; the oldest is dropped.")
                    .foregroundStyle(ECToken.secondary.color)
                Text("If the new value is a different kind (for example test to live), every grant and waiting request that uses this key ends.")
                    .foregroundStyle(ECToken.secondary.color)
            }
            .font(.subheadline)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("replace.facts")

            PasteField(receive: { model.receive(&$0) }, cleared: { cleared in
                model.clipboardNotice = cleared
                    ? "Cleared from the clipboard. Clipboard managers may have kept a copy."
                    : "The clipboard changed after pasting. Its new contents were kept."
            })
            .frame(height: 26)
            .privacySensitive()

            if model.count > 0 {
                Text("Pasted. \(model.count) characters.")
                    .foregroundStyle(ECToken.secondary.color)
            }
            if model.droppedLineEnding {
                Text("Removed one final line ending.")
                    .foregroundStyle(ECToken.secondary.color)
            }
            if let env = model.envName {
                Text("This looks like an env line. Use the part after \(Escape.display(env))= as the new key value?")
                HStack {
                    Button("Use env line") { model.useEnvLine() }
                    Button("Keep as pasted") { model.keepPasted() }
                }
            }
            if let notice = model.notice {
                Text(notice)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("replace.error")
            }
            if let clip = model.clipboardNotice {
                Text(clip)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(session.replaceButtonTitle) {
                    Task {
                        await model.submitRotation(session)
                        if model.completed { dismiss() }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.target == nil || model.count == 0 || model.envName != nil || model.busy || session.state != .ready)
                .accessibilityIdentifier("replace.confirm")
            }
        }
        .padding(24)
        .frame(width: 480)
        .interactiveDismissDisabled(model.busy)
        .task { await model.loadTarget(session) }
        .onDisappear { model.reset() }
        .onChange(of: session.state) { _, state in
            if state != .ready { model.reset(); dismiss() }
        }
    }
}
