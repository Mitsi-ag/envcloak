import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct PasteSheet: View {
    let session: VaultSession
    let useInProject: (ItemView) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var model: PasteModel
    init(session: VaultSession, useInProject: @escaping (ItemView) -> Void, model: PasteModel = PasteModel()) {
        self.session = session; self.useInProject = useInProject
        _model = State(initialValue: model)
    }
    @State private var savedAt = Date()
    @Environment(\.accessibilityReduceMotion) private var reducedMotion
    private func savedSummary(_ saved: AddedView) -> String {
        let provider = saved.item.provider?.escaped ?? saved.detected?.escaped ?? "Unknown provider"
        return "Saved as \(saved.item.slug.escaped). \(provider), \(saved.item.classification.rawValue)."
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add key").font(.title2)
            if let saved = model.saved {
                TimelineView(.animation(paused: reducedMotion)) { context in
                    HStack(spacing: 0) {
                        Text((model.variable.isEmpty ? "KEY" : Escape.display(model.variable)) + "=")
                        Text("█").opacity(reducedMotion || ECMotion.signOffVisible(context.date.timeIntervalSince(savedAt), from: 0) ? 1 : 0)
                    }.font(ECFont.martianMono(size: 13))
                }
                Text(savedSummary(saved))
                    .accessibilityIdentifier("paste.saved")
                Button("Use in project") { useInProject(saved.item) }.accessibilityIdentifier("paste.bind")
                HStack {
                    Button("Add another") { model.reset() }.accessibilityIdentifier("paste.another")
                    Spacer()
                    Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
                }
            } else {
                PasteField(receive: { model.receive(&$0) }, cleared: { cleared in
                    model.clipboardNotice = cleared
                        ? "Cleared from the clipboard. Clipboard managers may have kept a copy."
                        : "The clipboard changed after pasting. Its new contents were kept."
                }).frame(height: 26).privacySensitive()
                if model.count > 0 { Text("Pasted. \(model.count) characters.").foregroundStyle(ECToken.secondary.color) }
                if model.droppedLineEnding { Text("Removed one final line ending.").foregroundStyle(ECToken.secondary.color) }
                if let name = model.envName {
                    Text("This looks like an env line. Use " + Escape.display(name) + " as the variable and the part after = as the key?")
                    HStack { Button("Use env line") { model.useEnvLine() }; Button("Keep as pasted") { model.keepPasted() } }
                }
                TextField("Name (automatic, from the provider)", text: $model.name).accessibilityIdentifier("paste.name")
                TextField("Account (optional email)", text: $model.account).accessibilityIdentifier("paste.account")
                TextField("Variable (optional)", text: $model.variable).accessibilityIdentifier("paste.variable")
                Text("Provider detection appears after saving.").foregroundStyle(ECToken.secondary.color)
                if let notice = model.notice { Text(notice).foregroundStyle(ECToken.warning.color) }
                HStack {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Save") { Task { await model.save(session); savedAt = Date() } }
                        .keyboardShortcut(.return, modifiers: .command).accessibilityIdentifier("paste.save")
                        .disabled(model.count == 0 || model.envName != nil || model.busy || session.state != .ready)
                }
            }
            if let notice = model.clipboardNotice { Text(notice).font(.caption).foregroundStyle(ECToken.secondary.color) }
        }.padding(24).frame(width: 480)
        .interactiveDismissDisabled(model.busy)
        .onDisappear { model.reset() }
        .onChange(of: session.state) { _, state in if state != .ready { model.reset(); dismiss() } }
    }
}
