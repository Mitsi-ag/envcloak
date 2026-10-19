import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct PasteSheet: View {
    let session: VaultSession
    let useInProject: (ItemView) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var model: PasteModel
    init(
        session: VaultSession,
        useInProject: @escaping (ItemView) -> Void,
        model: PasteModel = PasteModel(),
        ask: AskSummary? = nil
    ) {
        self.session = session
        self.useInProject = useInProject
        if let ask, model.ask == nil {
            model.ask = ask
            if model.account.isEmpty, let askAccount = ask.account?.escaped {
                model.account = askAccount
            }
        }
        _model = State(initialValue: model)
    }
    @State private var savedAt = Date()
    @Environment(\.accessibilityReduceMotion) private var reducedMotion

    private func savedSummary(_ saved: AddedView) -> String {
        let provider = saved.item.provider?.escaped ?? saved.detected?.escaped ?? "Unknown provider"
        return "Saved as \(saved.item.slug.escaped). \(provider), \(saved.item.classification.rawValue)."
    }

    private func inspectionSummary(_ info: AppPasteInspectView) -> String {
        let provider = info.provider?.escaped ?? info.detected?.escaped ?? "Unknown provider"
        var parts = ["\(provider), \(info.classification.rawValue), length \(info.length.rawValue)."]
        if let slug = info.suggested_slug?.escaped {
            parts.append("Suggested name: \(slug).")
        }
        if let env = info.env_hint?.escaped {
            parts.append("Suggested variable: \(env).")
        }
        return parts.joined(separator: " ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let ask = model.ask {
                let caller = ask.requester.label?.escaped ?? ask.requester.kind.rawValue.capitalized
                let providerText = ask.provider?.escaped ?? "a service"
                let projectSuffix = ask.project_dir.map { " in \(MetadataRequest.basename($0))" } ?? ""
                Text("\(caller) asks you to add a key for \(providerText)\(projectSuffix). It will learn only the new key's name.")
                    .font(.headline)
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityIdentifier("paste.ask.header")
                VStack(alignment: .leading, spacing: 4) {
                    Text("Evidence")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(ECToken.secondary.color)
                    let exeText = ask.requester.root.exe?.escaped ?? "Unknown executable"
                    Text("\(exeText) · Caller PID \(ask.requester.caller_pid) · Root PID \(ask.requester.root.pid)")
                        .font(ECFont.martianMono(size: 11))
                        .foregroundStyle(ECToken.secondary.color)
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("paste.ask.evidence")
            } else {
                Text("Add key").font(.title2)
            }

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
                PasteField(receive: {
                    model.receive(&$0)
                    model.startInspect(session)
                }, cleared: { cleared in
                    model.clipboardNotice = cleared
                        ? "Cleared from the clipboard. Clipboard managers may have kept a copy."
                        : "The clipboard changed after pasting. Its new contents were kept."
                }).frame(height: 26).privacySensitive()
                if model.count > 0 { Text("Pasted. \(model.count) characters.").foregroundStyle(ECToken.secondary.color) }
                if model.droppedLineEnding { Text("Removed one final line ending.").foregroundStyle(ECToken.secondary.color) }
                if let name = model.envName {
                    Text("This looks like an env line. Use " + Escape.display(name) + " as the variable and the part after = as the key?")
                    HStack {
                        Button("Use env line") {
                            model.useEnvLine()
                            model.startInspect(session)
                        }
                        Button("Keep as pasted") {
                            model.keepPasted()
                            model.startInspect(session)
                        }
                    }
                }
                if let inspection = model.inspection {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("What EnvCloak found")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(ECToken.secondary.color)
                        Text(inspectionSummary(inspection))
                            .font(.subheadline)
                            .foregroundStyle(ECToken.text.color)
                            .accessibilityIdentifier("paste.inspection")
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                } else {
                    Text("Provider detection appears after saving.").foregroundStyle(ECToken.secondary.color)
                }
                TextField("Name (automatic, from the provider)", text: $model.name).accessibilityIdentifier("paste.name")
                TextField("Account (optional email)", text: $model.account).accessibilityIdentifier("paste.account")
                TextField("Variable (optional)", text: $model.variable).accessibilityIdentifier("paste.variable")
                if let ask = model.ask {
                    let caller = ask.requester.label?.escaped ?? ask.requester.kind.rawValue.capitalized
                    Text("No access is granted. \(caller) asks again when it runs with this key.")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("paste.ask.notice")
                }

                if let notice = model.notice {
                    Text(notice).foregroundStyle(ECToken.warning.color)
                        .accessibilityIdentifier("paste.error")
                }
                HStack {
                    if model.ask != nil {
                        Button("Decline") {
                            Task {
                                if await model.decline(session) { dismiss() }
                            }
                        }
                        .keyboardShortcut(.cancelAction)
                        .disabled(model.busy)
                        .accessibilityIdentifier("paste.decline")
                    } else {
                        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    }
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

