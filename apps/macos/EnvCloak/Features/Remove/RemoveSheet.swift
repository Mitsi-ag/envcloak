import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct RemoveSheet: View {
    let session: VaultSession
    let item: ItemView
    @Environment(\.dismiss) private var dismiss
    @State private var model: KeyWriteModel

    init(session: VaultSession, item: ItemView, model: KeyWriteModel? = nil) {
        self.session = session
        self.item = item
        _model = State(initialValue: model ?? KeyWriteModel(slug: item.slug, field: nil))
    }

    private var usedProjectNames: [String] {
        session.usedBy(item.slug).map { session.projects.title($0.dir) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Remove \(item.slug.escaped)?")
                .font(.title3)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("remove.title")

            VStack(alignment: .leading, spacing: 6) {
                if !usedProjectNames.isEmpty {
                    Text("\(usedProjectNames.joined(separator: " and ")) use it. Their next runs fail until you bind another key.")
                        .foregroundStyle(ECToken.text.color)
                } else {
                    Text("No projects currently bind this key.")
                        .foregroundStyle(ECToken.secondary.color)
                }
                if let grantCount = model.target?.grants, grantCount > 0 {
                    Text("\(grantCount) \(grantCount == 1 ? "grant" : "grants") in force will end.")
                        .foregroundStyle(ECToken.secondary.color)
                }

                Text("EnvCloak writes an encrypted backup of the vault first. envcloak recover with your Recovery Kit brings it back.")
                    .foregroundStyle(ECToken.secondary.color)
            }
            .font(.subheadline)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("remove.facts")

            if let notice = model.notice {
                Text(notice)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("remove.error")
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(session.removeButtonTitle) {
                    Task {
                        await model.submitRemoval(session)
                        if model.completed { dismiss() }
                    }
                }
                .foregroundStyle(ECToken.danger.color)
                .disabled(model.target == nil || model.busy || session.state != .ready)
                .accessibilityIdentifier("remove.confirm")
            }
        }
        .padding(24)
        .frame(width: 460)
        .interactiveDismissDisabled(model.busy)
        .task { await model.loadTarget(session) }
        .onDisappear { model.reset() }
        .onChange(of: session.state) { _, state in
            if state != .ready { model.reset(); dismiss() }
        }
    }
}
