import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct KeyInspector: View {
    let session: VaultSession
    let slug: DaemonText?
    @Binding var route: Route?
    @Environment(\.colorScheme) private var colorScheme
    @State private var action: InspectorAction?
    @State private var selectedField: DaemonText?
    var body: some View {
        content.task(id: slug) { await session.selectKey(slug) }
            .onChange(of: slug) { _, _ in action = nil; selectedField = nil }
            .onChange(of: session.state) { _, state in if state != .ready { action = nil } }
    }
    @ViewBuilder private var content: some View {
        if let summary = session.items.rows.first(where: { $0.slug == slug }) {
            let item = session.items.selectedItem?.slug == slug ? session.items.selectedItem! : summary
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(item.title.escaped).font(.title3)
                    Text(item.slug.escaped).font(ECFont.martianMono(size: 12)).textSelection(.enabled)
                    Text([item.provider?.escaped, item.classification.rawValue.capitalized].compactMap { $0 }.joined(separator: " · "))
                    HStack {
                        Text((item.env_hint?.escaped ?? "VALUE") + "=").font(ECFont.martianMono(size: 12))
                        Rectangle().fill(colorScheme == .dark ? ECToken.amber.color : ECToken.text.color).frame(width: 48, height: 14).accessibilityLabel("Value held in the vault")
                    }
                    Text("Stored in the vault. \(item.fields.count) fields, \(item.fields.reduce(0) { $0 + Int($1.prior_count) }) earlier values kept.")
                    if item.fields.count > 1 {
                        Picker("Field to replace", selection: $selectedField) {
                            Text("Choose a field").tag(Optional<DaemonText>.none)
                            ForEach(DisplayRow.of(item.fields)) { Text($0.value.name.escaped).tag(Optional($0.value.name)) }
                        }
                    }
                    HStack {
                        Button("Reveal…") { action = .reveal }
                        Button("Replace…") { action = .replace }
                            .disabled(session.state != .ready || InspectorAction.replace.commandWords(item: item, field: selectedField) == nil)
                    }
                    Text("Account").font(.headline)
                    ForEach(DisplayRow.of([item.account?.email, item.account?.label, item.account?.org_id].compactMap { $0 })) { Text($0.value.escaped) }
                    Text("Used by (last adopted run)").font(.headline)
                    if session.projects.failure != nil { Text("Projects could not be refreshed. Try again.") }
                    ForEach(Array(session.usedBy(item.slug).enumerated()), id: \.offset) { _, project in
                        if MetadataRequest.directoryURL(project.dir) != nil {
                            Button(session.projects.title(project.dir)) { route = .project(project.dir) }
                        } else { Text(ProjectInventoryRow.hiddenPathMessage) }
                        ForEach(DisplayRow.of(project.bindings.filter { MetadataRequest.slug($0.reference) == item.slug })) { Text($0.value.envName.escaped).font(ECFont.martianMono(size: 10)) }
                    }
                    Text("Access").font(.headline)
                    GrantRows(session: session, directory: nil, slug: item.slug)
                    if session.items.detailFailure != nil {
                        Text("Key details could not be refreshed. Try again.")
                        Button("Retry details") { Task { await session.selectKey(slug) } }
                    } else if item.detail == nil { Text("Loading key details…") }
                    if let detail = item.detail {
                        Text("Links").font(.headline)
                        link("Docs", detail.links.docs); link("Billing", detail.links.billing)
                        link("Keys page", detail.links.keys_page); link("Dashboard", detail.links.dashboard)
                        Text("Allowed hosts").font(.headline)
                        ForEach(DisplayRow.of(detail.allowed_hosts)) { Text($0.value.escaped).font(ECFont.martianMono(size: 10)) }
                        if let notes = detail.notes { Text(notes.escaped) }
                        Text(detail.tags.map(\.escaped).joined(separator: ", "))
                    }
                    LabeledContent("Created") { DateLabel(seconds: item.created_secs) }
                    LabeledContent("Rotated") { DateLabel(seconds: item.rotated_secs) }
                    LabeledContent("Last used") { DateLabel(seconds: item.last_used_secs ?? item.detail?.last_used_secs) }
                    LabeledContent("Expires") { DateLabel(seconds: item.expires_secs) }
                    Text("Balance and spend arrive in a later release (M4).").foregroundStyle(ECToken.secondary.color)
                    Button("Remove key…") { action = .remove }
                        .foregroundStyle(ECToken.danger.color).disabled(session.state != .ready)
                }.padding(16)
            }.onChange(of: item.fields.map(\.name), initial: true) { _, fields in
                if !fields.contains(selectedField ?? DaemonText("")) { selectedField = fields.count == 1 ? fields.first : nil }
            }.sheet(item: $action) { action in
                InspectorActionSheet(action: action, item: item, field: selectedField)
            }

        } else {
            ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a key, binding or entry to see its details."))
        }
    }
    @ViewBuilder private func link(_ title: String, _ value: DaemonText?) -> some View {
        if let url = MetadataRequest.safeLink(value) { Link(title, destination: url).help(value?.escaped ?? "") }
    }
}

enum InspectorAction: String, Identifiable {
    case reveal, replace, remove
    var id: String { rawValue }
    func commandWords(item: ItemView, field: DaemonText?) -> [String]? {
        switch self {
        case .reveal: return nil
        case .replace:
            guard let field, item.fields.contains(where: { $0.name == field }) else { return nil }
            return ["rotate", MetadataRequest.replaceTarget(slug: item.slug, field: field)]
        case .remove: return ["rm", MetadataRequest.path(item.slug)]
        }
    }
}

struct InspectorActionSheet: View {
    let action: InspectorAction
    let item: ItemView
    let field: DaemonText?
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if action == .reveal {
                Text("Reveal is unavailable in this build.").font(.headline)
            } else if let arguments = action.commandWords(item: item, field: field) {
                let command = MetadataRequest.terminalCommand(arguments)
                Text("Continue in Terminal").font(.headline)
                Text("This action arrives in the app with Touch ID. The command requires a human Terminal session.")
                Text(Escape.display(command)).font(ECFont.martianMono(size: 12)).textSelection(.enabled)
                Button("Copy command") { WorkspaceActions.copy(command) }
            } else { Text("Choose a field before replacing its value.") }
            Button("Done") { dismiss() }
        }.padding(24).frame(width: 440)
    }
}
