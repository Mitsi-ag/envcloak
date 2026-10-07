import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct KeyInspector: View {
    let session: VaultSession
    let slug: DaemonText?
    @Binding var route: Route?
    @Environment(\.colorScheme) private var colorScheme
    @State private var command: String?
    var body: some View {
        content.task(id: slug) { await session.selectKey(slug) }
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
                    HStack {
                        Button("Reveal…") { command = MetadataRequest.terminalCommand("reveal", slug: item.slug) }
                        Button("Replace…") { command = MetadataRequest.terminalCommand("rotate", slug: item.slug) }.disabled(session.state != .ready)
                    }
                    Text("Account").font(.headline)
                    ForEach([item.account?.email, item.account?.label, item.account?.org_id].compactMap { $0 }, id: \.self) { Text($0.escaped) }
                    Text("Used by (last adopted run)").font(.headline)
                    if session.projects.failure != nil { Text("Projects could not be refreshed. Try again.") }
                    ForEach(Array(session.usedBy(item.slug).enumerated()), id: \.offset) { _, project in
                        if MetadataRequest.directoryURL(project.dir) != nil {
                            Button(session.projects.title(project.dir)) { route = .project(project.dir) }
                        } else { Text(ProjectInventoryRow.hiddenPathMessage) }
                        ForEach(project.bindings.filter { MetadataRequest.slug($0.reference) == item.slug }, id: \.envName) { Text($0.envName.escaped).font(ECFont.martianMono(size: 10)) }
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
                        ForEach(detail.allowed_hosts, id: \.self) { Text($0.escaped).font(ECFont.martianMono(size: 10)) }
                        if let notes = detail.notes { Text(notes.escaped) }
                        Text(detail.tags.map(\.escaped).joined(separator: ", "))
                    }
                    LabeledContent("Created") { DateLabel(seconds: item.created_secs) }
                    LabeledContent("Rotated") { DateLabel(seconds: item.rotated_secs) }
                    LabeledContent("Last used") { DateLabel(seconds: item.last_used_secs ?? item.detail?.last_used_secs) }
                    LabeledContent("Expires") { DateLabel(seconds: item.expires_secs) }
                    Text("Balance and spend arrive in a later release (M4).").foregroundStyle(ECToken.secondary.color)
                    Button("Remove key…") { command = MetadataRequest.terminalCommand("rm", slug: item.slug) }
                        .foregroundStyle(ECToken.danger.color).disabled(session.state != .ready)
                }.padding(16)
            }.sheet(isPresented: Binding(get: { command != nil }, set: { if !$0 { command = nil } })) {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Continue in Terminal").font(.headline)
                    if command?.hasPrefix("envcloak reveal ") == true {
                        Text("Reveal is unavailable in this build. Its command will open the app in a later release.")
                    } else {
                        Text("This action arrives in the app with Touch ID. The command requires a human Terminal session.")
                    }
                    Text(Escape.display(command ?? "")).font(ECFont.martianMono(size: 12)).textSelection(.enabled)
                    Button("Copy command") { if let command { WorkspaceActions.copy(command) } }
                    Button("Done") { command = nil }
                }.padding(24).frame(width: 440)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a key, binding or entry to see its details."))
        }
    }
    @ViewBuilder private func link(_ title: String, _ value: DaemonText?) -> some View {
        if let url = MetadataRequest.safeLink(value) { Link(title, destination: url).help(value?.escaped ?? "") }
    }
}
