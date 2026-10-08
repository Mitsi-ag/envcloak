import EnvCloakDesign
import EnvCloakKit
import SwiftUI

private struct BindingRowValue: Identifiable {
    let id: String
    let binding: CheckBindingView
    let item: ItemView?
    let inherited: Bool
    var variable: String { binding.env_name?.escaped ?? "Unnamed variable" }
    var key: String { binding.reference?.escaped ?? "No reference" }
    var providerAccount: String { [item?.provider?.escaped, item?.account?.email?.escaped].compactMap { $0 }.joined(separator: ", ") }
    var classification: String { item?.classification.rawValue.capitalized ?? "Unknown" }
    var status: String { binding.status.words }
    var origin: String { inherited ? "Inherited from Default" : "" }
}

struct BindingsTable: View {
    let session: VaultSession
    let project: OpenedProject
    let profile: String?
    @Binding var selectedKey: DaemonText?
    var bind: (BindingSelection) -> Void = { _ in }
    @Environment(\.undoManager) private var undoManager
    @Binding var selection: String?
    @State private var sortOrder = [KeyPathComparator(\BindingRowValue.variable)]
    private var rows: [BindingRowValue] {
        project.bindings(profile: profile).enumerated().map { index, binding in
            let slug = binding.reference.flatMap(MetadataRequest.slug)
            return BindingRowValue(id: binding.env_name?.escaped ?? "Unavailable \(index)", binding: binding, item: session.items.rows.first { $0.slug == slug }, inherited: profile != nil && binding.profile == nil)
        }.sorted(using: sortOrder)
    }
    private var selectedSlug: DaemonText? { rows.first { $0.id == selection }?.item?.slug }
    var body: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Variable", value: \.variable) {
                Text($0.variable).font(ECFont.martianMono(size: 12)).accessibilityIdentifier("binding.variable." + $0.variable)
            }
            TableColumn("Key", value: \.key) { Text($0.key).font(ECFont.martianMono(size: 12)) }
            TableColumn("Provider and account", value: \.providerAccount)
            TableColumn("Class", value: \.classification)
            TableColumn("Status", value: \.status) { row in
                Label(row.status, systemImage: row.binding.status == .ok ? "checkmark.circle" : "exclamationmark.triangle")
                    .foregroundStyle(row.binding.status == .ok ? ECToken.success.color : ECToken.warning.color)
            }
            TableColumn("Access") { row in
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    let grants = session.grants.rows.filter { grant in
                        grant.project_dir == project.grantDirectory && session.grants.remaining(grant) > 0 && grant.bindings.contains { $0.env_name == row.binding.env_name && $0.slug == row.item?.slug }
                    }
                    Text(grants.map { "Grant recorded for " + ($0.label?.escaped ?? $0.kind.rawValue) + ", \(session.grants.remaining($0)) seconds left" }.joined(separator: "; "))
                        .help("A grant names this variable and key. The next run must still match its approved manifest, fields and command.")
                }
            }
            TableColumn("Origin", value: \.origin)
        }.accessibilityIdentifier("project.bindings")
        .contextMenu(forSelectionType: String.self) { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                Button("Change key…") { change(row) }.disabled(session.state != .ready)
                Button("Remove variable") { unbind(row.id) }.disabled(session.state != .ready || row.inherited)
            }
        } primaryAction: { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) { change(row) }
        }
        .onDeleteCommand { unbind(selection) }
        .onChange(of: rows.map(\.id), initial: true) { _, ids in
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
        .onChange(of: selectedSlug, initial: true) { _, slug in selectedKey = slug }
        .onChange(of: profile) { _, _ in selection = nil }
        .onChange(of: project.directory) { _, _ in selection = nil }
    }
    private func change(_ row: BindingRowValue) {
        bind(BindingSelection(project: project.directory, key: row.item, variable: row.variable, profile: profile ?? ""))
    }
    private func unbind(_ variable: String?) {
        guard let edit = project.removal(of: variable, profile: profile) else {
            if rows.first(where: { $0.id == variable })?.inherited == true {
                session.notice = "Switch to Default to remove this inherited variable."
            }
            return
        }
        Task { _ = await session.bindings.apply(edit, session: session, manager: undoManager) }
    }
}
