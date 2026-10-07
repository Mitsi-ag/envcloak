import EnvCloakDesign
import EnvCloakKit
import SwiftUI

private struct BindingRowValue: Identifiable {
    let id: Int
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
    @State private var selection: Int?
    @State private var sortOrder = [KeyPathComparator(\BindingRowValue.variable)]
    private var rows: [BindingRowValue] {
        project.bindings(profile: profile).enumerated().map { index, binding in
            let slug = binding.reference.flatMap(MetadataRequest.slug)
            return BindingRowValue(id: index, binding: binding, item: session.items.rows.first { $0.slug == slug }, inherited: profile != nil && binding.profile == nil)
        }.sorted(using: sortOrder)
    }
    var body: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Variable", value: \.variable) { Text($0.variable).font(ECFont.martianMono(size: 12)) }
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
        .onChange(of: selection) { _, id in selectedKey = rows.first { $0.id == id }?.item?.slug }
    }
}
