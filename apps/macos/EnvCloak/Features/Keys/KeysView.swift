import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct KeysView: View {
    let session: VaultSession
    let filter: KeyFilter
    let query: String
    let scope: DaemonText?
    @Binding var grouping: KeyGrouping
    @Binding var selectedKey: DaemonText?
    @State private var selection: KeyRowID?
    @State private var sortOrder = [KeyPathComparator(\KeyRow.item.slug.escaped)]
    @State private var columns = TableColumnCustomization<KeyRow>()
    private var sections: [KeySection] { session.keySections(query: query, filter: filter, scope: scope, grouping: grouping) }
    var body: some View {
        let sections = sections
        let rows = sections.flatMap(\.rows)
        let count = Set(rows.map { $0.item.id }).count
        VStack(alignment: .leading) {
            HStack {
                Text("\(count) keys").foregroundStyle(ECToken.secondary.color)
                Spacer()
                Picker("Group by", selection: $grouping) {
                    ForEach(KeyGrouping.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.fixedSize()
            }.padding(.horizontal)
            if session.keysUnavailable(query: query, scope: scope) {
                ContentUnavailableView("Keys could not be refreshed", systemImage: "exclamationmark.triangle", description: Text("Try again. No old listing is shown."))
            } else if rows.isEmpty {
                ContentUnavailableView(query.isEmpty ? "No keys yet." : "No matching keys", systemImage: "key.horizontal", description: Text(query.isEmpty ? "Add a key in Terminal with envcloak add. Pasting in the app arrives in the next build." : "Try another search."))
            } else {
                Table(of: KeyRow.self, selection: $selection, sortOrder: $sortOrder, columnCustomization: $columns) {
                    TableColumn("Key", value: \.item.slug.escaped) { row in Text(row.item.slug.escaped).font(ECFont.martianMono(size: 12)) }.customizationID("key")
                    TableColumn("Title", value: \.item.title.escaped).customizationID("title")
                    TableColumn("Provider") { Text($0.item.provider?.escaped ?? "Unknown") }.customizationID("provider")
                    TableColumn("Account") { Text($0.item.account?.email?.escaped ?? "None") }.customizationID("account")
                    TableColumn("Class") { Text($0.item.classification.rawValue.capitalized) }.customizationID("class")
                    TableColumn("Used by", value: \.usedBy).customizationID("used-by")
                    TableColumn("Last used") { row in DateLabel(seconds: row.item.detail?.last_used_secs) }.customizationID("last-used")
                    TableColumn("Rotated") { row in DateLabel(seconds: row.item.rotated_secs) }.customizationID("rotated").defaultVisibility(.hidden)
                    TableColumn("Expires") { row in DateLabel(seconds: row.item.expires_secs) }.customizationID("expires").defaultVisibility(.hidden)
                    TableColumn("Fields") { row in Text("\(row.item.fields.count)") }.customizationID("fields").defaultVisibility(.hidden)
                } rows: {
                    if grouping == .none {
                        ForEach(rows.sorted(using: sortOrder)) { TableRow($0) }
                    } else {
                        ForEach(sections) { section in
                            Section(section.title) {
                                ForEach(section.rows.sorted(using: sortOrder)) { TableRow($0) }
                            }
                        }
                    }
                }
                .accessibilityIdentifier("keys.table")
                .onChange(of: selection) { _, value in selectedKey = rows.first(where: { $0.id == value })?.item.slug }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct DateLabel: View {
    let seconds: UInt64?
    var body: some View {
        if let seconds, seconds <= 253_402_300_799 { Text(Date(timeIntervalSince1970: Double(seconds)), style: .date) }
        else { Text("Not recorded") }
    }
}
