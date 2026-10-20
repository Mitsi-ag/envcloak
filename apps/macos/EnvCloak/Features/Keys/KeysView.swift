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
                ContentUnavailableView(
                    query.isEmpty ? (filter == .exposed ? "No exposed keys." : "No keys yet.") : "No matching keys",
                    systemImage: "key.horizontal",
                    description: Text(query.isEmpty ? (filter == .exposed ? "Keys flagged by envcloak doctor appear here." : "Add a key with Add key or Command-N.") : "Try another search.")
                )
            } else {
                Table(of: KeyRow.self, selection: $selection, sortOrder: $sortOrder, columnCustomization: $columns) {
                    TableColumn("Key", value: \.item.slug.escaped) { row in Text(row.item.slug.escaped).font(ECFont.martianMono(size: 12)) }.customizationID("key")
                    TableColumn("Title", value: \.item.title.escaped).customizationID("title")
                    TableColumn("Provider") { Text($0.item.provider?.escaped ?? "Unknown") }.customizationID("provider")
                    TableColumn("Account") { Text($0.item.account?.email?.escaped ?? "None") }.customizationID("account")
                    TableColumn("Class") { row in
                        HStack(spacing: 6) {
                            Label(
                                row.item.classification.rawValue.capitalized,
                                systemImage: Self.classBadgeSymbol(row.item.classification)
                            )
                            .font(row.item.classification == .live ? .body.weight(.semibold) : .body)
                            .foregroundStyle(Self.classBadgeToken(row.item.classification).color)
                            .accessibilityLabel(Self.classBadgeAccessibilityLabel(row.item.classification))
                            .accessibilityIdentifier("keys.class." + row.item.slug.escaped)
                            if row.item.exposed != nil {
                                Label("Exposed", systemImage: "exclamationmark.triangle")
                                    .foregroundStyle(ECToken.warning.color)
                                    .accessibilityLabel("Exposed")
                            }
                        }
                    }.customizationID("class")
                    TableColumn("Used by", value: \.usedBy).customizationID("used-by")
                    TableColumn("Last used") { row in DateLabel(seconds: row.item.last_used_secs) }.customizationID("last-used")
                    TableColumn("Rotated") { row in DateLabel(seconds: row.item.rotated_secs) }.customizationID("rotated").defaultVisibility(.hidden)
                    TableColumn("Expires") { row in DateLabel(seconds: row.item.expires_secs) }.customizationID("expires").defaultVisibility(.hidden)
                    TableColumn("Fields") { row in Text("\(row.item.fields.count)") }.customizationID("fields").defaultVisibility(.hidden)
                } rows: {
                    if grouping == .none {
                        ForEach(rows.sorted(using: sortOrder)) { row in TableRow(row).draggable(row.item.slug.escaped) }
                    } else {
                        ForEach(sections) { section in
                            Section(section.title) {
                                ForEach(section.rows.sorted(using: sortOrder)) { row in TableRow(row).draggable(row.item.slug.escaped) }
                            }
                        }
                    }
                }
                .accessibilityIdentifier("keys.table")
                .onChange(of: selection) { _, value in selectedKey = rows.first(where: { $0.id == value })?.item.slug }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    static func classBadgeSymbol(_ classification: ClassificationView) -> String {
        switch classification {
        case .live: "bolt.fill"
        case .test: "testtube.2"
        case .unknown: "questionmark.circle"
        }
    }

    static func classBadgeToken(_ classification: ClassificationView) -> ECToken {
        switch classification {
        case .live: .text
        case .test, .unknown: .secondary
        }
    }

    static func classBadgeAccessibilityLabel(_ classification: ClassificationView) -> String {
        switch classification {
        case .live: "Live key"
        case .test: "Test key"
        case .unknown: "Unknown kind"
        }
    }
}

struct DateLabel: View {
    let seconds: UInt64?
    var body: some View {
        if let seconds, seconds <= 253_402_300_799 { Text(Date(timeIntervalSince1970: Double(seconds)), style: .date) }
        else { Text("Not recorded") }
    }
}
