import EnvCloakKit

struct KeyRowID: Hashable { let item: DaemonText; let group: String }
struct KeyRow: Identifiable {
    let item: ItemView
    let group: String
    let usedBy: String
    var id: KeyRowID { KeyRowID(item: item.id, group: group) }
}
struct KeySection: Identifiable {
    let title: String
    let rows: [KeyRow]
    var id: String { title }
}

extension VaultSession {
    func keySections(query: String, filter: KeyFilter, scope: DaemonText?, grouping: KeyGrouping) -> [KeySection] {
        var groups: [String: [KeyRow]] = [:]
        for item in filteredKeys(query: query, filter: filter, scope: scope) {
            let users = usedBy(item.slug).map { $0.dir.escaped }
            let names: [String] = switch grouping {
            case .none: [""]
            case .project: projects.failure != nil ? ["Project metadata unavailable"] : (users.isEmpty ? ["No adopted project"] : users)
            case .provider: [item.provider?.escaped ?? "No provider"]
            case .account: [item.account?.email?.escaped ?? "No account"]
            }
            for name in names {
                groups[name, default: []].append(KeyRow(item: item, group: name, usedBy: projects.failure == nil ? users.joined(separator: ", ") : "Projects could not be refreshed"))
            }
        }
        return groups.keys.sorted().map { KeySection(title: $0, rows: groups[$0] ?? []) }
    }
}

