import EnvCloakKit

enum KeyFilter: String, CaseIterable, Hashable { case all = "All keys", live = "Live", test = "Test", exposed = "Exposed" }
enum LaterFeature: String, Hashable { case spend = "Spend", devices = "Devices", dashboard = "Dashboard" }
enum KeyGrouping: String, CaseIterable { case none = "None", project = "Project", provider = "Provider", account = "Account" }
enum Route: Hashable {
    case projects, project(DaemonText), keys(KeyFilter), key(DaemonText), approvals, activity, agents, settings, later(LaterFeature)
    var title: String {
        switch self {
        case .projects: "Projects"
        case .project(let dir): MetadataRequest.basename(dir)
        case .keys: "Keys"
        case .key(let slug): slug.escaped
        case .approvals: "Approvals"
        case .activity: "Activity"
        case .agents: "Agents"
        case .settings: "Settings"
        case .later(let feature): feature.rawValue
        }
    }
    var unavailableMessage: String? {
        switch self {
        case .approvals, .activity, .agents: "Arrives with Touch ID approvals"
        case .keys(.exposed): "Leak checks arrive with envcloak doctor"
        case .later(.spend), .later(.dashboard): "Spend arrives in M4"
        case .later(.devices): "Devices arrive in M5"
        default: nil
        }
    }
}

extension VaultSession {
    func usedBy(_ slug: DaemonText) -> [ProjectView] {
        projects.rows.filter { $0.bindings.contains { MetadataRequest.slug($0.reference) == slug } }
    }
    func filteredKeys(query: String, filter: KeyFilter, scope: DaemonText?) -> [ItemView] {
        let tokens = query.lowercased().split(whereSeparator: \.isWhitespace)
        return items.rows.filter { item in
            if filter == .live && item.classification != .live { return false }
            if filter == .test && item.classification != .test { return false }
            let users = usedBy(item.slug)
            if let scope, !users.contains(where: { $0.dir == scope }) { return false }
            let text = [item.slug.escaped, item.title.escaped, item.provider?.escaped ?? "", item.account?.email?.escaped ?? "", item.env_hint?.escaped ?? ""].joined(separator: " ").lowercased()
            return tokens.allSatisfy { token in
                let parts = token.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { return text.contains(token) }
                let value = String(parts[1])
                switch parts[0] {
                case "provider": return item.provider?.escaped.lowercased().contains(value) ?? false
                case "account": return item.account?.email?.escaped.lowercased().contains(value) ?? false
                case "class": return item.classification.rawValue == value
                case "project": return users.contains { $0.dir.escaped.lowercased().contains(value) }
                default: return text.contains(token)
                }
            }
        }
    }
}
