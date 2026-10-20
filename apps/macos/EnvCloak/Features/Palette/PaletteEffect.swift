import EnvCloakKit
import Foundation

enum PaletteSheet: String, Equatable, Sendable, CaseIterable {
    case addKey
    case addBinding
    case inspectKey
    case swapKey
    case deleteKey
    case reviewRequests
    case welcome
}

enum PaletteEffect: Equatable, Sendable {
    case navigate(Route)
    case openSheet(PaletteSheet)
    case copyReference(String)
    case lock
    case revoke(DaemonText)

    var isDirectPrivilegeAction: Bool {
        false
    }
}

struct PaletteItem: Identifiable, Equatable, Sendable {
    let id: String
    let section: String
    let title: String
    let subtitle: String?
    let shortcut: String?
    let primaryEffect: PaletteEffect
    let secondaryEffect: PaletteEffect?
    let optionEffect: PaletteEffect?

    init(
        id: String,
        section: String,
        title: String,
        subtitle: String? = nil,
        shortcut: String? = nil,
        primaryEffect: PaletteEffect,
        secondaryEffect: PaletteEffect? = nil,
        optionEffect: PaletteEffect? = nil
    ) {
        self.id = id
        self.section = section
        self.title = title
        self.subtitle = subtitle
        self.shortcut = shortcut
        self.primaryEffect = primaryEffect
        self.secondaryEffect = secondaryEffect
        self.optionEffect = optionEffect
    }

    var isDirectPrivilegeAction: Bool {
        let lower = title.lowercased()
        if lower == "approve" || lower == "unlock" || lower == "copy secret" || lower == "copy value" {
            return true
        }
        return primaryEffect.isDirectPrivilegeAction ||
            (secondaryEffect?.isDirectPrivilegeAction == true) ||
            (optionEffect?.isDirectPrivilegeAction == true)
    }
}

enum PaletteBuilder {
    enum PrefixScope: Equatable {
        case all
        case projects(String)
        case keys(String)
        case agentsAndGrants(String)
        case commands(String)
    }

    static func parseQuery(_ raw: String) -> PrefixScope {
        if raw.hasPrefix("p ") {
            return .projects(String(raw.dropFirst(2)).trimmingCharacters(in: .whitespaces))
        }
        if raw.hasPrefix("k ") {
            return .keys(String(raw.dropFirst(2)).trimmingCharacters(in: .whitespaces))
        }
        if raw.hasPrefix("a ") {
            return .agentsAndGrants(String(raw.dropFirst(2)).trimmingCharacters(in: .whitespaces))
        }
        if raw.hasPrefix(">") {
            return .commands(String(raw.dropFirst(1)).trimmingCharacters(in: .whitespaces))
        }
        return .all
    }

    static func items(
        query: String,
        selectedKey: ItemView?,
        projects: [DaemonText],
        projectTitles: [DaemonText: String],
        keys: [ItemView],
        grants: [GrantView],
        pendingCount: Int
    ) -> [PaletteItem] {
        let scope = parseQuery(query)
        let filterText: String
        switch scope {
        case .all:
            filterText = query.trimmingCharacters(in: .whitespaces)
        case .projects(let sub), .keys(let sub), .agentsAndGrants(let sub), .commands(let sub):
            filterText = sub
        }

        var all: [PaletteItem] = []

        if case .all = scope, let key = selectedKey {
            let section = "Actions for \(key.slug.escaped)"
            let ref = MetadataRequest.referenceString(slug: key.slug)
            let envLine = MetadataRequest.envLineString(item: key)
            all.append(contentsOf: [
                PaletteItem(
                    id: "sel.copyRef.\(key.slug.escaped)",
                    section: section,
                    title: "Copy reference",
                    subtitle: ref,
                    shortcut: "⌘C",
                    primaryEffect: .copyReference(ref)
                ),
                PaletteItem(
                    id: "sel.copyEnv.\(key.slug.escaped)",
                    section: section,
                    title: "Copy env line",
                    subtitle: envLine,
                    shortcut: "⌥⌘C",
                    primaryEffect: .copyReference(envLine)
                ),
                PaletteItem(
                    id: "sel.sight.\(key.slug.escaped)",
                    section: section,
                    title: "Reveal…",
                    subtitle: key.slug.escaped,
                    primaryEffect: .openSheet(.inspectKey)
                ),
                PaletteItem(
                    id: "sel.swap.\(key.slug.escaped)",
                    section: section,
                    title: "Replace…",
                    subtitle: key.slug.escaped,
                    primaryEffect: .openSheet(.swapKey)
                ),
                PaletteItem(
                    id: "sel.delete.\(key.slug.escaped)",
                    section: section,
                    title: "Remove key…",
                    subtitle: key.slug.escaped,
                    primaryEffect: .openSheet(.deleteKey)
                ),
            ])
        }

        if scope == .all || isCommandsScope(scope) {
            var commands: [PaletteItem] = [
                PaletteItem(
                    id: "cmd.addKey",
                    section: "Commands",
                    title: "Add key",
                    shortcut: "⌘N",
                    primaryEffect: .openSheet(.addKey)
                ),
                PaletteItem(
                    id: "cmd.addBinding",
                    section: "Commands",
                    title: "Add variable",
                    primaryEffect: .openSheet(.addBinding)
                ),
                PaletteItem(
                    id: "cmd.review",
                    section: "Commands",
                    title: pendingCount > 0 ? "Review requests (\(pendingCount))" : "Review requests",
                    primaryEffect: .openSheet(.reviewRequests)
                ),
                PaletteItem(
                    id: "cmd.lock",
                    section: "Commands",
                    title: "Lock",
                    shortcut: "⇧⌘L",
                    primaryEffect: .lock
                ),
                PaletteItem(
                    id: "cmd.welcome",
                    section: "Commands",
                    title: "Show welcome",
                    primaryEffect: .openSheet(.welcome)
                ),
            ]
            if case .commands = scope {
                commands.append(contentsOf: goToItems())
            }
            all.append(contentsOf: commands)
        }

        if case .all = scope {
            all.append(contentsOf: goToItems())
        }

        if scope == .all || isProjectsScope(scope) {
            for dir in projects {
                let title = projectTitles[dir] ?? MetadataRequest.basename(dir)
                all.append(
                    PaletteItem(
                        id: "proj.\(dir.escaped)",
                        section: "Projects",
                        title: title,
                        subtitle: dir.escaped,
                        primaryEffect: .navigate(.project(dir))
                    )
                )
            }
        }

        if scope == .all || isKeysScope(scope) {
            for key in keys {
                let ref = MetadataRequest.referenceString(slug: key.slug)
                let envLine = MetadataRequest.envLineString(item: key)
                all.append(
                    PaletteItem(
                        id: "key.\(key.slug.escaped)",
                        section: "Keys",
                        title: key.slug.escaped,
                        subtitle: [key.provider?.escaped, key.classification.rawValue].compactMap { $0 }.joined(separator: " · "),
                        primaryEffect: .copyReference(ref),
                        secondaryEffect: .navigate(.key(key.slug)),
                        optionEffect: .copyReference(envLine)
                    )
                )
            }
        }

        if scope == .all || isAgentsScope(scope) {
            if isAgentsScope(scope) {
                all.append(
                    PaletteItem(
                        id: "goto.agents.scoped",
                        section: "Agents",
                        title: "Agents",
                        shortcut: "⌘5",
                        primaryEffect: .navigate(.agents)
                    )
                )
            }
            for grant in grants {
                let who = grant.label?.escaped ?? grant.kind.rawValue.capitalized
                all.append(
                    PaletteItem(
                        id: "grant.\(grant.id.escaped)",
                        section: "In force",
                        title: "Revoke \(who)",
                        subtitle: grant.project_dir.escaped,
                        primaryEffect: .revoke(grant.id)
                    )
                )
            }
        }

        guard !filterText.isEmpty else { return all }
        return all.filter { item in
            item.title.localizedStandardContains(filterText) ||
                (item.subtitle?.localizedStandardContains(filterText) ?? false) ||
                item.section.localizedStandardContains(filterText)
        }
    }

    private static func goToItems() -> [PaletteItem] {
        [
            PaletteItem(id: "goto.projects", section: "Go to", title: "Projects", shortcut: "⌘1", primaryEffect: .navigate(.projects)),
            PaletteItem(id: "goto.keys", section: "Go to", title: "Keys", shortcut: "⌘2", primaryEffect: .navigate(.keys(.all))),
            PaletteItem(id: "goto.approvals", section: "Go to", title: "Approvals", shortcut: "⌘3", primaryEffect: .navigate(.approvals)),
            PaletteItem(id: "goto.activity", section: "Go to", title: "Activity", shortcut: "⌘4", primaryEffect: .navigate(.activity)),
            PaletteItem(id: "goto.agents", section: "Go to", title: "Agents", shortcut: "⌘5", primaryEffect: .navigate(.agents)),
            PaletteItem(id: "goto.settings", section: "Go to", title: "Settings", shortcut: "⌘,", primaryEffect: .navigate(.settings)),
        ]
    }

    private static func isProjectsScope(_ scope: PrefixScope) -> Bool {
        if case .projects = scope { return true }
        return false
    }

    private static func isKeysScope(_ scope: PrefixScope) -> Bool {
        if case .keys = scope { return true }
        return false
    }

    private static func isAgentsScope(_ scope: PrefixScope) -> Bool {
        if case .agentsAndGrants = scope { return true }
        return false
    }

    private static func isCommandsScope(_ scope: PrefixScope) -> Bool {
        if case .commands = scope { return true }
        return false
    }
}
