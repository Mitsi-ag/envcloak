import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct MainView: View {
    let session: VaultSession
    @State private var route: Route? = .projects
    @State private var selectedKey: DaemonText?
    @State private var inspector = false
    @State private var query = ""
    private var scope: DaemonText? { session.projects.scope }
    private var scopeBinding: Binding<DaemonText?> { Binding(get: { scope }, set: { session.setScope($0) }) }
    @State private var grouping = KeyGrouping.none
    @State private var columns = NavigationSplitViewVisibility.all
    @FocusState private var searchFocused: Bool
    init(session: VaultSession, initialRoute: Route = .projects) {
        self.session = session
        _route = State(initialValue: initialRoute)
    }
    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            List(selection: $route) {
                Section {
                    Label("Projects", systemImage: "folder").tag(Route.projects)
                    if session.state.canReadMetadata {
                        ForEach(session.projects.directories, id: \.self) { dir in
                            Text(session.projects.title(dir)).tag(Route.project(dir)).padding(.leading, 12)
                                .accessibilityIdentifier("sidebar.project." + dir.escaped)
                        }
                    }
                    Label("Keys", systemImage: "key.horizontal").tag(Route.keys(.all))
                    ForEach([KeyFilter.live, .test, .exposed], id: \.self) { filter in
                        VStack(alignment: .leading) {
                            Text(filter.rawValue)
                            if let message = Route.keys(filter).unavailableMessage {
                                Text(message).font(.caption).foregroundStyle(ECToken.secondary.color)
                            }
                        }.tag(Route.keys(filter)).padding(.leading, 12)
                    }
                    unavailableRow(.approvals, icon: "tray")
                    unavailableRow(.activity, icon: "clock.arrow.circlepath")
                    unavailableRow(.agents, icon: "terminal")
                    Label("Settings", systemImage: "gearshape").tag(Route.settings)
                }
                Section("Later") {
                    Label("Spend · M4", systemImage: "chart.bar").tag(Route.later(.spend))
                    Label("Devices · M5", systemImage: "laptopcomputer").tag(Route.later(.devices))
                    Label("Dashboard · M4", systemImage: "chart.xyaxis.line").tag(Route.later(.dashboard))
                }
            }.navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
        } detail: {
            VStack(spacing: 0) {
                if let notice = session.notice {
                    HStack { Text(notice); Spacer(); Button("Dismiss") { session.notice = nil } }.padding(12)
                        .background(ECToken.raised.color).accessibilityIdentifier("session.notice")
                }
                if session.state == .readOnly {
                    ReadOnlyBanner()
                    ContentUnavailableView("Metadata unavailable", systemImage: "exclamationmark.triangle", description: Text("This build cannot read keys or projects from a vault that failed its integrity check. Recover from a backup to continue."))
                } else if session.state.canReadMetadata {
                    if session.state == .upgradeReadOnly {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(session.state.title)
                            Text(session.state.detail)
                        }.padding(12).foregroundStyle(ECToken.warning.color)
                            .accessibilityIdentifier("upgrade-read-only.banner")
                    }
                    detail
                }
                else { ConnectionView(session: session) }
            }.frame(minWidth: 420).background(ECToken.background.color)
        }
        .navigationTitle(windowTitle)
        .navigationSubtitle(windowSubtitle)
        .inspector(isPresented: $inspector) {
            KeyInspector(session: session, slug: selectedKey, route: $route)
                .inspectorColumnWidth(min: 260, ideal: 300, max: 380)
        }
        .searchable(text: $query, placement: .toolbar, prompt: "Search keys; provider:, account:, class:, project:")
        .searchFocused($searchFocused)
        .toolbar {
            ToolbarItemGroup {
                Button { addFolder() } label: { Label("Add project folder…", systemImage: "folder.badge.plus") }
                    .help("Add project folder…").disabled(session.state != .ready)
            }
            ToolbarSpacer(.fixed)
            ToolbarItemGroup {
                Picker("Scope", selection: scopeBinding) {
                    Text("All projects").tag(Optional<DaemonText>.none)
                    ForEach(session.projects.scopeDirectories, id: \.self) { Text(session.projects.title($0)).tag(Optional($0)) }
                    if let scope, !session.projects.scopeDirectories.contains(scope) { Text(MetadataRequest.basename(scope)).tag(Optional(scope)) }
                }.accessibilityIdentifier("workspace.scope")
                Button { Task { await session.lock() } } label: { Label("Lock", systemImage: "lock") }
                    .help("Lock the vault").disabled(!session.state.canLock)
            }
            ToolbarSpacer(.fixed)
            ToolbarItem {
                Button { inspector.toggle() } label: { Label("Show inspector", systemImage: "sidebar.right") }.help("Show inspector")
            }
        }
        .frame(minWidth: 900, minHeight: 560)
        .onGeometryChange(for: Bool.self) { $0.size.width < 980 } action: { columns = $0 ? .detailOnly : .all }
        .onChange(of: selectedKey) { _, key in if key != nil { inspector = true } }
        .onChange(of: session.state) { _, state in if !state.canReadMetadata { selectedKey = nil } }
        .focusedSceneValue(\.workspaceNavigation, WorkspaceNavigation(
            navigate: { route = $0 }, search: { searchFocused = true },
            addFolder: { addFolder() }, lock: { Task { await session.lock() } },
            group: { grouping = $0 }, ready: session.state == .ready, canLock: session.state.canLock))
        .task { await session.run() }
    }

    private var windowTitle: String {
        if case .project(let directory) = route, let project = session.projects.opened, project.directory == directory {
            return project.title
        }
        return route?.title ?? "Projects"
    }
    private var windowSubtitle: String {
        guard session.state.canReadMetadata else { return "" }
        switch route ?? .projects {
        case .projects: return "\(session.projects.inventory.count) projects"
        case .project(let directory):
            guard let project = session.projects.opened, project.directory == directory else { return "Not checked" }
            return "\(project.check.bindings.count) bindings across profiles"
        case .keys: return scope.map(MetadataRequest.basename) ?? "All projects"
        default: return ""
        }
    }
    private func addFolder() {
        guard session.state == .ready else { return }
        WorkspaceActions.addFolder(session) { route = .project($0) }
    }

    @ViewBuilder private var detail: some View {
        if let message = route?.unavailableMessage {
            ContentUnavailableView(route?.title ?? "Unavailable", systemImage: "clock", description: Text(message))
                .accessibilityIdentifier("feature.unavailable")
        } else {
            switch route ?? .projects {
            case .projects: ProjectsOverview(session: session, route: $route)
            case .project(let dir): ProjectDetail(session: session, directory: dir, selectedKey: $selectedKey)
            case .keys(let filter): KeysView(session: session, filter: filter, query: query, scope: scope, grouping: $grouping, selectedKey: $selectedKey)
            case .key(let slug): KeyInspector(session: session, slug: slug, route: $route)
            case .settings:
                VStack(alignment: .leading, spacing: 16) {
                    DevelopmentBanner()
                    Text("Unlock in Terminal with envcloak unlock. Touch ID, Recovery Kit settings and agent integrations arrive in later builds.")
                    Text("Policies and the idle limit cannot be edited in this build.")
                    Spacer()
                }.padding()
            default: EmptyView()
            }
        }
    }
    private func unavailableRow(_ route: Route, icon: String) -> some View {
        VStack(alignment: .leading) {
            Label(route.title, systemImage: icon)
            Text(route.unavailableMessage ?? "").font(.caption).foregroundStyle(ECToken.secondary.color)
        }.tag(route).accessibilityElement(children: .contain)
            .accessibilityIdentifier("sidebar." + route.title)
    }
}

struct WorkspaceNavigation {
    let navigate: (Route) -> Void
    let search: () -> Void
    let addFolder: () -> Void
    let lock: () -> Void
    let group: (KeyGrouping) -> Void
    let ready: Bool
    let canLock: Bool
}
private struct WorkspaceNavigationKey: FocusedValueKey { typealias Value = WorkspaceNavigation }
extension FocusedValues {
    var workspaceNavigation: WorkspaceNavigation? {
        get { self[WorkspaceNavigationKey.self] }
        set { self[WorkspaceNavigationKey.self] = newValue }
    }
}
struct WorkspaceCommands: Commands {
    @FocusedValue(\.workspaceNavigation) private var navigation
    var body: some Commands {
        CommandMenu("Navigate") {
            Button("Projects") { navigation?.navigate(.projects) }.keyboardShortcut("1")
            Button("Keys") { navigation?.navigate(.keys(.all)) }.keyboardShortcut("2")
            Button("Approvals") { navigation?.navigate(.approvals) }.keyboardShortcut("3")
            Button("Activity") { navigation?.navigate(.activity) }.keyboardShortcut("4")
            Button("Agents") { navigation?.navigate(.agents) }.keyboardShortcut("5")
            Button("Settings") { navigation?.navigate(.settings) }.keyboardShortcut(",")
        }
        CommandGroup(after: .newItem) {
            Button("Add project folder…") { navigation?.addFolder() }.disabled(navigation?.ready != true)
            Button("Lock the vault") { navigation?.lock() }.keyboardShortcut("l", modifiers: [.command, .shift]).disabled(navigation?.canLock != true)
        }
        CommandGroup(after: .textEditing) {
            Button("Find") { navigation?.search() }.keyboardShortcut("f")
        }
        CommandGroup(after: .sidebar) {
            Menu("Group keys by") {
                ForEach(KeyGrouping.allCases, id: \.self) { group in Button(group.rawValue) { navigation?.group(group) } }
            }
        }
    }
}
