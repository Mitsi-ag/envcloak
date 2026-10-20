import AppKit
import EnvCloakDesign
import EnvCloakKit
import SwiftUI

enum MenuBarCatalog {
    static func isBlinkVisible(waitingCount: Int, reduceMotion: Bool, elapsed: TimeInterval) -> Bool {
        if waitingCount <= 0 || reduceMotion || elapsed < 0 {
            return true
        }
        let beat = Int((elapsed / ECMotion.caret).rounded(.down))
        return beat % 2 == 0
    }

    static func accessibilityDescription(state: ConnectionState, waitingCount: Int) -> String {
        if waitingCount > 0 {
            return "EnvCloak, \(waitingCount) \(waitingCount == 1 ? "request" : "requests") waiting"
        }
        return state == .ready ? "EnvCloak, unlocked" : "EnvCloak, locked"
    }

    static func searchItems(
        query: String,
        keys: [ItemView],
        projects: [DaemonText],
        projectTitles: [DaemonText: String]
    ) -> (shown: [PaletteItem], hasMore: Bool) {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        var matches: [PaletteItem] = []

        for key in keys {
            let slugText = key.slug.escaped
            let providerText = key.provider?.escaped ?? ""
            if trimmed.isEmpty ||
                slugText.localizedStandardContains(trimmed) ||
                providerText.localizedStandardContains(trimmed) ||
                key.title.escaped.localizedStandardContains(trimmed) {
                let ref = MetadataRequest.referenceString(slug: key.slug)
                let envLine = MetadataRequest.envLineString(item: key)
                matches.append(
                    PaletteItem(
                        id: "menubar.key.\(slugText)",
                        section: "Keys",
                        title: slugText,
                        subtitle: [key.provider?.escaped, key.classification.rawValue].compactMap { $0 }.joined(separator: " · "),
                        primaryEffect: .copyReference(ref),
                        secondaryEffect: .navigate(.key(key.slug)),
                        optionEffect: .copyReference(envLine)
                    )
                )
            }
        }

        for dir in projects {
            let title = projectTitles[dir] ?? MetadataRequest.basename(dir)
            if trimmed.isEmpty ||
                title.localizedStandardContains(trimmed) ||
                dir.escaped.localizedStandardContains(trimmed) {
                matches.append(
                    PaletteItem(
                        id: "menubar.project.\(dir.escaped)",
                        section: "Projects",
                        title: title,
                        subtitle: dir.escaped,
                        primaryEffect: .navigate(.project(dir))
                    )
                )
            }
        }

        let hasMore = matches.count > 6
        return (Array(matches.prefix(6)), hasMore)
    }

    static func allActionItems(
        keys: [ItemView],
        projects: [DaemonText],
        projectTitles: [DaemonText: String],
        grants: [GrantView],
        pendingCount: Int,
        exposedCount: Int
    ) -> [PaletteItem] {
        var result: [PaletteItem] = [
            PaletteItem(id: "menubar.state.lock", section: "State", title: "Lock", shortcut: "⇧⌘L", primaryEffect: .lock),
        ]
        if pendingCount > 0 {
            result.append(
                PaletteItem(
                    id: "menubar.waiting.review",
                    section: "Waiting",
                    title: "Review requests",
                    primaryEffect: .openSheet(.reviewRequests)
                )
            )
        }
        let search = searchItems(query: "", keys: keys, projects: projects, projectTitles: projectTitles)
        result.append(contentsOf: search.shown)
        if search.hasMore {
            result.append(
                PaletteItem(
                    id: "menubar.search.more",
                    section: "Search",
                    title: "Show all in EnvCloak",
                    primaryEffect: .navigate(.keys(.all))
                )
            )
        }
        for grant in grants {
            let who = grant.label?.escaped ?? grant.kind.rawValue.capitalized
            result.append(
                PaletteItem(
                    id: "menubar.grant.\(grant.id.escaped)",
                    section: "In force",
                    title: "Revoke \(who)",
                    primaryEffect: .revoke(grant.id)
                )
            )
        }
        if exposedCount > 0 {
            result.append(
                PaletteItem(
                    id: "menubar.alert.exposed",
                    section: "Alerts",
                    title: "\(exposedCount) exposed \(exposedCount == 1 ? "key" : "keys")",
                    primaryEffect: .navigate(.keys(.exposed))
                )
            )
        }
        result.append(contentsOf: [
            PaletteItem(id: "menubar.footer.addKey", section: "Footer", title: "Add key", primaryEffect: .openSheet(.addKey)),
            PaletteItem(id: "menubar.footer.open", section: "Footer", title: "Open EnvCloak", primaryEffect: .navigate(.projects)),
            PaletteItem(id: "menubar.footer.settings", section: "Footer", title: "Settings…", primaryEffect: .navigate(.settings)),
        ])
        return result
    }
}

struct MenuBarLabelView: View {
    let session: VaultSession
    @State private var startedAt = Date()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var waitingCount: Int {
        Int(session.pendingCount) + Int(session.appRequestsCount)
    }

    var body: some View {
        TimelineView(.animation(paused: reduceMotion || waitingCount == 0)) { context in
            let visible = MenuBarCatalog.isBlinkVisible(
                waitingCount: waitingCount,
                reduceMotion: reduceMotion,
                elapsed: context.date.timeIntervalSince(startedAt)
            )
            HStack(spacing: 4) {
                Image(systemName: session.state == .ready ? "key.horizontal.fill" : "lock.fill")
                    .opacity(visible ? 1.0 : 0.35)
                if waitingCount > 0 {
                    Text("\(waitingCount)")
                        .font(.caption.monospacedDigit())
                }
            }
        }
        .accessibilityLabel(MenuBarCatalog.accessibilityDescription(state: session.state, waitingCount: waitingCount))
        .accessibilityIdentifier("menubar.label")
    }
}

struct MenuBarPopover: View {
    let session: VaultSession
    var clipboardWriter: ClipboardWriter = ClipboardWriter()
    var onNavigateMain: (Route) -> Void = { _ in }

    @State private var query = ""
    @State private var highlightedId: String?
    @FocusState private var searchFocused: Bool
    @Environment(\.openWindow) private var openWindow

    private var projectTitles: [DaemonText: String] {
        var map: [DaemonText: String] = [:]
        for dir in session.projects.directories {
            map[dir] = session.projects.title(dir)
        }
        return map
    }

    private var searchResult: (shown: [PaletteItem], hasMore: Bool) {
        MenuBarCatalog.searchItems(
            query: query,
            keys: session.items.rows,
            projects: session.projects.directories,
            projectTitles: projectTitles
        )
    }

    private var activeGrants: [GrantView] {
        session.grants.rows.filter { session.grants.remaining($0) > 0 }
    }

    private var exposedCount: Int {
        session.items.rows.filter { $0.exposed != nil }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            stateRow

            if !session.grants.pending.isEmpty || !session.grants.asks.isEmpty {
                Divider()
                waitingSection
            }

            if session.state.canReadMetadata {
                Divider()
                searchSection

                if !activeGrants.isEmpty {
                    Divider()
                    inForceSection
                }

                if session.state == .readOnly || exposedCount > 0 {
                    Divider()
                    alertsSection
                }
            }

            Divider()
            footerRow
        }
        .padding(12)
        .frame(width: 360)
        .background(ECToken.background.color)
        .onAppear {
            searchFocused = true
            highlightedId = searchResult.shown.first?.id
        }
        .onChange(of: query) { _, _ in
            highlightedId = searchResult.shown.first?.id
        }
    }

    private var stateRow: some View {
        HStack(spacing: 8) {
            Image(systemName: session.state == .ready ? "lock.open" : "lock")
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityHidden(true)
            Text(session.state == .ready ? "Unlocked" : "Locked")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("menubar.state")
            Spacer()
            if session.state.canLock {
                Button("Lock") {
                    Task { await session.lock() }
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .accessibilityIdentifier("menubar.lock")
            } else if session.enrolledTouchID {
                Button(session.unlockButtonTitle) {
                    Task { _ = await session.unlockWithTouchID() }
                }
                .disabled(session.actionInProgress)
                .accessibilityIdentifier("menubar.unlock")
            }
        }
    }

    private var waitingSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Waiting")
                .font(.caption.weight(.semibold))
                .foregroundStyle(ECToken.secondary.color)
            ForEach(session.grants.pending, id: \.request) { item in
                let caller = NotificationManager.pendingCallerLabel(item)
                let project = MetadataRequest.basename(item.project)
                Button {
                    session.openApprovalWindow(for: item.request)
                    openWindow(id: WindowID.approval)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(caller) wants to run")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(ECToken.text.color)
                        Text(ApprovalsView.waitingSubtitle(project: project, item: item))
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("menubar.waiting." + item.request.escaped)
            }
            ForEach(session.grants.asks, id: \.ask) { ask in
                let caller = ask.requester.label?.escaped ?? ask.requester.kind.rawValue.capitalized
                let provider = ask.provider?.escaped ?? "a service"

                Button {
                    session.activeAsk = ask
                    openWindow(id: WindowID.paste)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(caller) asks you to add a key")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(ECToken.text.color)
                        Text(provider)
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("menubar.ask." + ask.ask.escaped)
            }
        }
    }

    private var searchSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Search keys and projects", text: $query)
                .textFieldStyle(.roundedBorder)
                .focused($searchFocused)
                .onSubmit {
                    if let first = searchResult.shown.first {
                        runEffect(first.primaryEffect)
                    }
                }
                .accessibilityIdentifier("menubar.search")

            ForEach(searchResult.shown) { item in
                HStack {
                    Button {
                        runEffect(item.primaryEffect)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title)
                                .font(ECFont.martianMono(size: 12))
                                .foregroundStyle(ECToken.text.color)
                            if let sub = item.subtitle, !sub.isEmpty {
                                Text(sub)
                                    .font(.caption)
                                    .foregroundStyle(ECToken.secondary.color)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier(item.id)
                }
            }

            if searchResult.hasMore {
                Button("Show all in EnvCloak") {
                    runEffect(.navigate(.keys(.all)))
                }
                .font(.caption)
                .accessibilityIdentifier("menubar.search.more")
            }
        }
        .onKeyPress(keys: [.return], phases: .down) { press in
            guard let first = searchResult.shown.first(where: { $0.id == highlightedId }) ?? searchResult.shown.first else {
                return .ignored
            }
            if press.modifiers.contains(.command), let secondary = first.secondaryEffect {
                runEffect(secondary)
            } else if press.modifiers.contains(.option), let opt = first.optionEffect {
                runEffect(opt)
            } else {
                runEffect(first.primaryEffect)
            }
            return .handled
        }
    }

    private var inForceSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("In force")
                .font(.caption.weight(.semibold))
                .foregroundStyle(ECToken.secondary.color)
            ForEach(activeGrants, id: \.id) { grant in
                let who = grant.label?.escaped ?? grant.kind.rawValue.capitalized
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(who)
                            .font(.subheadline)
                            .foregroundStyle(ECToken.text.color)
                        Text("\(session.grants.remaining(grant)) s left")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(ECToken.secondary.color)
                    }
                    Spacer()
                    Button("Revoke") {
                        runEffect(.revoke(grant.id))
                    }
                    .disabled(session.actionInProgress || session.state != .ready)
                    .accessibilityIdentifier("menubar.revoke." + grant.id.escaped)
                }
            }
        }
    }

    private var alertsSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Alerts")
                .font(.caption.weight(.semibold))
                .foregroundStyle(ECToken.secondary.color)
            if session.state == .readOnly {
                Button("Vault is read-only") {
                    runEffect(.navigate(.projects))
                }
                .foregroundStyle(ECToken.warning.color)
                .buttonStyle(.plain)
            }
            if exposedCount > 0 {
                Button("\(exposedCount) exposed \(exposedCount == 1 ? "key" : "keys")") {
                    runEffect(.navigate(.keys(.exposed)))
                }
                .foregroundStyle(ECToken.warning.color)
                .buttonStyle(.plain)
                .accessibilityIdentifier("menubar.alert.exposed")
            }
        }
    }

    private var footerRow: some View {
        HStack {
            Button("Add key") {
                runEffect(.openSheet(.addKey))
            }
            .disabled(session.state != .ready)
            .accessibilityIdentifier("menubar.addKey")

            Button("Open EnvCloak") {
                runEffect(.navigate(.projects))
            }
            .accessibilityIdentifier("menubar.open")

            Spacer()

            Menu {
                Button("Settings…") {
                    runEffect(.navigate(.settings))
                }
                Button("About EnvCloak") {
                    openWindow(id: WindowID.about)
                }
                Divider()
                Button("Quit EnvCloak") {
                    NSApplication.shared.terminate(nil)
                }
            } label: {
                if let gearImage = NSImage(systemSymbolName: "gearshape", accessibilityDescription: "EnvCloak menu") {
                    Image(nsImage: gearImage)
                } else {
                    Image(systemName: "gearshape")
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("EnvCloak menu")
            .accessibilityLabel("EnvCloak menu")
            .accessibilityIdentifier("menubar.gear")
        }
    }

    func runEffect(_ effect: PaletteEffect) {
        switch effect {
        case .copyReference(let reference):
            clipboardWriter.copyReference(reference)
        case .navigate(let route):
            openWindow(id: WindowID.main)
            onNavigateMain(route)
            NSApplication.shared.activate()
        case .openSheet(let sheet):
            switch sheet {
            case .addKey:
                session.activeAsk = nil
                openWindow(id: WindowID.paste)
                NSApplication.shared.activate()
            case .reviewRequests:
                session.openApprovalWindow()
                openWindow(id: WindowID.approval)
                NSApplication.shared.activate()
            case .welcome:
                openWindow(id: WindowID.welcome)
                NSApplication.shared.activate()
            case .addBinding, .inspectKey, .swapKey, .deleteKey:
                openWindow(id: WindowID.main)
                NSApplication.shared.activate()
            }
        case .lock:
            Task { await session.lock() }
        case .revoke(let id):
            Task { await session.revoke(id) }
        }
    }
}
