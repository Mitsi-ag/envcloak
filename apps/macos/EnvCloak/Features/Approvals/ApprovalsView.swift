import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct ApprovalsView: View {
    let session: VaultSession
    let scope: DaemonText?
    @State private var selectedPendingId: DaemonText?
    @State private var confirmRevokeAll = false
    @Environment(\.openWindow) private var openWindow

    var filteredPending: [AppPendingView] {
        guard let scope else { return session.grants.pending }
        let canonical = session.projects.canonicalDirectory(scope)
        return session.grants.pending.filter { $0.project == canonical || $0.project == scope }
    }

    var filteredAsks: [AskSummary] {
        guard let scope else { return session.grants.asks }
        let canonical = session.projects.canonicalDirectory(scope)
        return session.grants.asks.filter { $0.project_dir == nil || $0.project_dir == canonical || $0.project_dir == scope }
    }

    var filteredGrants: [GrantView] {
        let canonical = scope.map { session.projects.canonicalDirectory($0) }
        return session.grants.rows.filter { grant in
            (canonical == nil || grant.project_dir == canonical || grant.project_dir == scope) &&
                session.grants.remaining(grant) > 0
        }
    }

    var filteredStanding: [StandingView] {
        let canonical = scope.map { session.projects.canonicalDirectory($0) }
        return session.grants.standing.filter { row in
            canonical == nil || row.project_dir == canonical || row.project_dir == scope
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Waiting")
                        .font(.headline)
                        .foregroundStyle(ECToken.text.color)
                    if session.grants.pendingFailure != nil {
                        Text("Waiting requests could not be refreshed. Try again.")
                            .foregroundStyle(ECToken.danger.color)
                            .accessibilityIdentifier("approvals.pending.error")
                    } else if filteredPending.isEmpty && filteredAsks.isEmpty {
                        Text("Nothing waiting. Requests from Claude Code, Codex and other agents appear here.")
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("approvals.waiting.empty")
                    } else {
                        ForEach(filteredPending, id: \.request) { item in
                            waitingRow(item)
                        }
                        ForEach(filteredAsks, id: \.ask) { ask in
                            askRow(ask)
                        }
                    }
                }


                VStack(alignment: .leading, spacing: 8) {
                    Text("In force")
                        .font(.headline)
                        .foregroundStyle(ECToken.text.color)
                    if session.grants.failure != nil {
                        Text("Grants could not be refreshed. Try again.")
                            .foregroundStyle(ECToken.danger.color)
                    } else if filteredGrants.isEmpty && filteredStanding.isEmpty {
                        Text("No grants in force")
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("approvals.grants.empty")
                    } else {
                        ForEach(filteredGrants, id: \.id) { grant in
                            grantRow(grant)
                        }
                        if filteredGrants.count > 1 {
                            HStack {
                                Spacer()
                                Button("Revoke all") {
                                    confirmRevokeAll = true
                                }
                                .disabled(session.actionInProgress || session.state != .ready)
                                .accessibilityIdentifier("approvals.revokeAll")
                            }
                        }
                        ForEach(filteredStanding, id: \.id) { row in
                            standingRow(row)
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(ECToken.background.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approvals.list")
        .onKeyPress(characters: CharacterSet(charactersIn: "jkJK")) { press in
            let lower = press.characters.lowercased()
            if lower == "j" {
                moveSelection(delta: 1)
                return .handled
            } else if lower == "k" {
                moveSelection(delta: -1)
                return .handled
            }
            return .ignored
        }
        .onKeyPress(.return) {
            if let id = selectedPendingId ?? filteredPending.first?.request {
                openReview(for: id)
                return .handled
            }
            return .ignored
        }
        .overlay(alignment: .bottomTrailing) {
            Button("Deny selected request") {
                denySelected()
            }
            .keyboardShortcut(.delete, modifiers: .command)
            .opacity(0)
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
        }
        .confirmationDialog(
            "Revoke all \(filteredGrants.count) grants? Agents ask again on their next run.",
            isPresented: $confirmRevokeAll
        ) {
            Button("Revoke all", role: .destructive) {
                Task { await session.revokeAllGrants() }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func waitingRow(_ item: AppPendingView) -> some View {
        let agentName = NotificationManager.pendingCallerLabel(item)
        let projectName = MetadataRequest.basename(item.project)
        let remaining = session.grants.remainingPending(item)
        let bindingList = item.bindings.map(\.escaped).joined(separator: ", ")
        return HStack(spacing: 12) {
            Image(systemName: Self.subjectSymbol(item.kind))
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text("\(agentName) wants to run")
                        .font(.headline)
                        .foregroundStyle(ECToken.text.color)
                    if !bindingList.isEmpty {
                        Text(bindingList)
                            .font(ECFont.martianMono(size: 12))
                            .foregroundStyle(ECToken.text.color)
                    }
                }
                Text(Self.waitingSubtitle(project: projectName, item: item))
                    .font(.subheadline)
                    .foregroundStyle(ECToken.secondary.color)
            }
            Spacer()
            Text(Self.remainingWords(remaining))
                .font(.caption.monospacedDigit())
                .foregroundStyle(ECToken.secondary.color)
            Button("Review") {
                openReview(for: item.request)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("approvals.review." + item.request.escaped)
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approvals.waiting." + item.request.escaped)
    }

    private func askRow(_ ask: AskSummary) -> some View {
        let caller = ask.requester.label?.escaped ?? ask.requester.kind.rawValue.capitalized
        let providerText = ask.provider?.escaped ?? "a service"
        let projectText = ask.project_dir.map { MetadataRequest.basename($0) } ?? "No project"
        let remaining = session.grants.remainingAsk(ask)
        return HStack(spacing: 12) {
            Image(systemName: Self.subjectSymbol(ask.requester.kind))
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text("\(caller) asks you to add a key for \(providerText)")
                    .font(.headline)
                    .foregroundStyle(ECToken.text.color)
                Text(projectText)
                    .font(.subheadline)
                    .foregroundStyle(ECToken.secondary.color)
            }
            Spacer()
            Text(Self.remainingWords(remaining))
                .font(.caption.monospacedDigit())
                .foregroundStyle(ECToken.secondary.color)
            Button("Add key…") {
                session.activeAsk = ask
                openWindow(id: WindowID.paste)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("approvals.ask.add." + ask.ask.escaped)
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approvals.ask." + ask.ask.escaped)
    }


    private func grantRow(_ grant: GrantView) -> some View {
        let who = grant.label?.escaped ?? grant.kind.rawValue.capitalized
        let slugs = Self.slugSummary(grant.bindings.map(\.slug.escaped))
        let timeText = grant.uses == .once ? "Once" : "\(session.grants.remaining(grant)) seconds left"
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(who)
                    .font(.headline)
                    .foregroundStyle(ECToken.text.color)
                Text("\(grant.project_dir.escaped) · \(slugs) · \(grant.mode.rawValue.capitalized)")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                Text(timeText)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(ECToken.secondary.color)
            }
            Spacer()
            Button("Revoke") {
                Task { await session.revoke(grant.id) }
            }
            .disabled(session.actionInProgress || session.state != .ready)
            .accessibilityIdentifier("approvals.revoke." + grant.id.escaped)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approvals.grant." + grant.id.escaped)
    }

    private func standingRow(_ row: StandingView) -> some View {
        let slugs = Self.slugSummary(row.bindings.map(\.escaped))
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("\(row.agent_name.escaped) · \(MetadataRequest.basename(row.project_dir))")
                    .font(.headline)
                    .foregroundStyle(ECToken.text.color)
                Text("\(row.project_dir.escaped) · \(slugs)")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                Text(row.scopeLabel)
                    .font(.caption)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("approvals.standing.label." + row.id.escaped)
            }
            Spacer()
            Button("Revoke") {
                Task { await session.revokeStanding(row.id) }
            }
            .disabled(session.actionInProgress || session.state != .ready)
            .accessibilityIdentifier("approvals.standing.revoke." + row.id.escaped)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approvals.standing." + row.id.escaped)
    }

    private func moveSelection(delta: Int) {
        let ids = filteredPending.map(\.request)
        guard !ids.isEmpty else { return }
        guard let current = selectedPendingId, let index = ids.firstIndex(of: current) else {
            selectedPendingId = ids.first
            return
        }
        let next = max(0, min(ids.count - 1, index + delta))
        selectedPendingId = ids[next]
    }

    private func openReview(for id: DaemonText) {
        session.openApprovalWindow(for: id)
        openWindow(id: WindowID.approval)
    }

    private func denySelected() {
        guard let id = selectedPendingId ?? filteredPending.first?.request else { return }
        Task { _ = await session.denyPending(id) }
    }

    static func subjectSymbol(_ kind: SubjectKind) -> String {
        switch kind {
        case .agent: "terminal"
        case .terminal: "person"
        case .unknown: "questionmark.circle"
        }
    }

    static func commandPreview(_ argv: [DaemonText]) -> String {
        let joined = argv.map(\.escaped).joined(separator: " ")
        if joined.count <= 60 { return joined }
        return String(joined.prefix(60)) + "…"
    }

    static func waitingSubtitle(project: String, item: AppPendingView) -> String {
        let total = UInt64(item.bindings.count) + item.more_bindings
        return "\(project), \(total) \(total == 1 ? "key" : "keys")"
    }

    static func remainingWords(_ seconds: UInt64) -> String {
        if seconds >= 60 {
            return "\(seconds / 60) min left"
        }
        return "\(seconds) s left"
    }

    static func slugSummary(_ slugs: [String]) -> String {
        guard slugs.count > 3 else { return slugs.joined(separator: ", ") }
        return slugs.prefix(3).joined(separator: ", ") + " +\(slugs.count - 3)"
    }
}
