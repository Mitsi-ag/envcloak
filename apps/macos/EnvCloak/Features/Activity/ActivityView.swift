import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct ActivityEventPresentation: Equatable, Sendable {
    let title: String
    let symbol: String

    static func from(kind: DaemonText, outcome: DaemonText) -> ActivityEventPresentation {
        let k = kind.escaped.lowercased()
        let o = outcome.escaped.lowercased()
        if o == "denied" || k == "deny" || k == "denied" {
            return ActivityEventPresentation(title: "Denied", symbol: "xmark.circle")
        }
        if o == "refused" || k == "refused" || k == "proof_refused" {
            return ActivityEventPresentation(title: "Refused", symbol: "nosign")
        }
        switch k {
        case "delivered", "run", "inject":
            return ActivityEventPresentation(title: "Delivered", symbol: "arrow.down.circle")
        case "approved", "approve":
            return ActivityEventPresentation(title: "Approved", symbol: "checkmark.circle")
        case "waiting", "pending":
            return ActivityEventPresentation(title: "Waiting", symbol: "hourglass")
        case "revoked", "revoke", "standing_revoke":
            return ActivityEventPresentation(title: "Revoked", symbol: "xmark")
        case "locked", "lock", "app_lock":
            return ActivityEventPresentation(title: "Locked", symbol: "lock")
        case "unlocked", "unlock", "app_unlock":
            return ActivityEventPresentation(title: "Unlocked", symbol: "lock.open")
        case "added", "add", "paste", "items_add", "unlocker_add":
            return ActivityEventPresentation(title: "Added", symbol: "plus.circle")
        case "replaced", "rotate", "items_rotate":
            return ActivityEventPresentation(title: "Replaced", symbol: "arrow.triangle.2.circlepath")
        case "removed", "remove", "items_remove", "unlocker_remove":
            return ActivityEventPresentation(title: "Removed", symbol: "trash")
        case "backup", "backup_create":
            return ActivityEventPresentation(title: "Backup", symbol: "archivebox")
        case "restore":
            return ActivityEventPresentation(title: "Restore", symbol: "arrow.uturn.backward")
        case "reveal", "reveal_app":
            return ActivityEventPresentation(title: "Revealed", symbol: "eye")
        default:
            let fallback = kind.escaped.replacingOccurrences(of: "_", with: " ").capitalized
            return ActivityEventPresentation(title: fallback.isEmpty ? "Event" : fallback, symbol: "doc.text")
        }
    }

    static func reasonWords(_ reason: DaemonText?) -> String {
        guard let raw = reason?.escaped, !raw.isEmpty else { return "" }
        switch raw {
        case "live_not_ticked": return "Live key not ticked"
        case "no_such_request", "expired": return "Request expired"
        case "statement_mismatch": return "Statement changed"
        case "vault_locked": return "Vault locked"
        case "proof_refused": return "Proof refused"
        case "screen_lock": return "Screen locked"
        case "session_resign": return "Session switched"
        case "sleep": return "Mac slept"
        case "idle": return "Idle timeout"
        case "user", "request": return "Locked by request"
        case "repeated": return "Repeated denial"
        case "root_denied": return "Process tree blocked"
        default:
            return raw.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    static func whoLabel(_ entry: AppAuditEntryView) -> String {
        if let label = entry.subject?.agent?.escaped, !label.isEmpty {
            return label
        }
        return switch entry.subject?.kind {
        case .agent: "Agent"
        case .terminal: "Terminal"
        case .unknown, nil: "Unknown process"
        }
    }

    static func escapedCommandLine(_ entry: AppAuditEntryView) -> String {
        entry.argv_masked.map(\.escaped).joined(separator: " ")
    }
}

struct ActivityView: View {
    let session: VaultSession
    let scope: DaemonText?
    let query: String

    private var filteredEntries: [AppAuditEntryView] {
        let canonicalScope = scope.map { session.projects.canonicalDirectory($0) }
        let tokens = query.lowercased().split(whereSeparator: \.isWhitespace)
        return session.activity.entries.filter { entry in
            if let canonicalScope, let proj = entry.project_dir,
               session.projects.canonicalDirectory(proj) != canonicalScope && proj != canonicalScope {
                return false
            } else if canonicalScope != nil && entry.project_dir == nil {
                return false
            }
            guard !tokens.isEmpty else { return true }
            let eventPres = ActivityEventPresentation.from(kind: entry.kind, outcome: entry.outcome)
            let who = ActivityEventPresentation.whoLabel(entry)
            let projectText = entry.project_dir?.escaped ?? ""
            let keysText = entry.slugs.map(\.escaped).joined(separator: " ")
            let cmdText = ActivityEventPresentation.escapedCommandLine(entry)
            let reasonText = ActivityEventPresentation.reasonWords(entry.reason)
            let combined = [eventPres.title, entry.kind.escaped, who, projectText, keysText, cmdText, reasonText]
                .joined(separator: " ")
                .lowercased()

            return tokens.allSatisfy { token in
                let parts = token.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { return combined.contains(token) }
                let value = String(parts[1])
                switch parts[0] {
                case "project":
                    return projectText.lowercased().contains(value)
                case "key":
                    return entry.slugs.contains { $0.escaped.lowercased().contains(value) }
                case "agent":
                    return who.lowercased().contains(value)
                case "event":
                    return eventPres.title.lowercased().contains(value) || entry.kind.escaped.lowercased().contains(value)
                default:
                    return combined.contains(token)
                }
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Text("Activity")
                    .font(.headline)
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityIdentifier("activity.heading")
                Spacer()
                if let summary = session.activity.verifySummary {
                    HStack(spacing: 4) {
                        Image(systemName: session.activity.verifyIsOK == true ? "checkmark.circle" : "exclamationmark.triangle")
                            .accessibilityHidden(true)
                        Text(summary)
                            .font(.caption)
                            .accessibilityIdentifier("activity.verify.summary")
                    }
                    .foregroundStyle(session.activity.verifyIsOK == true ? ECToken.success.color : ECToken.warning.color)
                }
                Button("Verify log") {
                    Task { await session.activity.verifyLog() }
                }
                .disabled(session.activity.verifying || session.state != .ready)
                .accessibilityIdentifier("activity.verify")
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(ECToken.raised.color)

            Divider()

            if let failure = session.activity.failure {
                ContentUnavailableView(
                    "Activity unavailable",
                    systemImage: "exclamationmark.triangle",
                    description: Text("EnvCloak could not read the audit log (\(failure.description)).")
                )
                .accessibilityIdentifier("activity.error")
            } else if filteredEntries.isEmpty {
                ContentUnavailableView(
                    "No activity yet.",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Every delivery, approval and refusal is recorded here.")
                )
                .accessibilityIdentifier("activity.empty")
            } else {
                HSplitView {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(filteredEntries, id: \.seq) { entry in
                                activityRow(entry)
                            }
                            if session.activity.hasMore {
                                HStack {
                                    Spacer()
                                    if session.activity.loadingMore {
                                        ECBusy(size: .small)
                                    } else {
                                        Button("Load earlier entries") {
                                            Task { await session.activity.loadMore() }
                                        }
                                        .accessibilityIdentifier("activity.loadMore")
                                    }
                                    Spacer()
                                }
                                .padding(.vertical, 8)
                            }
                        }
                        .padding(16)
                    }
                    .frame(minWidth: 440, maxWidth: .infinity)
                    .accessibilityIdentifier("activity.table")

                    if let selected = session.activity.selectedEntry {
                        activityInspector(selected)
                            .frame(width: 280)
                    }
                }
            }
        }
        .background(ECToken.background.color)
        .onKeyPress(characters: CharacterSet(charactersIn: "jkJK")) { press in
            moveSelection(down: press.characters.lowercased() == "j")
            return .handled
        }
        .task {
            if session.activity.entries.isEmpty && session.state.canReadMetadata {
                await session.activity.refetch(.all)
            }
        }
    }

    private func moveSelection(down: Bool) {
        let list = filteredEntries
        guard !list.isEmpty else { return }
        guard let current = session.activity.selectedSeq,
              let idx = list.firstIndex(where: { $0.seq == current }) else {
            session.activity.selectedSeq = list.first?.seq
            return
        }
        let nextIndex = down ? min(idx + 1, list.count - 1) : max(idx - 1, 0)
        session.activity.selectedSeq = list[nextIndex].seq
    }

    private func activityRow(_ entry: AppAuditEntryView) -> some View {
        let event = ActivityEventPresentation.from(kind: entry.kind, outcome: entry.outcome)
        let who = ActivityEventPresentation.whoLabel(entry)
        let project = entry.project_dir.map(MetadataRequest.basename) ?? ""
        let keys = entry.slugs.map(\.escaped).joined(separator: ", ")
        let command = ActivityEventPresentation.escapedCommandLine(entry)
        let reason = ActivityEventPresentation.reasonWords(entry.reason)
        let isSelected = session.activity.selectedSeq == entry.seq

        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: event.symbol)
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityHidden(true)
                Text(event.title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(ECToken.text.color)
                Text(who)
                    .font(.subheadline)
                    .foregroundStyle(ECToken.secondary.color)
                if !project.isEmpty {
                    Text(project)
                        .font(.subheadline)
                        .foregroundStyle(ECToken.secondary.color)
                }
                Spacer()
                Text("#\(entry.seq)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(ECToken.secondary.color)
            }
            if !keys.isEmpty {
                Text(keys)
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.text.color)
            }
            if !command.isEmpty {
                Text(command)
                    .font(ECFont.martianMono(size: 10))
                    .foregroundStyle(ECToken.text.color)
                    .lineLimit(1)
                    .accessibilityIdentifier("activity.command.\(entry.seq)")
            }
            if !reason.isEmpty {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            isSelected ? ECToken.rule.color.opacity(0.35) : ECToken.raised.color,
            in: RoundedRectangle(cornerRadius: 6, style: .continuous)
        )
        .contentShape(Rectangle())
        .onTapGesture {
            session.activity.selectedSeq = entry.seq
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("activity.row.\(entry.seq)")
    }

    private func activityInspector(_ entry: AppAuditEntryView) -> some View {
        let event = ActivityEventPresentation.from(kind: entry.kind, outcome: entry.outcome)
        let command = ActivityEventPresentation.escapedCommandLine(entry)
        let reason = ActivityEventPresentation.reasonWords(entry.reason)
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Label(event.title, systemImage: event.symbol)
                    .font(.title3)
                    .foregroundStyle(ECToken.text.color)
                Text("Sequence #\(entry.seq)")
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.secondary.color)
                Text("Who: \(ActivityEventPresentation.whoLabel(entry))")
                    .font(.caption)
                    .foregroundStyle(ECToken.text.color)
                if let project = entry.project_dir {
                    Text("Project: \(project.escaped)")
                        .font(ECFont.martianMono(size: 10))
                        .foregroundStyle(ECToken.text.color)
                }
                if !entry.slugs.isEmpty {
                    Text("Keys: \(entry.slugs.map(\.escaped).joined(separator: ", "))")
                        .font(ECFont.martianMono(size: 10))
                        .foregroundStyle(ECToken.text.color)
                }
                if !command.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Command")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(ECToken.secondary.color)
                        Text(command)
                            .font(ECFont.martianMono(size: 10))
                            .foregroundStyle(ECToken.text.color)
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                }
                if !reason.isEmpty {
                    Text("Reason: \(reason)")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                }
                if let grant = entry.grant {
                    Text("Grant: \(grant.escaped)")
                        .font(ECFont.martianMono(size: 10))
                        .foregroundStyle(ECToken.secondary.color)
                }
                if let request = entry.request {
                    Text("Request: \(request.escaped)")
                        .font(ECFont.martianMono(size: 10))
                        .foregroundStyle(ECToken.secondary.color)
                }
            }
            .padding(16)
        }
        .background(ECToken.background.color)
        .accessibilityIdentifier("activity.inspector")
    }
}
