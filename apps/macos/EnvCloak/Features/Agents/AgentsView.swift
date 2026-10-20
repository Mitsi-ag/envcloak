import EnvCloakDesign
import EnvCloakKit
import Foundation
import SwiftUI

/// The six coverage surfaces reported by `envcloak agents status --json` (SPEC §7.1).
enum AgentSurfaceKind: String, Codable, CaseIterable, Sendable, Hashable {
    case promptToModel = "prompt_to_model"
    case transcript = "transcript"
    case fileRead = "file_read"
    case shell = "shell"
    case mcp = "mcp"
    case output = "output"

    var displayName: String {
        switch self {
        case .promptToModel:
            "prompt-to-model"
        case .transcript:
            "transcript"
        case .fileRead:
            "file read"
        case .shell:
            "shell"
        case .mcp:
            "MCP"
        case .output:
            "output"
        }
    }

    var canonicalIndex: Int {
        switch self {
        case .promptToModel: 0
        case .transcript: 1
        case .fileRead: 2
        case .shell: 3
        case .mcp: 4
        case .output: 5
        }
    }
}

/// Coverage state for a surface (SPEC §7.1).
enum AgentCoverageState: String, Codable, CaseIterable, Sendable, Hashable {
    case active
    case degraded
    case unsupported
    case unverified
}

/// Probe outcome for a surface, reported separately from `AgentCoverageState` (SPEC §7.1).
enum AgentProbeOutcome: String, Codable, CaseIterable, Sendable, Hashable {
    case passed
    case failed
    case skipped
    case notQualified = "not_qualified"
}

/// One surface row decoded from `envcloak agents status --json`.
struct AgentSurfaceReport: Codable, Equatable, Sendable, Identifiable {
    let surface: AgentSurfaceKind
    let state: AgentCoverageState
    let reasons: [String]
    let probe: AgentProbeOutcome
    let skipped: [String]

    var id: String { surface.rawValue }

    init(
        surface: AgentSurfaceKind,
        state: AgentCoverageState,
        reasons: [String] = [],
        probe: AgentProbeOutcome,
        skipped: [String] = []
    ) {
        self.surface = surface
        self.state = state
        self.reasons = reasons
        self.probe = probe
        self.skipped = skipped
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.surface = try container.decode(AgentSurfaceKind.self, forKey: .surface)
        self.state = try container.decode(AgentCoverageState.self, forKey: .state)
        self.reasons = try container.decodeIfPresent([String].self, forKey: .reasons) ?? []
        self.probe = try container.decode(AgentProbeOutcome.self, forKey: .probe)
        self.skipped = try container.decodeIfPresent([String].self, forKey: .skipped) ?? []
    }

    /// The coverage state as displayed in the UI. Never upgrades `.degraded` to `.active`.
    var displayedState: AgentCoverageState {
        state
    }

    /// Canonical CLI summary line: `<state> (<reasons>; probe=<outcome>)`.
    var formattedLine: String {
        let skippedSuffix = skipped.isEmpty
            ? ""
            : ", " + skipped.map { "\(Escape.display($0)) skipped" }.joined(separator: ", ")
        if reasons.isEmpty {
            return "\(displayedState.rawValue) (probe=\(probe.rawValue)\(skippedSuffix))"
        }
        let reasonList = reasons.map(Escape.display).joined(separator: ", ")
        return "\(displayedState.rawValue) (\(reasonList); probe=\(probe.rawValue)\(skippedSuffix))"
    }

    /// Human-readable explanation for the reported reason tokens.
    var humanReasonSummary: String? {
        guard !reasons.isEmpty else { return nil }
        return reasons.map(Self.humanReasonWord).joined(separator: "; ")
    }

    static func humanReasonWord(_ token: String) -> String {
        switch token {
        case "hooks_untrusted":
            "hooks wait for host trust"
        case "workspace_untrusted":
            "hooks wait for workspace trust"
        case "switched_off_user":
            "hooks switched off in user settings"
        case "switched_off_project":
            "hooks switched off in project settings"
        case "switched_off_local":
            "hooks switched off in local settings"
        case "switched_off_managed":
            "hooks switched off in managed settings"
        case "managed_only":
            "managed settings allow managed hooks only"
        case "config_dir_moved":
            "CLAUDE_CONFIG_DIR points to another settings folder"
        case "fails_open_on_timeout":
            "a hook that times out lets the action through"
        case "override_file":
            "AGENTS.override.md shadows the instruction block"
        case "needs_host_approval":
            "host asks before each tool call"
        case "outside_host_sandbox":
            "commands run outside the host sandbox"
        case "persists_blocked_prompt":
            "host keeps blocked prompts on disk"
        case "sandbox_blocks_socket":
            "host sandbox blocks the daemon socket"
        case "probe_needs_terminal":
            "probe needs an interactive terminal approval"
        case "hook_missing":
            "EnvCloak hook is missing from the host configuration"
        case "not_probed":
            "no probe has run on this machine"
        case "changed_since_probe":
            "binary, version, or configuration changed since last probe"
        case "not_drivable":
            "host has no headless CLI probe contract"
        default:
            Escape.display(token.replacingOccurrences(of: "_", with: " "))
        }
    }
}

/// EnvCloak's own MCP server line from `envcloak agents status --json`.
struct AgentServerReport: Codable, Equatable, Sendable {
    let availability: String
    let reasons: [String]
    let probe: AgentProbeOutcome
    let sentinel: String

    var formattedLine: String {
        let escapedAvailability = Escape.display(availability)
        let reasonSuffix = reasons.isEmpty ? "" : "; " + reasons.map(Escape.display).joined(separator: "; ")
        if sentinel == "not_run" {
            return "\(escapedAvailability)\(reasonSuffix) (probe=\(probe.rawValue))"
        }
        let sentinelWords = Escape.display(sentinel.replacingOccurrences(of: "_", with: " "))
        return "\(escapedAvailability)\(reasonSuffix) (probe=\(probe.rawValue), sentinel \(sentinelWords))"
    }
}

/// One agent host row decoded from `envcloak agents status --json`.
struct AgentRowReport: Codable, Equatable, Sendable, Identifiable {
    let agent: String
    let name: String?
    let tier: Int?
    let version: String?
    let exe: String?
    let probed: String?
    let identified_by: String?
    let surfaces: [AgentSurfaceReport]
    let envcloak_server: AgentServerReport?

    var id: String { agent }

    var displayName: String {
        if let name, !name.isEmpty {
            return Escape.display(name)
        }
        return Escape.display(agent)
    }

    var displayVersion: String? {
        guard let version, !version.isEmpty else { return nil }
        return Escape.display(version)
    }

    var displayExecutable: String? {
        guard let exe, !exe.isEmpty else { return nil }
        return Escape.display(exe)
    }

    /// Surfaces ordered with failed probes (`probe == .failed`) first, then canonical surface order (SPEC §7.1).
    var sortedSurfaces: [AgentSurfaceReport] {
        surfaces.sorted { lhs, rhs in
            let lhsFailed = lhs.probe == .failed
            let rhsFailed = rhs.probe == .failed
            if lhsFailed != rhsFailed {
                return lhsFailed && !rhsFailed
            }
            return lhs.surface.canonicalIndex < rhs.surface.canonicalIndex
        }
    }
}

/// Top-level JSON report from `envcloak agents status --json`.
struct AgentStatusReport: Codable, Equatable, Sendable {
    let agents: [AgentRowReport]
}

/// One planned or applied file step from `envcloak agents install --json`.
struct AgentInstallChange: Codable, Equatable, Sendable, Identifiable {
    let path: String
    let what: String?
    let outcome: String?
    let reason: String?
    let message: String?

    var id: String { "\(path):\(what ?? outcome ?? "")" }

    var displayPath: String {
        Escape.display(path)
    }

    var displayDetail: String {
        if let what, !what.isEmpty {
            return Escape.display(what)
        }
        if let outcome, !outcome.isEmpty {
            if let message, !message.isEmpty {
                return "\(Escape.display(outcome)): \(Escape.display(message))"
            }
            return Escape.display(outcome)
        }
        return "update configuration"
    }
}

struct AgentHostInstallPlan: Codable, Equatable, Sendable {
    let host: String
    let version: String?
    let found: String?
    let changes: [AgentInstallChange]
}

struct AgentProjectInstallPlan: Codable, Equatable, Sendable {
    let dir: String
    let changes: [AgentInstallChange]
}

/// Decoded output of `envcloak agents install [--yes] --json`.
struct AgentInstallPlan: Codable, Equatable, Sendable {
    let hosts: [AgentHostInstallPlan]
    let project: AgentProjectInstallPlan?
    let applied: Bool
    let complete: Bool?

    var allChanges: [AgentInstallChange] {
        var result = hosts.flatMap(\.changes)
        if let project {
            result.append(contentsOf: project.changes)
        }
        return result
    }

    var plannedFilePaths: [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for change in allChanges {
            let escaped = change.displayPath
            if seen.insert(escaped).inserted {
                ordered.append(escaped)
            }
        }
        return ordered
    }
}

struct CLIOutput: Equatable, Sendable {
    let exitCode: Int32
    let json: String
    let errorText: String
}

/// Backing store for the Agents area (`M3-J3`, design §5.5).
@MainActor
@Observable
final class AgentsStore {
    private let runCLI: @Sendable ([String]) async throws -> CLIOutput

    private(set) var agents: [AgentRowReport] = []
    var selectedAgentID: String?
    private(set) var isLoading = false
    private(set) var isUnavailableInBuild = false
    var notice: String?
    private(set) var pendingInstallPlan: AgentInstallPlan?
    private(set) var pendingInstallAgentID: String?

    init(
        runCLI: @escaping @Sendable ([String]) async throws -> CLIOutput = { args in
            do {
                let (exitCode, json) = try await CLIRunner().runAgents(arguments: args)
                return CLIOutput(exitCode: exitCode, json: json, errorText: "")
            } catch CLIError.failed(let code) {
                return CLIOutput(exitCode: code, json: "", errorText: "")
            }
        }
    ) {
        self.runCLI = runCLI
    }

    var selectedAgent: AgentRowReport? {
        if let selectedAgentID, let match = agents.first(where: { $0.agent == selectedAgentID }) {
            return match
        }
        return agents.first
    }

    func refresh(preserveNotice: Bool = false) async {
        isLoading = true
        defer { isLoading = false }

        do {
            let output = try await runCLI(["agents", "status", "--json"])
            guard output.exitCode == 0 else {
                if output.errorText.contains("not_in_this_build") || output.json.contains("not_in_this_build") {
                    isUnavailableInBuild = true
                    if !preserveNotice { notice = nil }
                } else {
                    let detail = output.errorText.trimmingCharacters(in: .whitespacesAndNewlines)
                    notice = detail.isEmpty
                        ? "Could not read agent coverage status (exit \(output.exitCode))."
                        : Escape.display(detail)
                }
                return
            }
            isUnavailableInBuild = false
            let decoded = try JSONDecoder().decode(
                AgentStatusReport.self,
                from: Data(output.json.utf8)
            )
            agents = decoded.agents.map { row in
                AgentRowReport(
                    agent: row.agent,
                    name: row.name,
                    tier: row.tier,
                    version: row.version,
                    exe: row.exe,
                    probed: row.probed,
                    identified_by: row.identified_by,
                    surfaces: row.sortedSurfaces,
                    envcloak_server: row.envcloak_server
                )
            }
            if selectedAgentID == nil || !agents.contains(where: { $0.agent == selectedAgentID }) {
                selectedAgentID = agents.first?.agent
            }
            if !preserveNotice {
                notice = nil
            }
        } catch {
            notice = "Could not decode agent coverage report."
        }
    }

    func runChecksAgain() async {
        await refresh()
        if notice == nil && !isUnavailableInBuild {
            notice = "Coverage checks updated."
        }
    }

    /// Runs `envcloak agents install [--agent <id>] --json` without `--yes` so the files to be written are named before confirmation.
    func prepareInstall(for agentID: String? = nil) async {
        isLoading = true
        defer { isLoading = false }

        var args = ["agents", "install", "--json"]
        if let agentID, !agentID.isEmpty {
            args.append(contentsOf: ["--agent", agentID])
        }
        do {
            let output = try await runCLI(args)
            guard let data = output.json.data(using: .utf8),
                  let plan = try? JSONDecoder().decode(AgentInstallPlan.self, from: data) else {
                let detail = output.errorText.trimmingCharacters(in: .whitespacesAndNewlines)
                notice = detail.isEmpty
                    ? "Could not preview integration changes."
                    : Escape.display(detail)
                return
            }
            pendingInstallAgentID = agentID
            pendingInstallPlan = plan
            notice = nil
        } catch {
            notice = "Could not run envcloak agents install preview."
        }
    }

    func cancelInstall() {
        pendingInstallPlan = nil
        pendingInstallAgentID = nil
    }

    /// Runs `envcloak agents install [--agent <id>] --yes --json` after the user confirms the named files.
    func confirmInstall() async {
        isLoading = true
        defer { isLoading = false }

        var args = ["agents", "install", "--yes", "--json"]
        if let agentID = pendingInstallAgentID, !agentID.isEmpty {
            args.append(contentsOf: ["--agent", agentID])
        }
        pendingInstallPlan = nil
        pendingInstallAgentID = nil

        do {
            let output = try await runCLI(args)
            if let data = output.json.data(using: .utf8),
               let report = try? JSONDecoder().decode(AgentInstallPlan.self, from: data) {
                let changedFiles = report.plannedFilePaths
                if report.complete == false || output.exitCode != 0 {
                    let details = report.allChanges.map { change in
                        "\(change.displayPath) (\(change.displayDetail))"
                    }
                    if details.isEmpty {
                        notice = "Integration install did not complete (exit \(output.exitCode))."
                    } else {
                        notice = "Integration install incomplete: \(details.joined(separator: "; "))."
                    }
                } else if changedFiles.isEmpty {
                    notice = "Integration is already up to date."
                } else {
                    notice = "Updated integration files: \(changedFiles.joined(separator: ", "))."
                }
            } else if output.exitCode == 0 {
                notice = "Agent integration installed."
            } else {
                let detail = output.errorText.trimmingCharacters(in: .whitespacesAndNewlines)
                notice = detail.isEmpty
                    ? "Integration install did not complete (exit \(output.exitCode))."
                    : Escape.display(detail)
            }
            await refresh(preserveNotice: true)
        } catch {
            notice = "Could not complete agent integration install."
        }
    }

    static func matches(agent: AgentRowReport, token: String) -> Bool {
        let normalizedToken = normalizeAgentToken(token)
        guard !normalizedToken.isEmpty else { return false }
        let idToken = normalizeAgentToken(agent.agent)
        let nameToken = normalizeAgentToken(agent.name ?? "")
        return normalizedToken == idToken
            || normalizedToken == nameToken
            || idToken.hasPrefix(normalizedToken)
            || normalizedToken.hasPrefix(idToken)
    }

    static func grants(for agent: AgentRowReport, in grants: [GrantView]) -> [GrantView] {
        grants.filter { grant in
            guard let grantAgent = grant.label?.escaped else { return false }
            return matches(agent: agent, token: grantAgent)
        }
    }

    static func standingApprovals(for agent: AgentRowReport, in standing: [StandingView]) -> [StandingView] {
        standing.filter { entry in
            matches(agent: agent, token: entry.agent_name.escaped) || matches(agent: agent, token: entry.agent_id.escaped)
        }
    }

    private static func normalizeAgentToken(_ raw: String) -> String {
        raw.lowercased()
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: " ", with: "")
    }
}

/// Design §5.5 Agents screen (`M3-J3`).
struct AgentsView: View {
    @Bindable var session: VaultSession

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar
            Divider().overlay(ECToken.rule.color)

            if let plan = session.agents.pendingInstallPlan {
                installConfirmationBanner(plan)
                Divider().overlay(ECToken.rule.color)
            }

            if let notice = session.agents.notice {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                        .foregroundStyle(ECToken.secondary.color)
                    Text(notice)
                        .font(.caption)
                        .foregroundStyle(ECToken.text.color)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
                .background(ECToken.raised.color)
                .accessibilityIdentifier("agents.notice")
                Divider().overlay(ECToken.rule.color)
            }

            if session.agents.isUnavailableInBuild {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Coverage checks arrive with `envcloak agents status`.")
                        .font(.body)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("agents.coverage.unavailable")
                }
                .padding(20)
                Spacer(minLength: 0)
            } else if session.agents.agents.isEmpty {
                emptyState
            } else {
                HSplitView {
                    agentSidebar
                        .frame(minWidth: 200, idealWidth: 220, maxWidth: 260)
                    agentDetail
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .background(ECToken.background.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("agents.view")
        .task {
            if session.agents.agents.isEmpty && !session.agents.isLoading {
                await session.agents.refresh()
            }
        }
    }

    private var headerBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Agents")
                    .font(.title2)
                    .foregroundStyle(ECToken.text.color)
                Text("Which agents are on this Mac, how well EnvCloak covers each surface, and what they hold now.")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
            }
            Spacer()
            Button("Install integration…") {
                let selected = session.agents.selectedAgent?.agent
                Task { await session.agents.prepareInstall(for: selected) }
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("agents.install")

            Button("Run checks again") {
                Task { await session.agents.runChecksAgain() }
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("agents.runChecks")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    private func installConfirmationBanner(_ plan: AgentInstallPlan) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Install EnvCloak agent integration")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            let files = plan.plannedFilePaths
            if files.isEmpty {
                Text("No configuration files need changes.")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
            } else {
                Text("EnvCloak will write the following files (backed up in the vault first):")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                ForEach(plan.allChanges) { change in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(change.displayPath)
                            .font(ECFont.martianMono(size: 11))
                            .foregroundStyle(ECToken.text.color)
                        Text(change.displayDetail)
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                    }
                    .accessibilityIdentifier("agents.install.file.\(change.displayPath)")
                }
            }
            HStack(spacing: 8) {
                Button("Write changes") {
                    Task { await session.agents.confirmInstall() }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("agents.install.confirm")

                Button("Cancel") {
                    session.agents.cancelInstall()
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("agents.install.cancel")
            }
        }
        .padding(12)
        .background(ECToken.raised.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("agents.install.sheet")
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Spacer()
            Text("No agent host found on PATH.")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            Text("Install a supported coding agent or click Run checks again to refresh.")
                .font(.body)
                .foregroundStyle(ECToken.secondary.color)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("agents.empty")
    }

    private var agentSidebar: some View {
        List(
            selection: Binding(
                get: { session.agents.selectedAgentID },
                set: { session.agents.selectedAgentID = $0 }
            )
        ) {
            ForEach(session.agents.agents) { row in
                HStack(spacing: 8) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.displayName)
                            .font(.callout.weight(.medium))
                            .foregroundStyle(ECToken.text.color)
                        if let version = row.displayVersion {
                            Text(version)
                                .font(ECFont.martianMono(size: 11))
                                .foregroundStyle(ECToken.secondary.color)
                        }
                    }
                    Spacer()
                    if row.sortedSurfaces.contains(where: { $0.probe == .failed }) {
                        Label("probe failed", systemImage: "xmark.octagon")
                            .font(.caption)
                            .foregroundStyle(ECToken.danger.color)
                    }
                }
                .tag(Optional(row.agent))
                .accessibilityIdentifier("agents.row.\(row.agent)")
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private var agentDetail: some View {
        if let agent = session.agents.selectedAgent {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    agentHeader(agent)
                    coverageSection(agent)
                    grantsSection(agent)
                    standingSection(agent)
                }
                .padding(20)
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("agents.detail.\(agent.agent)")
        } else {
            emptyState
        }
    }

    private func agentHeader(_ agent: AgentRowReport) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(agent.displayName)
                    .font(.title2)
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityIdentifier("agents.header.name")
                if let version = agent.displayVersion {
                    Text(version)
                        .font(ECFont.martianMono(size: 12))
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("agents.header.version")
                }
            }
            if let exe = agent.displayExecutable {
                Text(exe)
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("agents.header.exe")
            }
        }
    }

    private func coverageSection(_ agent: AgentRowReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Coverage")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)

            ForEach(agent.sortedSurfaces) { surface in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: symbol(for: surface))
                            .foregroundStyle(color(for: surface))
                            .accessibilityHidden(true)
                        Text(surface.surface.displayName)
                            .font(.callout.weight(.medium))
                            .foregroundStyle(ECToken.text.color)
                            .frame(width: 130, alignment: .leading)
                        Text(surface.formattedLine)
                            .font(ECFont.martianMono(size: 11))
                            .foregroundStyle(color(for: surface))
                            .accessibilityIdentifier("agents.surface.\(surface.surface.rawValue).state")
                        Spacer()
                    }
                    if let summary = surface.humanReasonSummary {
                        Text(summary)
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                            .padding(.leading, 148)
                            .accessibilityIdentifier("agents.surface.\(surface.surface.rawValue).reasons")
                    }
                }
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(ECToken.raised.color)
                )
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("agents.surface.\(surface.surface.rawValue)")
            }

            if let server = agent.envcloak_server {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("EnvCloak server")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(ECToken.text.color)
                            .frame(width: 130, alignment: .leading)
                        Text(server.formattedLine)
                            .font(ECFont.martianMono(size: 11))
                            .foregroundStyle(ECToken.text.color)
                        Spacer()
                    }
                    Text("Commands that run_with_secrets starts run outside \(agent.displayName)'s sandbox and hold the keys injected into them while they run.")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                }
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(ECToken.raised.color)
                )
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("agents.server")
            }
        }
    }

    private func grantsSection(_ agent: AgentRowReport) -> some View {
        let activeGrants = AgentsStore.grants(for: agent, in: session.grants.rows)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Grants in force")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            if activeGrants.isEmpty {
                Text("No active grants for \(agent.displayName).")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("agents.grants.empty")
            } else {
                ForEach(activeGrants, id: \.id.escaped) { grant in
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(MetadataRequest.basename(grant.project_dir))
                                .font(.callout.weight(.medium))
                                .foregroundStyle(ECToken.text.color)
                            Text(grant.bindings.map(\.slug.escaped).joined(separator: ", "))
                                .font(ECFont.martianMono(size: 11))
                                .foregroundStyle(ECToken.secondary.color)
                        }
                        Spacer()
                        Text("Inject")
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                        Button("Revoke") {
                            Task { await session.revoke(grant.id) }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .accessibilityIdentifier("agents.grants.revoke.\(grant.id.escaped)")
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(ECToken.raised.color)
                    )
                    .accessibilityIdentifier("agents.grants.row.\(grant.id.escaped)")
                }
            }
        }
    }

    private func standingSection(_ agent: AgentRowReport) -> some View {
        let standingRows = AgentsStore.standingApprovals(for: agent, in: session.grants.standing)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Standing approvals")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            if standingRows.isEmpty {
                Text("No standing approvals for \(agent.displayName).")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("agents.standing.empty")
            } else {
                ForEach(standingRows, id: \.id.escaped) { entry in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(MetadataRequest.basename(entry.project_dir))
                                .font(.callout.weight(.medium))
                                .foregroundStyle(ECToken.text.color)
                            Label(entry.scopeLabel, systemImage: "exclamationmark.triangle")
                                .font(.caption)
                                .foregroundStyle(ECToken.warning.color)
                        }
                        Spacer()
                        Button("Revoke") {
                            Task { await session.revokeStanding(entry.id) }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .accessibilityIdentifier("agents.standing.revoke.\(entry.id.escaped)")
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(ECToken.raised.color)
                    )
                    .accessibilityIdentifier("agents.standing.row.\(entry.id.escaped)")
                }
            }
        }
    }

    private func symbol(for surface: AgentSurfaceReport) -> String {
        if surface.probe == .failed {
            return "xmark.octagon"
        }
        switch surface.displayedState {
        case .active:
            return "checkmark.circle"
        case .degraded:
            return "exclamationmark.triangle"
        case .unsupported:
            return "nosign"
        case .unverified:
            return "questionmark.circle"
        }
    }

    private func color(for surface: AgentSurfaceReport) -> Color {
        if surface.probe == .failed {
            return ECToken.danger.color
        }
        switch surface.displayedState {
        case .active:
            return ECToken.success.color
        case .degraded:
            return ECToken.warning.color
        case .unsupported, .unverified:
            return ECToken.secondary.color
        }
    }
}
