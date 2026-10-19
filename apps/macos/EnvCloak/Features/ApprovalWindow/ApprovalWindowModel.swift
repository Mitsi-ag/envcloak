import CryptoKit
import EnvCloakKit
import Foundation
import Observation

enum ApprovalOutcome: Equatable {
    case pending
    case signing
    case approved(grantId: DaemonText, expiresInSecs: UInt64?)
    case cancelled
    case authFailed
    case denied
    case expired
    case statementChanged
    case liveNotTicked
    case vaultLocked
    case proposalApplied(envName: String, slug: String)
    case failed(String)
}

enum ApprovalDurationChoice: String, CaseIterable, Identifiable {
    case once = "Once"
    case minutes15 = "15 min"
    case hour1 = "1 h"
    case hours8 = "8 h"
    case hours12 = "12 h"
    case hours24 = "24 h"
    case standingDays7 = "Standing: 7 days"
    case standingDays30 = "Standing: 30 days"

    var id: String { rawValue }

    var durationSecs: UInt64? {
        switch self {
        case .once: nil
        case .minutes15: 900
        case .hour1: 3600
        case .hours8: 28800
        case .hours12: 43200
        case .hours24: 86400
        case .standingDays7: 604_800
        case .standingDays30: 2_592_000
        }
    }

    var isStanding: Bool {
        switch self {
        case .standingDays7, .standingDays30: true
        default: false
        }
    }

    var words: String {
        switch self {
        case .once: "once"
        case .minutes15: "15 minutes"
        case .hour1: "1 hour"
        case .hours8: "8 hours"
        case .hours12: "12 hours"
        case .hours24: "24 hours"
        case .standingDays7: "7 days (standing)"
        case .standingDays30: "30 days (standing)"
        }
    }
}

@Observable @MainActor final class ApprovalWindowModel {
    let session: VaultSession
    var descriptor: PendingDescriptor?
    var outcome: ApprovalOutcome = .pending
    var durationChoice: ApprovalDurationChoice = .hours8 {
        didSet {
            if oldValue != durationChoice {
                noteContentChanged()
            }
        }
    }
    var tickedLiveVariables: Set<String> = []
    var showFullCommand = false
    var loadedAt: ContinuousClock.Instant
    var guardReadyAt: ContinuousClock.Instant
    var lastSignedStatementBytes: Data?
    var lastSignedDigestHex: String?
    private let nowProvider: () -> ContinuousClock.Instant

    init(
        session: VaultSession,
        descriptor: PendingDescriptor? = nil,
        now: @escaping () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) {
        self.session = session
        self.descriptor = descriptor
        self.nowProvider = now
        let current = now()
        self.loadedAt = current
        self.guardReadyAt = current.advanced(by: .milliseconds(500))
    }

    var isKnownAgentRoot: Bool {
        guard let descriptor else { return false }
        return descriptor.subject.kind == .agent && descriptor.subject.label != nil
    }

    var isStandingCapable: Bool {
        guard let descriptor, isKnownAgentRoot, descriptor.standing != nil else { return false }
        return descriptor.bindings.allSatisfy { $0.classificationView == .test }
    }

    var isLiveGuarded: Bool {
        guard let descriptor else { return false }
        return CanonicalStatement.liveGuarded(descriptor.subject.kind)
    }

    var availableDurationChoices: [ApprovalDurationChoice] {
        if isKnownAgentRoot {
            var choices: [ApprovalDurationChoice] = [
                .once,
                .minutes15,
                .hour1,
                .hours8,
                .hours24,
            ]
            if isStandingCapable {
                choices.append(contentsOf: [.standingDays7, .standingDays30])
            }
            return choices
        } else {
            return [.once, .minutes15, .hour1, .hours8, .hours12]
        }
    }

    var requestedBindings: [BindingSummary] {
        descriptor?.bindings.filter { !$0.granted } ?? []
    }

    var coveredBindings: [BindingSummary] {
        descriptor?.bindings.filter { $0.granted } ?? []
    }

    var liveBindings: [BindingSummary] {
        guard let descriptor, isLiveGuarded else {
            return []
        }
        return descriptor.bindings.filter { $0.classificationView == .live }
    }

    var allLiveKeysTicked: Bool {
        liveBindings.allSatisfy { tickedLiveVariables.contains($0.env_name.escaped) }
    }

    var isWithinGuardWindow: Bool {
        nowProvider() < guardReadyAt
    }

    var remainingSecs: UInt64 {
        guard let descriptor else { return 0 }
        let total = descriptor.expires_in_secs
        let elapsed = max(0, Int64(loadedAt.duration(to: nowProvider()).components.seconds))
        let left = Int64(total) - elapsed
        return left > 0 ? UInt64(left) : 0
    }

    var isExpired: Bool {
        if outcome == .expired { return true }
        guard descriptor != nil else { return false }
        return remainingSecs == 0
    }

    var canApprove: Bool {
        guard descriptor != nil else { return false }
        guard session.state == .ready else { return false }
        guard outcome != .signing, outcome != .expired, !isExpired else { return false }
        guard allLiveKeysTicked else { return false }
        guard !isWithinGuardWindow else { return false }
        return true
    }

    var disabledReasonText: String? {
        if isExpired {
            return "This request expired."
        }
        if !allLiveKeysTicked {
            return "Tick each live key to approve, or use its test key."
        }
        if isWithinGuardWindow {
            return "Wait a moment before approving."
        }
        return nil
    }

    var standingWarningText: String? {
        guard durationChoice.isStanding, let descriptor else { return nil }
        let agent = NotificationManager.subjectLabel(descriptor.subject)
        return "any \(agent) session in this project, including one started by another program, gets these keys without asking"
    }

    func noteWindowBecameKey() {
        guardReadyAt = nowProvider().advanced(by: .milliseconds(500))
    }

    func noteContentChanged() {
        guardReadyAt = nowProvider().advanced(by: .milliseconds(500))
    }

    func completeGuardPeriodForTesting() {
        guardReadyAt = nowProvider()
    }

    func toggleLiveKey(_ envNameEscaped: String, isTicked: Bool? = nil) {
        let shouldTick = isTicked ?? !tickedLiveVariables.contains(envNameEscaped)
        if shouldTick {
            tickedLiveVariables.insert(envNameEscaped)
        } else {
            tickedLiveVariables.remove(envNameEscaped)
        }
        noteContentChanged()
    }

    func currentApproveOptions() -> ApprovalOptions {
        guard let descriptor else {
            return ApprovalOptions(uses: .once, ttl_secs: 300)
        }
        let confirmed: [String] = isLiveGuarded
            ? descriptor.bindings
                .filter { $0.classificationView == .live && tickedLiveVariables.contains($0.env_name.escaped) }
                .map { MetadataRequest.raw($0.env_name) }
            : []
        if durationChoice == .once {
            return ApprovalOptions(
                uses: .once,
                ttl_secs: 300,
                live: confirmed,
                standing: nil
            )
        }
        if durationChoice.isStanding {
            return ApprovalOptions(
                uses: .session,
                ttl_secs: 28800,
                live: confirmed,
                standing: durationChoice.durationSecs
            )
        }
        return ApprovalOptions(
            uses: .session,
            ttl_secs: durationChoice.durationSecs ?? 28800,
            live: confirmed,
            standing: nil
        )
    }

    func currentStatementData() -> Data? {
        guard let descriptor else { return nil }
        return CanonicalStatement.encode(descriptor, options: currentApproveOptions())
    }

    func load(requestId: DaemonText? = nil) async {
        guard let id = requestId ?? session.activeApprovalRequestId ?? session.grants.pending.first?.request else {
            descriptor = nil
            return
        }
        do {
            let fetched = try await session.fetchPendingDescriptor(id)
            applyDescriptor(fetched)
        } catch EnvCloakError.rpc(.vaultLocked, _) {
            outcome = .vaultLocked
        } catch EnvCloakError.rpc(.noSuchRequest, _) {
            outcome = .expired
        } catch {
            outcome = .failed("The request could not be loaded.")
        }
    }

    func applyDescriptor(_ newDescriptor: PendingDescriptor) {
        descriptor = newDescriptor
        tickedLiveVariables = []
        if !availableDurationChoices.contains(durationChoice) {
            durationChoice = .hours8
        }
        let now = nowProvider()
        loadedAt = now
        guardReadyAt = now.advanced(by: .milliseconds(500))
        if outcome != .statementChanged {
            outcome = .pending
        }
    }

    func triggerExpiry() {
        session.resolvedSigner.invalidateActiveContext()
        outcome = .expired
    }

    func checkExpiry() {
        if descriptor != nil && remainingSecs == 0 && outcome != .expired {
            triggerExpiry()
        }
    }

    func approve() async {
        guard let descriptor else { return }
        if session.state == .locked {
            outcome = .vaultLocked
            return
        }
        if isExpired {
            triggerExpiry()
            return
        }
        guard allLiveKeysTicked else {
            outcome = .liveNotTicked
            return
        }
        guard !isWithinGuardWindow else { return }

        let options = currentApproveOptions()
        let statementBytes = CanonicalStatement.encode(descriptor, options: options)
        let digestHex = CanonicalStatement.digestHex(descriptor, options: options)
        lastSignedStatementBytes = statementBytes
        lastSignedDigestHex = digestHex

        let cmdSummary = Self.headerCommand(descriptor.argv)
        let projectName = MetadataRequest.basename(descriptor.project.dir)
        let reason = ContextFactory.approvalReason(
            command: cmdSummary,
            project: projectName,
            keyCount: requestedBindings.count
        )

        outcome = .signing
        do {
            let signature = try await session.resolvedSigner.sign(statementBytes, reason: reason)
            if isExpired {
                triggerExpiry()
                return
            }
            let output = try await session.submitSignedApproval(
                request: descriptor.request,
                options: options,
                digestHex: digestHex,
                signatureHex: signature.hex
            )
            outcome = .approved(grantId: output.grant, expiresInSecs: output.expires_in_secs)
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            if outcome != .expired {
                outcome = .cancelled
            }
        } catch SignerError.notInteractiveSession, KeyStoreError.notInteractiveSession {
            outcome = .failed("Touch ID cannot be used over SSH. Approve in a terminal with envcloak approve <id>.")
        } catch EnvCloakError.rpc(.statementMismatch, _) {
            outcome = .statementChanged
            if let reloaded = try? await session.fetchPendingDescriptor(descriptor.request) {
                applyDescriptor(reloaded)
                outcome = .statementChanged
            }
        } catch EnvCloakError.rpc(.liveNotTicked, _) {
            outcome = .liveNotTicked
        } catch EnvCloakError.rpc(.vaultLocked, _) {
            outcome = .vaultLocked
        } catch EnvCloakError.rpc(.noSuchRequest, _) {
            triggerExpiry()
        } catch {
            outcome = .failed("The approval could not be completed. Try again.")
        }
    }

    func deny() async {
        guard let descriptor else { return }
        let ok = await session.denyPending(descriptor.request)
        if ok {
            outcome = .denied
        } else if session.state == .locked {
            outcome = .vaultLocked
        } else {
            outcome = .failed("The request could not be denied. Try again.")
        }
    }

    func useTestKeyInstead(_ proposal: Proposal) async {
        guard let descriptor else { return }
        guard proposal.canApplyAutomatically else {
            outcome = .failed(proposal.advice(manifest: descriptor.project.manifest))
            return
        }
        let edit = MetadataRequest.proposalEdit(project: descriptor.project.dir, proposal: proposal)
        let applied = await session.bindings.apply(edit, session: session, manager: nil)
        guard applied else {
            outcome = .failed(session.notice ?? "The binding could not be updated in envcloak.toml.")
            return
        }
        _ = WorkspaceActions.copyBindingCommand(edit)
        let denied = await session.denyPending(descriptor.request)
        guard denied else {
            outcome = .failed("Updated envcloak.toml, but the pending request could not be denied.")
            return
        }
        outcome = .proposalApplied(
            envName: proposal.env_name.escaped,
            slug: proposal.testReferenceDisplay
        )
    }

    static func headerCommand(_ argv: [DaemonText]) -> String {
        let firstTwo = argv.prefix(2).map(\.escaped).joined(separator: " ")
        return firstTwo.isEmpty ? "command" : firstTwo
    }
}
