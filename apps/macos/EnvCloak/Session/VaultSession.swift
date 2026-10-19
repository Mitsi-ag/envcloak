import EnvCloakKit
import Foundation
import Observation

struct Change: OptionSet {
    let rawValue: Int
    static let items = Change(rawValue: 1)
    static let projects = Change(rawValue: 2)
    static let grants = Change(rawValue: 4)
    static let pending = Change(rawValue: 8)
    static let all: Change = [.items, .projects, .grants, .pending]
}

@MainActor protocol Store {
    func refetch(_ change: Change) async
}

@Observable @MainActor final class VaultSession {
    let bindings: BindingHistory
    let items: ItemsStore
    let projects: ProjectsStore
    let grants: GrantsStore
    let contextFactory: ContextFactory
    let keyStore: KeyStore
    let notifications: NotificationManager
    var unlockKey: (any UnlockKeyAgreement)?
    var approvalSigner: (any ApprovalSigner)?
    var enrolledPublicKeysOverride: EnrolledPublicKeys?
    var enrolledTouchID = false
    var enrolmentPendingId: DaemonText?
    var enrolmentCommand: String?
    var enrolmentCompleted = false
    var activeApprovalRequestId: DaemonText?
    var onOpenApprovalWindow: (@MainActor () -> Void)?
    var isFrontmostOverride: Bool?
    var sshSession = false
    var clamshellClosed = false
    private let client: (any WorkspaceClient)?
    private var lastStatus: StatusView?
    private var polling = false
    private var locking = false
    private static let busyNotice = "EnvCloak is busy finishing an unlock or approval. Try again in a moment."
    private var generation = 0
    var state = ConnectionState.connecting
    var lockReason = ""
    var notice: String?
    var actionInProgress = false
    private(set) var pendingCount: UInt32 = 0
    private(set) var proofWait: UInt64 = 0

    static var defaultKeyStore: KeyStore {
        #if ENVCLOAK_SCREEN_TESTS
        KeyStore(storage: DataProtectionKeychainBlobStorage(enabled: false))
        #else
        KeyStore()
        #endif
    }

    init(
        client: (any WorkspaceClient)?,
        folders: ProjectFolders? = nil,
        runner: CLIRunner? = try? CLIRunner(),
        contextFactory: ContextFactory = ContextFactory(),
        keyStore: KeyStore = VaultSession.defaultKeyStore,
        unlockKey: (any UnlockKeyAgreement)? = nil,
        approvalSigner: (any ApprovalSigner)? = nil,
        enrolledPublicKeysOverride: EnrolledPublicKeys? = nil,
        notifications: NotificationManager? = nil
    ) {
        self.client = client
        self.contextFactory = contextFactory
        self.keyStore = keyStore
        self.unlockKey = unlockKey
        self.approvalSigner = approvalSigner
        self.enrolledPublicKeysOverride = enrolledPublicKeysOverride
        let resolvedNotifications = notifications ?? NotificationManager()
        self.notifications = resolvedNotifications
        bindings = BindingHistory(runner: runner)
        items = ItemsStore(client: client)
        projects = ProjectsStore(client: client, folders: folders)
        grants = GrantsStore(client: client)
        if unlockKey != nil || approvalSigner != nil || keyStore.hasEnrolledKeys() {
            enrolledTouchID = true
        }
        resolvedNotifications.onDeny = { [weak self] id in
            guard let self else { return }
            _ = await self.denyPending(id)
        }
        resolvedNotifications.onOpenRequest = { [weak self] id in
            guard let self else { return }
            self.openApprovalWindow(for: id)
        }
    }

    var unlockButtonTitle: String {
        if clamshellClosed {
            return "Unlock with password"
        }
        if let override = contextFactory.wordingOverride {
            return override.unlockButtonTitle
        }
        if unlockKey != nil || approvalSigner != nil {
            return "Unlock with Touch ID"
        }
        #if ENVCLOAK_SCREEN_TESTS
        return "Unlock with Touch ID"
        #else
        if contextFactory.wording() == .password {
            return "Unlock with password"
        }
        return "Unlock with Touch ID"
        #endif
    }

    var approveButtonTitle: String {
        if clamshellClosed {
            return "Approve with password"
        }
        if let override = contextFactory.wordingOverride {
            return override.approveButtonTitle
        }
        if unlockKey != nil || approvalSigner != nil {
            return "Approve with Touch ID"
        }
        #if ENVCLOAK_SCREEN_TESTS
        return "Approve with Touch ID"
        #else
        if contextFactory.wording() == .password {
            return "Approve with password"
        }
        return "Approve with Touch ID"
        #endif
    }

    static func live() -> VaultSession {
        do {
            let client = SocketWorkspaceClient(client: try DaemonClient())
            do { return VaultSession(client: client, folders: try ProjectFolders.live()) }
            catch {
                let session = VaultSession(client: client)
                session.notice = "Saved project folders could not be restored. The adopted project index is still available."
                return session
            }
        }
        catch {
            let session = VaultSession(client: nil)
            session.state = .unverified(.path)
            return session
        }
    }

    func run() async {
        guard client != nil else { return }
        while !Task.isCancelled {
            await poll()
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
        }
    }

    func poll() async {
        guard !polling, !locking, let client else { return }
        polling = true
        defer { polling = false }
        let captured = generation
        do {
            let status = try await readStatus(client)
            guard captured == generation, !Task.isCancelled else { return }
            if notice == Self.busyNotice { notice = nil }
            proofWait = status.approvals.proof_wait_secs
            lockReason = switch status.lock.last_reason {
            case .idle: "Locked after \(Self.durationWords(status.lock.idle_limit_secs)) idle"
            case .sleep: "Locked when this Mac slept"
            case .screenLock: "Locked when the screen locked"
            case .sessionResign: "Locked when the user session became inactive"
            case .request: "Locked by request"
            case .signal: "Locked when the background process stopped"
            case .restore: "Locked after restoring the vault"
            case nil: ""
            }
            let next: ConnectionState
            next = switch status.vault.state {
            case .absent: .noVault
            case .locked: .locked
            case .unlocked: status.vault.integrity == .tampered ? .readOnly : (status.vault.read_only ? .upgradeReadOnly : .ready)
            case .unavailable: .unavailable
            }
            var change: Change = []
            if lastStatus == nil || next != state || status.daemon.pid != lastStatus?.daemon.pid {
                change = .all
            } else {
                if status.audit.head_seq != lastStatus?.audit.head_seq { change.formUnion(.all) }
                if status.approvals.grants != lastStatus?.approvals.grants { change.insert(.grants) }
                if status.approvals.pending != lastStatus?.approvals.pending { change.insert(.pending) }
            }
            state = next
            pendingCount = next == .ready ? status.approvals.pending : 0
            if !next.canReadMetadata {
                clearMetadata()
                lastStatus = status
                return
            }
            await items.refetch(change)
            guard captured == generation, !Task.isCancelled else { return }
            await projects.refetch(change)
            guard captured == generation, !Task.isCancelled else { return }
            if projects.scopeSaveFailed { notice = ProjectsStore.scopeSaveWarning }
            else if notice == ProjectsStore.scopeSaveWarning { notice = nil }
            await projects.refreshOpenIfChanged()
            guard captured == generation, !Task.isCancelled else { return }
            await grants.refetch(change)
            guard captured == generation, !Task.isCancelled else { return }
            if change.contains(.pending) {
                await notifications.reconcile(
                    pending: grants.pending,
                    isFrontmost: isFrontmostOverride
                )
            }
            for error in [items.failure, items.detailFailure, projects.failure, projects.checkFailure, grants.failure].compactMap({ $0 }) {
                switch error {
                case .daemonUnavailable, .daemonUnverified, .rpc(.vaultLocked, _), .rpc(.vaultTampered, _):
                    fail(error); return
                default: break
                }
            }
            lastStatus = status
        } catch {
            if captured == generation, !Task.isCancelled {
                if error as? EnvCloakError == .rpc(.busy, nil) {
                    notice = Self.busyNotice
                } else { fail(error) }
            }
        }
    }

    private func readStatus(_ client: any WorkspaceClient) async throws -> StatusView {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var delay = Duration.milliseconds(100)
        while true {
            try Task.checkCancellation()
            do {
                let status = try await client.call(Status())
                guard !status.vault.busy else { throw EnvCloakError.rpc(.busy, nil) }
                return status
            } catch EnvCloakError.rpc(.busy, _) {
                let remaining = ContinuousClock.now.duration(to: deadline)
                guard remaining > .zero else { throw EnvCloakError.rpc(.busy, nil) }
                try await Task.sleep(for: min(delay, remaining))
                delay = min(delay * 2, .milliseconds(400))
            }
        }
    }

    private func clearMetadata() {
        bindings.clear()
        items.clear(); projects.clear(); grants.clear()
        notifications.clear()
    }

    private func fail(_ error: any Error) {
        lastStatus = nil
        clearMetadata()
        pendingCount = 0
        switch error as? EnvCloakError {
        case .daemonUnverified(let check): state = .unverified(check)
        case .rpc(.vaultLocked, _): state = .locked
        case .rpc(.vaultTampered, _): state = .readOnly
        case .daemonUnavailable: state = .noDaemon
        default:
            state = .unavailable
            notice = "The background process could not complete the request. Try again."
        }
    }

    static func durationWords(_ seconds: UInt64) -> String {
        let parts = [(seconds / 3600, "hour"), ((seconds / 60) % 60, "minute"), (seconds % 60, "second")]
        let words = parts.filter { $0.0 > 0 }.map { "\($0.0) " + $0.1 + ($0.0 == 1 ? "" : "s") }
        return words.isEmpty ? "0 seconds" : words.joined(separator: " ")
    }
    var verificationDetails: String {
        guard case .unverified(let check) = state else { return "" }
        return "Failed check: " + check.rawValue + ". Socket: " + (client?.socketPath?.escaped ?? "path unavailable")
    }
    func setScope(_ scope: DaemonText?) {
        do { try projects.setScope(scope) }
        catch { notice = projects.scopeSaveFailed ? ProjectsStore.scopeSaveWarning : "The project scope could not be saved. Try again." }
    }

    func selectKey(_ slug: DaemonText?) async {
        guard state.canReadMetadata else { return }
        await items.select(slug)
    }

    func openProject(_ directory: DaemonText) async {
        guard state.canReadMetadata else { return }
        await projects.open(directory)
    }

    func add(_ request: consuming ItemsAdd) async throws -> AddedView {
        guard state == .ready, !actionInProgress, let client else { throw EnvCloakError.daemonUnavailable }
        actionInProgress = true
        defer { actionInProgress = false }
        let captured = generation
        let added = try await client.add(consume request)
        guard captured == generation, state == .ready else { throw EnvCloakError.daemonUnavailable }
        await items.refetch(.items)
        guard captured == generation, state == .ready else { throw EnvCloakError.daemonUnavailable }
        return added
    }

    func lock() async {
        guard let client, !locking, state != .locked else { return }
        locking = true
        actionInProgress = true
        defer {
            // Lock uses its own client slot. Retire every earlier refresh at
            // completion as well as entry, including failed lock responses.
            generation += 1
            lastStatus = nil
            clearMetadata()
            pendingCount = 0
            proofWait = 0
            locking = false
            actionInProgress = false
        }
        generation += 1
        lastStatus = nil
        clearMetadata()
        pendingCount = 0
        proofWait = 0
        state = .connecting
        do {
            _ = try await client.call(Lock())
            state = .locked
            lockReason = "Locked by request"
        } catch { fail(error) }
    }

    func revoke(_ id: DaemonText) async {
        guard let client, !actionInProgress, state == .ready else { return }
        actionInProgress = true
        let captured = generation
        notice = nil
        defer { actionInProgress = false }
        do {
            let result = try await client.call(MetadataRequest.revoke(id))
            guard captured == generation, state == .ready else { return }
            await grants.refetch(.grants)
            guard captured == generation, state == .ready else { return }
            notice = grants.failure == nil
                ? (result.revoked > 0 ? "Revoked. The agent asks again on its next run." : "That grant has already ended.")
                : "The revoke completed, but grants could not be refreshed. Try again."
        } catch {
            guard captured == generation, state == .ready else { return }
            await grants.refetch(.grants)
            guard captured == generation, state == .ready else { return }
            notice = grants.failure == nil
                ? "The revoke outcome could not be confirmed. Grants have been refreshed."
                : "The revoke outcome could not be confirmed, and grants could not be refreshed. Wait for a fresh listing before retrying."
        }
    }

    func revokeAllGrants() async {
        guard let client, !actionInProgress, state == .ready else { return }
        actionInProgress = true
        let captured = generation
        notice = nil
        defer { actionInProgress = false }
        let ids = grants.rows.map(\.id)
        var revokedTotal: UInt64 = 0
        var hadError = false
        for id in ids {
            do {
                let res = try await client.call(MetadataRequest.revoke(id))
                revokedTotal += res.revoked
            } catch {
                hadError = true
            }
        }
        guard captured == generation, state == .ready else { return }
        await grants.refetch(.grants)
        guard captured == generation, state == .ready else { return }
        if hadError || grants.failure != nil {
            notice = "Some grants could not be confirmed revoked. Grants have been refreshed."
        } else {
            notice = revokedTotal > 0 ? "Revoked all grants. Agents ask again on their next run." : "No grants remained in force."
        }
    }

    func revokeStanding(_ id: DaemonText) async {
        guard let client, !actionInProgress, state == .ready else { return }
        actionInProgress = true
        let captured = generation
        notice = nil
        defer { actionInProgress = false }
        do {
            let result = try await client.call(MetadataRequest.standingRevoke(id))
            guard captured == generation, state == .ready else { return }
            await grants.refetch(.grants)
            guard captured == generation, state == .ready else { return }
            notice = grants.failure == nil
                ? (result.revoked > 0 ? "Standing approval revoked. The agent asks again on its next run." : "That standing approval has already ended.")
                : "The standing approval was revoked, but grants could not be refreshed. Try again."
        } catch {
            guard captured == generation, state == .ready else { return }
            await grants.refetch(.grants)
            guard captured == generation, state == .ready else { return }
            notice = grants.failure == nil
                ? "The standing revoke outcome could not be confirmed. Grants have been refreshed."
                : "The standing revoke outcome could not be confirmed, and grants could not be refreshed."
        }
    }

    @discardableResult
    func unlockWithTouchID() async -> Bool {
        guard let client, !actionInProgress else { return false }
        if sshSession {
            notice = "Touch ID cannot be used over SSH. Use envcloak unlock and envcloak approve in Terminal."
            return false
        }
        let key: any UnlockKeyAgreement = unlockKey ?? SecureEnclaveUnlockKey(keyStore: keyStore, contextFactory: contextFactory)
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            let begin = try await client.call(MetadataRequest.unlockBegin())
            let sealed = try await key.openAndReseal(begin, reason: ContextFactory.unlockReason)
            _ = try await client.call(MetadataRequest.unlockFinish(requestID: begin.request_id, sealed: sealed))
            notice = nil
            await poll()
            return state == .ready || state == .upgradeReadOnly
        } catch SEUnlockError.userCancelled, KeyStoreError.userCancelled {
            notice = "Unlock cancelled. The vault is still locked."
            return false
        } catch SEUnlockError.notInteractiveSession, KeyStoreError.notInteractiveSession {
            notice = "Touch ID cannot be used over SSH. Use envcloak unlock and envcloak approve in Terminal."
            return false
        } catch EnvCloakError.rpc(.noUnlocker, _) {
            enrolledTouchID = false
            notice = "Touch ID is not enrolled for this vault yet. Set up Touch ID first."
            return false
        } catch EnvCloakError.rpc(.tooManyAttempts, _) {
            notice = "Too many failed attempts. Try again later."
            return false
        } catch {
            notice = "Touch ID unlock could not be completed. You can also run envcloak unlock in Terminal."
            return false
        }
    }

    @discardableResult
    func beginEnrolment(touchIDOnly: Bool = false) async -> Bool {
        guard let client, !actionInProgress else { return false }
        if sshSession {
            notice = "Touch ID cannot be used over SSH. Use envcloak unlock and envcloak approve in Terminal."
            return false
        }
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            let unlockHex: String
            let approveHex: String
            if let overrideKeys = enrolledPublicKeysOverride {
                unlockHex = overrideKeys.unlockPublicKeyHex
                approveHex = overrideKeys.approvePublicKeyHex
            } else {
                let enrolled = try keyStore.loadOrCreatePublicKeys(touchIDOnly: touchIDOnly)
                unlockHex = enrolled.unlockPublicKeyHex
                approveHex = enrolled.approvePublicKeyHex
                unlockKey = SecureEnclaveUnlockKey(keyStore: keyStore, contextFactory: contextFactory)
                approvalSigner = SecureEnclaveApprovalSigner(keyStore: keyStore, contextFactory: contextFactory)
            }
            let output = try await client.call(MetadataRequest.enrollBegin(unlockPublicKeyHex: unlockHex, approvePublicKeyHex: approveHex))
            enrolmentPendingId = output.request
            enrolmentCommand = MetadataRequest.enrollApprovalCommand(request: output.request)?.display
            enrolmentCompleted = false
            notice = nil
            return true
        } catch {
            notice = "Touch ID enrolment could not be started. Unlock the vault in Terminal first."
            return false
        }
    }

    @discardableResult
    func pollEnrolment() async -> UnlockerEnrollState? {
        guard let client, let id = enrolmentPendingId else { return nil }
        do {
            let output = try await client.call(MetadataRequest.enrollPoll(id))
            switch output.state {
            case .enrolled:
                enrolledTouchID = true
                enrolmentCompleted = true
                enrolmentPendingId = nil
                notice = "Touch ID added."
            case .denied:
                enrolmentPendingId = nil
                notice = "Touch ID enrolment was denied in Terminal."
            case .expired:
                enrolmentPendingId = nil
                notice = "Touch ID enrolment expired. Start again when ready."
            case .pending:
                break
            }
            return output.state
        } catch {
            return nil
        }
    }

    func openApprovalWindow(for id: DaemonText? = nil) {
        activeApprovalRequestId = id ?? grants.pending.first?.request
        onOpenApprovalWindow?()
    }

    func fetchPendingDescriptor(_ id: DaemonText) async throws -> PendingDescriptor {
        guard let client else { throw EnvCloakError.daemonUnavailable }
        return try await client.call(MetadataRequest.pendingGet(id))
    }

    func submitSignedApproval(
        request: DaemonText,
        options: ApprovalOptions,
        digestHex: String,
        signatureHex: String
    ) async throws -> ApprovedView {
        guard let client else { throw EnvCloakError.daemonUnavailable }
        let output = try await client.call(
            MetadataRequest.approve(
                request: request,
                options: options,
                digestHex: digestHex,
                signatureHex: signatureHex
            )
        )
        await grants.refetch([.grants, .pending])
        await notifications.reconcile(
            pending: grants.pending,
            isFrontmost: isFrontmostOverride
        )
        return output
    }

    @discardableResult
    func denyPending(_ id: DaemonText) async -> Bool {
        guard let client, !actionInProgress, state == .ready else { return false }
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            _ = try await client.call(MetadataRequest.deny(id))
            await grants.refetch(.pending)
            await notifications.reconcile(
                pending: grants.pending,
                isFrontmost: isFrontmostOverride
            )
            return true
        } catch {
            await grants.refetch(.pending)
            return false
        }
    }

    var resolvedSigner: any ApprovalSigner {
        approvalSigner ?? SecureEnclaveApprovalSigner(keyStore: keyStore, contextFactory: contextFactory)
    }
}

