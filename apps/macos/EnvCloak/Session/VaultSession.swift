import CryptoKit
import EnvCloakKit
import Foundation
import Observation
import Security

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
    private let folders: ProjectFolders?
    var unlockKey: (any UnlockKeyAgreement)?
    var approvalSigner: (any ApprovalSigner)?
    var enrolledPublicKeysOverride: EnrolledPublicKeys?
    var enrolledTeamID: String
    var enrolledSigningID: String
    var enrolledUnlockerID: DaemonText?
    var enrolledUnlockerLabel = "This Mac"
    var enrolledTouchID = false
    var passphraseUnlockerRemoved = false
    var touchIDOnlyEnabled = false
    var showMenuBarExtra = false
    var enrolmentPendingId: DaemonText?
    var enrolmentCommand: String?
    var enrolmentCompleted = false
    var activeApprovalRequestId: DaemonText?
    var activeAsk: AskSummary?
    var activeRevealRequest: DaemonText?
    var selectedField: DaemonText?
    var onOpenApprovalWindow: (@MainActor () -> Void)?
    var onOpenPasteWindow: (@MainActor () -> Void)?
    var onOpenMainWindow: (@MainActor () -> Void)?
    var onFocusApprovals: (@MainActor () -> Void)?
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
    private(set) var appRequestsCount: UInt32 = 0
    private(set) var proofWait: UInt64 = 0

    static var defaultKeyStore: KeyStore {
        #if ENVCLOAK_SCREEN_TESTS
        KeyStore(storage: DataProtectionKeychainBlobStorage(enabled: false))
        #else
        KeyStore()
        #endif
    }

    static func readOwnSigningIdentity() -> (teamID: String, signingID: String) {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else {
            return ("CI00000000", "ai.envcloak.app")
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
            return ("CI00000000", "ai.envcloak.app")
        }
        var infoRef: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
              let info = infoRef as? [String: Any] else {
            return ("CI00000000", "ai.envcloak.app")
        }
        let teamID = (info[kSecCodeInfoTeamIdentifier as String] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "CI00000000"
        let signingID = (info[kSecCodeInfoIdentifier as String] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "ai.envcloak.app"
        if signingID.lowercased().contains("xctest") {
            return ("CI00000000", "ai.envcloak.app")
        }
        return (teamID, signingID)
    }

    var canSignInApp: Bool {
        enrolledTouchID && !sshSession
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
        enrolledTouchID: Bool? = nil,
        notifications: NotificationManager? = nil
    ) {
        self.client = client
        self.folders = folders
        self.contextFactory = contextFactory
        self.keyStore = keyStore
        self.unlockKey = unlockKey
        self.approvalSigner = approvalSigner
        self.enrolledPublicKeysOverride = enrolledPublicKeysOverride
        let ownIdentity = VaultSession.readOwnSigningIdentity()
        self.enrolledTeamID = ownIdentity.teamID
        self.enrolledSigningID = ownIdentity.signingID
        self.showMenuBarExtra = folders?.showMenuBarExtra ?? false
        let resolvedNotifications = notifications ?? NotificationManager()
        self.notifications = resolvedNotifications
        bindings = BindingHistory(runner: runner)
        items = ItemsStore(client: client)
        projects = ProjectsStore(client: client, folders: folders)
        grants = GrantsStore(client: client)
        if let enrolledTouchID {
            self.enrolledTouchID = enrolledTouchID
        } else if unlockKey != nil || approvalSigner != nil || keyStore.hasEnrolledKeys() {
            self.enrolledTouchID = true
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

    private var effectiveBiometryWording: BiometryWording {
        if clamshellClosed {
            return .password
        }
        if let override = contextFactory.wordingOverride {
            return override
        }
        if unlockKey != nil || approvalSigner != nil {
            return .touchID
        }
        #if ENVCLOAK_SCREEN_TESTS
        return .touchID
        #else
        return contextFactory.wording()
        #endif
    }

    var unlockButtonTitle: String {
        effectiveBiometryWording.unlockButtonTitle
    }

    var approveButtonTitle: String {
        effectiveBiometryWording.approveButtonTitle
    }

    var replaceButtonTitle: String {
        effectiveBiometryWording.replaceButtonTitle
    }

    var removeButtonTitle: String {
        effectiveBiometryWording.removeButtonTitle
    }

    var revealButtonTitle: String {
        effectiveBiometryWording.revealButtonTitle
    }

    func setShowMenuBarExtra(_ enabled: Bool) {
        showMenuBarExtra = enabled
        try? folders?.saveMenuBarExtra(enabled)
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
            case .sessionResign: "Locked when the user session switched"
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
                if status.approvals.pending != lastStatus?.approvals.pending
                    || status.app_requests != lastStatus?.app_requests {
                    change.insert(.pending)
                }
            }
            state = next
            pendingCount = next == .ready ? status.approvals.pending : 0
            appRequestsCount = next == .ready ? status.app_requests : 0
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
                    asksCount: grants.asks.count,
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
        selectedField = nil
        notifications.clear()
    }

    private func fail(_ error: any Error) {
        lastStatus = nil
        clearMetadata()
        pendingCount = 0
        appRequestsCount = 0
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
        if items.selectedSlug != slug {
            selectedField = nil
        }
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
            appRequestsCount = 0
            proofWait = 0
            locking = false
            actionInProgress = false
        }
        generation += 1
        lastStatus = nil
        clearMetadata()
        pendingCount = 0
        appRequestsCount = 0
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
            let begin = try await client.call(MetadataRequest.unlockBegin(unlockerID: enrolledUnlockerID))
            let sealed = try await key.openAndReseal(begin, reason: ContextFactory.unlockReason)
            _ = try await client.call(MetadataRequest.unlockFinish(requestID: begin.request_id, sealed: sealed))
            enrolledUnlockerID = begin.unlocker_id
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
                if let id = output.unlocker_id {
                    enrolledUnlockerID = id
                }
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

    func openPasteWindow(for ask: AskSummary? = nil) {
        activeAsk = ask
        onOpenPasteWindow?()
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
            asksCount: grants.asks.count,
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
                asksCount: grants.asks.count,
                isFrontmost: isFrontmostOverride
            )
            return true
        } catch {
            await grants.refetch(.pending)
            return false
        }
    }

    func beginPasteStage() async throws -> AppPasteBeginView {
        guard let client, state == .ready else { throw EnvCloakError.daemonUnavailable }
        return try await client.call(MetadataRequest.pasteBegin())
    }

    func inspectPasteStage(
        stage: DaemonText,
        secret: borrowing SecretBuffer,
        daemonEphPubHex: String
    ) async throws -> AppPasteInspectView {
        guard let client, state == .ready else { throw EnvCloakError.daemonUnavailable }
        let aad = Data(MetadataRequest.raw(stage).utf8)
        let sealedHex = try SEHPKE.sealSecretToX25519(
            secret,
            recipientPubHex: daemonEphPubHex,
            aad: aad
        )
        return try await client.call(
            MetadataRequest.pasteInspect(stage: stage, sealedHex: sealedHex)
        )
    }

    func commitPasteStage(
        stage: DaemonText,
        slug: String? = nil,
        provider: String? = nil,
        field: String? = nil,
        account: String? = nil,
        envHint: String? = nil,
        allowShort: Bool = false,
        ask: DaemonText? = nil
    ) async throws -> AddedView {
        guard let client, state == .ready, !actionInProgress else { throw EnvCloakError.daemonUnavailable }
        actionInProgress = true
        defer { actionInProgress = false }
        let captured = generation
        let added = try await client.call(
            MetadataRequest.pasteCommit(
                stage: stage,
                slug: slug,
                provider: provider,
                field: field,
                account: account,
                envHint: envHint,
                allowShort: allowShort,
                ask: ask
            )
        )
        guard captured == generation, state == .ready else { throw EnvCloakError.daemonUnavailable }
        await items.refetch(.items)
        if ask != nil {
            await grants.refetch(.pending)
            await notifications.reconcile(
                pending: grants.pending,
                asksCount: grants.asks.count,
                isFrontmost: isFrontmostOverride
            )
        }
        return added
    }

    @discardableResult
    func declineAsk(_ ask: DaemonText) async -> Bool {
        guard let client, state == .ready, !actionInProgress else { return false }
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            _ = try await client.call(MetadataRequest.asksDecline(ask))
            if activeAsk?.ask == ask {
                activeAsk = nil
            }
            await grants.refetch(.pending)
            await notifications.reconcile(
                pending: grants.pending,
                asksCount: grants.asks.count,
                isFrontmost: isFrontmostOverride
            )
            return true
        } catch {
            await grants.refetch(.pending)
            return false
        }
    }

    func fetchWriteTarget(slug: DaemonText, field: DaemonText? = nil) async throws -> AppItemsTargetView {
        guard let client, state == .ready else { throw EnvCloakError.daemonUnavailable }
        return try await client.call(MetadataRequest.itemsTarget(slug: slug, field: field))
    }

    func rotateItemWithTouchID(
        target: AppItemsTargetView,
        newValue: borrowing SecretBuffer
    ) async throws -> RotatedView {
        guard let client, state == .ready, !actionInProgress,
              let field = target.field, let fieldName = target.field_name else {
            throw EnvCloakError.daemonUnavailable
        }
        if sshSession {
            throw SignerError.notInteractiveSession
        }
        actionInProgress = true
        notice = nil
        defer { actionInProgress = false }

        let aad = try SEHPKE.resealAAD(
            requestID: MetadataRequest.raw(target.target),
            challengeHex: MetadataRequest.raw(target.nonce)
        )
        let sealedHex = try SEHPKE.sealSecretToX25519(
            newValue,
            recipientPubHex: MetadataRequest.raw(target.daemon_eph_pub),
            aad: aad
        )
        let newValueSHA256 = SEHPKE.secretSHA256Hex(newValue)
        let stmt = WriteStatement(
            target: MetadataRequest.raw(target.target),
            nonce: MetadataRequest.raw(target.nonce),
            vault_id: MetadataRequest.raw(target.vault_id),
            action: .rotate(
                item: MetadataRequest.raw(target.item),
                slug: MetadataRequest.raw(target.slug),
                field: MetadataRequest.raw(field),
                field_name: MetadataRequest.raw(fieldName),
                classification: target.classification.rawValue,
                prior_count: target.prior_count,
                grants: target.grants,
                new_value_sha256: newValueSHA256
            )
        )
        let stmtBytes = CanonicalStatement.encodeWrite(stmt)
        let digestHex = CanonicalStatement.writeDigestHex(stmt)
        let reason = ContextFactory.replaceReason(
            slug: target.slug.escaped,
            field: fieldName.escaped
        )
        let signature = try await resolvedSigner.sign(stmtBytes, reason: reason)
        let rotated = try await client.call(
            MetadataRequest.itemsRotate(
                target: target.target,
                sealedValueHex: sealedHex,
                digestHex: digestHex,
                signatureHex: signature.hex
            )
        )
        await items.refetch(.items)
        await grants.refetch(.grants)
        return rotated
    }

    func removeItemWithTouchID(target: AppItemsTargetView) async throws -> RemovedView {
        guard let client, state == .ready, !actionInProgress else {
            throw EnvCloakError.daemonUnavailable
        }
        if sshSession {
            throw SignerError.notInteractiveSession
        }
        actionInProgress = true
        notice = nil
        defer { actionInProgress = false }

        let stmt = WriteStatement(
            target: MetadataRequest.raw(target.target),
            nonce: MetadataRequest.raw(target.nonce),
            vault_id: MetadataRequest.raw(target.vault_id),
            action: .remove(
                item: MetadataRequest.raw(target.item),
                slug: MetadataRequest.raw(target.slug),
                grants: target.grants
            )
        )
        let stmtBytes = CanonicalStatement.encodeWrite(stmt)
        let digestHex = CanonicalStatement.writeDigestHex(stmt)
        let reason = ContextFactory.removeReason(slug: target.slug.escaped)
        let signature = try await resolvedSigner.sign(stmtBytes, reason: reason)
        let removed = try await client.call(
            MetadataRequest.itemsRemove(
                target: target.target,
                digestHex: digestHex,
                signatureHex: signature.hex
            )
        )
        if items.selectedSlug == target.slug {
            await items.select(nil)
        }
        await items.refetch(.items)
        await projects.refetch(.projects)
        await grants.refetch([.grants, .pending])
        return removed
    }

    func beginReveal(slug: DaemonText, field: DaemonText? = nil) async throws -> RevealDescriptor {
        guard let client, state == .ready else { throw EnvCloakError.daemonUnavailable }
        return try await client.call(MetadataRequest.revealBegin(slug: slug, field: field))
    }

    func beginClientReveal(request: DaemonText) async throws -> RevealDescriptor {
        guard let client, state == .ready else { throw EnvCloakError.daemonUnavailable }
        return try await client.call(MetadataRequest.revealBegin(request: request))
    }

    func completeRevealWithTouchID(descriptor: RevealDescriptor) async throws -> SecretBuffer {
        guard let client, state == .ready, !actionInProgress else {
            throw EnvCloakError.daemonUnavailable
        }
        if sshSession {
            throw SignerError.notInteractiveSession
        }
        actionInProgress = true
        notice = nil
        defer { actionInProgress = false }

        let appEphKey = Curve25519.KeyAgreement.PrivateKey()
        let appEphPubHex = HexCoding.encode(appEphKey.publicKey.rawRepresentation)
        var signedDescriptor = descriptor
        signedDescriptor.app_eph_pub = DaemonText(appEphPubHex)
        let stmtBytes = CanonicalStatement.encodeReveal(signedDescriptor)
        let digestHex = CanonicalStatement.revealDigestHex(signedDescriptor)
        let reason = ContextFactory.revealReason(
            slug: descriptor.slug.escaped,
            field: descriptor.field_name.escaped
        )
        let signature = try await resolvedSigner.sign(stmtBytes, reason: reason)
        let out = try await client.call(
            MetadataRequest.revealFinish(
                request: descriptor.request,
                digestHex: digestHex,
                signatureHex: signature.hex,
                appEphPubHex: appEphPubHex
            )
        )
        let aad = try SEHPKE.revealAAD(
            requestID: MetadataRequest.raw(descriptor.request),
            challengeHex: MetadataRequest.raw(descriptor.nonce),
            appEphPubHex: appEphPubHex
        )
        return try SEHPKE.openSecretFromX25519(
            sealedHex: MetadataRequest.raw(out.sealed_value),
            privateKey: appEphKey,
            aad: aad
        )
    }

    @discardableResult
    func removePassphraseUnlockerWithTouchID() async -> Bool {
        guard let client, state == .ready, !actionInProgress else { return false }
        if sshSession {
            notice = "Touch ID cannot be used over SSH."
            return false
        }
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            let target = try await client.call(MetadataRequest.itemsTargetUnlockerRemove())
            let stmt = WriteStatement(
                target: "unlocker_remove",
                nonce: MetadataRequest.raw(target.nonce),
                vault_id: MetadataRequest.raw(target.vault_id),
                action: .unlockerRemove(unlocker: .passphrase)
            )
            let stmtBytes = CanonicalStatement.encodeWrite(stmt)
            let digestHex = CanonicalStatement.writeDigestHex(stmt)
            let signature = try await resolvedSigner.sign(
                stmtBytes,
                reason: ContextFactory.unlockerRemoveReason(target: "passphrase")
            )
            _ = try await client.call(
                MetadataRequest.unlockerRemove(
                    unlocker: "passphrase",
                    createdSecs: target.created_secs,
                    nonceHex: MetadataRequest.raw(target.nonce),
                    digestHex: digestHex,
                    signatureHex: signature.hex
                )
            )
            passphraseUnlockerRemoved = true
            notice = "Passphrase unlocker removed. Touch ID and your Recovery Kit remain."
            return true
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            notice = "Passphrase removal cancelled."
            return false
        } catch {
            notice = "The passphrase unlocker could not be removed. Keep at least one Touch ID unlocker enrolled."
            return false
        }
    }

    @discardableResult
    func enrollTouchIDOnlyUnlocker(label: String = "This Mac (Touch ID only)") async -> Bool {
        guard let client, state == .ready, !actionInProgress else { return false }
        if sshSession {
            notice = "Touch ID cannot be used over SSH."
            return false
        }
        actionInProgress = true
        defer { actionInProgress = false }
        do {
            let priorKeys: EnrolledPublicKeys? = enrolledPublicKeysOverride
                ?? (keyStore.hasEnrolledKeys() ? (try? keyStore.loadOrCreatePublicKeys(touchIDOnly: false)) : nil)
            let target = try await client.call(MetadataRequest.itemsTargetUnlockerAdd())
            let unlockHex: String
            let approveHex: String
            var stagedPair: KeyStore.StagedKeyPair?
            if let overrideKeys = enrolledPublicKeysOverride {
                unlockHex = overrideKeys.unlockPublicKeyHex
                approveHex = overrideKeys.approvePublicKeyHex
            } else {
                let staged = try keyStore.stageNewPublicKeys(touchIDOnly: true)
                unlockHex = staged.keys.unlockPublicKeyHex
                approveHex = staged.keys.approvePublicKeyHex
                stagedPair = staged
            }
            let unlockFP = try SEHPKE.p256FingerprintHex(unlockHex)
            let approveFP = try SEHPKE.p256FingerprintHex(approveHex)
            let stmt = WriteStatement(
                target: "unlocker_add",
                nonce: MetadataRequest.raw(target.nonce),
                vault_id: MetadataRequest.raw(target.vault_id),
                action: .unlockerAdd(
                    label: label,
                    unlock_pub_sha256: unlockFP,
                    approve_pub_sha256: approveFP,
                    team_id: enrolledTeamID,
                    signing_id: enrolledSigningID
                )
            )
            let stmtBytes = CanonicalStatement.encodeWrite(stmt)
            let digestHex = CanonicalStatement.writeDigestHex(stmt)
            let signature = try await resolvedSigner.sign(
                stmtBytes,
                reason: ContextFactory.unlockerAddReason(label: label)
            )
            let added = try await client.call(
                MetadataRequest.unlockerAdd(
                    unlockPublicKeyHex: unlockHex,
                    approvePublicKeyHex: approveHex,
                    label: label,
                    createdSecs: target.created_secs,
                    nonceHex: MetadataRequest.raw(target.nonce),
                    digestHex: digestHex,
                    signatureHex: signature.hex
                )
            )
            if let priorID = enrolledUnlockerID, let priorKeys {
                let priorUnlockFP = try SEHPKE.p256FingerprintHex(priorKeys.unlockPublicKeyHex)
                let priorApproveFP = try SEHPKE.p256FingerprintHex(priorKeys.approvePublicKeyHex)
                let removeTarget = try await client.call(MetadataRequest.itemsTargetUnlockerRemove())
                let removeStmt = WriteStatement(
                    target: "unlocker_remove",
                    nonce: MetadataRequest.raw(removeTarget.nonce),
                    vault_id: MetadataRequest.raw(removeTarget.vault_id),
                    action: .unlockerRemove(
                        unlocker: .secureEnclave(
                            unlocker_id: MetadataRequest.raw(priorID),
                            label: enrolledUnlockerLabel,
                            unlock_pub_sha256: priorUnlockFP,
                            approve_pub_sha256: priorApproveFP
                        )
                    )
                )
                let removeBytes = CanonicalStatement.encodeWrite(removeStmt)
                let removeDigestHex = CanonicalStatement.writeDigestHex(removeStmt)
                let removeSig = try await resolvedSigner.sign(
                    removeBytes,
                    reason: ContextFactory.unlockerRemoveReason(target: enrolledUnlockerLabel)
                )
                _ = try await client.call(
                    MetadataRequest.unlockerRemove(
                        unlocker: MetadataRequest.raw(priorID),
                        createdSecs: removeTarget.created_secs,
                        nonceHex: MetadataRequest.raw(removeTarget.nonce),
                        digestHex: removeDigestHex,
                        signatureHex: removeSig.hex
                    )
                )
            }
            if let stagedPair {
                try keyStore.commitStagedKeys(stagedPair)
            }
            enrolledUnlockerID = added.unlocker_id
            enrolledUnlockerLabel = label
            touchIDOnlyEnabled = true
            enrolledTouchID = true
            notice = "Touch ID is now required. Your login password will no longer approve."
            return true
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            notice = "Touch ID only enrolment cancelled."
            return false
        } catch {
            notice = "Touch ID only unlocker could not be added."
            return false
        }
    }

    var resolvedSigner: any ApprovalSigner {
        approvalSigner ?? SecureEnclaveApprovalSigner(keyStore: keyStore, contextFactory: contextFactory)
    }
}

