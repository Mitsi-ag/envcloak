import EnvCloakKit
import Foundation
import Observation

struct Change: OptionSet {
    let rawValue: Int
    static let items = Change(rawValue: 1)
    static let projects = Change(rawValue: 2)
    static let grants = Change(rawValue: 4)
    static let all: Change = [.items, .projects, .grants]
}

@MainActor protocol Store {
    func refetch(_ change: Change) async
}

@Observable @MainActor final class VaultSession {
    let items: ItemsStore
    let projects: ProjectsStore
    let grants: GrantsStore
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

    init(client: (any WorkspaceClient)?, folders: ProjectFolders? = nil) {
        self.client = client
        items = ItemsStore(client: client)
        projects = ProjectsStore(client: client, folders: folders)
        grants = GrantsStore(client: client)
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
        items.clear(); projects.clear(); grants.clear()
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
}
