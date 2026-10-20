import EnvCloakKit
import Foundation
import Observation

@Observable @MainActor final class GrantsStore: Store {
    private let client: (any WorkspaceClient)?
    private var revision = 0
    private var dirty = true
    private var fetchedAt = ContinuousClock.now
    private var standingFetchedAt = ContinuousClock.now
    private var pendingFetchedAt = ContinuousClock.now
    private var asksFetchedAt = ContinuousClock.now
    private(set) var rows: [GrantView] = []
    private(set) var standing: [StandingView] = []
    private(set) var policyEpochUnverified = false
    private(set) var pending: [AppPendingView] = []
    private(set) var asks: [AskSummary] = []
    private(set) var failure: EnvCloakError?
    private(set) var pendingFailure: EnvCloakError?

    init(client: (any WorkspaceClient)?) {
        self.client = client
    }

    func clear() {
        revision += 1
        rows = []
        standing = []
        policyEpochUnverified = false
        pending = []
        asks = []
        failure = nil
        pendingFailure = nil
        dirty = true
    }

    func remaining(_ grant: GrantView) -> UInt64 {
        let elapsed = fetchedAt.duration(to: .now).components.seconds
        let seconds = UInt64(max(0, elapsed))
        return grant.remaining_secs > seconds ? grant.remaining_secs - seconds : 0
    }

    func remainingStanding(_ record: StandingView) -> UInt64 {
        let elapsed = standingFetchedAt.duration(to: .now).components.seconds
        let seconds = UInt64(max(0, elapsed))
        return record.remaining_secs > seconds ? record.remaining_secs - seconds : 0
    }

    func remainingPending(_ item: AppPendingView) -> UInt64 {
        let elapsed = pendingFetchedAt.duration(to: .now).components.seconds
        let seconds = UInt64(max(0, elapsed))
        return item.expires_in_secs > seconds ? item.expires_in_secs - seconds : 0
    }

    func remainingAsk(_ item: AskSummary) -> UInt64 {
        let elapsed = asksFetchedAt.duration(to: .now).components.seconds
        let seconds = UInt64(max(0, elapsed))
        return item.expires_in_secs > seconds ? item.expires_in_secs - seconds : 0
    }

    func refetch(_ change: Change) async {
        guard let client else { return }
        let captured = revision
        if change.contains(.grants) || dirty {
            let requestedAt = ContinuousClock.now
            do {
                let result = try await client.call(GrantsList())
                guard captured == revision, !Task.isCancelled else { return }
                rows = result.grants
                fetchedAt = requestedAt
                failure = nil
                dirty = false
            } catch {
                guard captured == revision else { return }
                rows = []
                failure = error as? EnvCloakError ?? .protocolError
                dirty = true
                return
            }

            let standingRequestedAt = ContinuousClock.now
            do {
                let standingResult = try await client.call(StandingList())
                guard captured == revision, !Task.isCancelled else { return }
                standing = standingResult.standing
                policyEpochUnverified = standingResult.policy_epoch_unverified
                standingFetchedAt = standingRequestedAt
            } catch let error as EnvCloakError {
                guard captured == revision else { return }
                switch error {
                case .daemonUnavailable, .daemonUnverified, .rpc(.vaultLocked, _), .rpc(.vaultTampered, _):
                    standing = []
                    failure = error
                    return
                default:
                    break
                }
            } catch {}
        }

        if change.contains(.pending) {
            let pendingRequestedAt = ContinuousClock.now
            do {
                let pendingResult = try await client.call(AppPendingList())
                guard captured == revision, !Task.isCancelled else { return }
                pending = pendingResult.requests
                pendingFetchedAt = pendingRequestedAt
                pendingFailure = nil
            } catch let error as EnvCloakError {
                guard captured == revision else { return }
                pendingFailure = error
                switch error {
                case .daemonUnavailable, .daemonUnverified, .rpc(.vaultLocked, _), .rpc(.vaultTampered, _):
                    pending = []
                    failure = error
                default:
                    break
                }
            } catch {
                guard captured == revision else { return }
                pendingFailure = .protocolError
            }

            let asksRequestedAt = ContinuousClock.now
            do {
                let asksResult = try await client.call(AppAsksList())
                guard captured == revision, !Task.isCancelled else { return }
                asks = asksResult.asks
                asksFetchedAt = asksRequestedAt
            } catch let error as EnvCloakError {
                guard captured == revision else { return }
                switch error {
                case .daemonUnavailable, .daemonUnverified, .rpc(.vaultLocked, _), .rpc(.vaultTampered, _):
                    asks = []
                    failure = error
                default:
                    break
                }
            } catch {}
        }
    }
}
