import EnvCloakKit
import Foundation
import Observation

@Observable @MainActor final class GrantsStore: Store {
    private let client: (any WorkspaceClient)?
    private var revision = 0
    private var dirty = true
    private var fetchedAt = ContinuousClock.now
    private(set) var rows: [GrantView] = []
    private(set) var failure: EnvCloakError?
    init(client: (any WorkspaceClient)?) { self.client = client }
    func clear() { revision += 1; rows = []; failure = nil; dirty = true }
    func remaining(_ grant: GrantView) -> UInt64 {
        let elapsed = fetchedAt.duration(to: .now).components.seconds
        let seconds = UInt64(max(0, elapsed))
        return grant.remaining_secs > seconds ? grant.remaining_secs - seconds : 0
    }
    func refetch(_ change: Change) async {
        guard change.contains(.grants) || dirty, let client else { return }
        let captured = revision
        let requestedAt = ContinuousClock.now
        do {
            let result = try await client.call(GrantsList())
            guard captured == revision, !Task.isCancelled else { return }
            rows = result.grants; fetchedAt = requestedAt; failure = nil; dirty = false
        } catch {
            guard captured == revision else { return }
            rows = []; failure = error as? EnvCloakError ?? .protocolError; dirty = true
        }
    }
}
