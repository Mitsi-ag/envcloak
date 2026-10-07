import EnvCloakKit
import Observation

@Observable @MainActor final class ItemsStore: Store {
    private let client: (any WorkspaceClient)?
    private var revision = 0
    private var dirty = true
    private(set) var rows: [ItemView] = []
    private(set) var failure: EnvCloakError?
    init(client: (any WorkspaceClient)?) { self.client = client }
    func clear() { revision += 1; rows = []; failure = nil; dirty = true }
    func refetch(_ change: Change) async {
        guard change.contains(.items) || dirty, let client else { return }
        let captured = revision
        do {
            let result = try await client.call(ItemsList(long: true))
            guard captured == revision, !Task.isCancelled else { return }
            var ids = Set<DaemonText>()
            guard result.items.allSatisfy({ ids.insert($0.id).inserted }) else { throw EnvCloakError.protocolError }
            rows = result.items; failure = nil; dirty = false
        } catch {
            guard captured == revision else { return }
            rows = []; failure = error as? EnvCloakError ?? .protocolError; dirty = true
        }
    }
}
