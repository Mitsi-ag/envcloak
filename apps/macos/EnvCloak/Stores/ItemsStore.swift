import EnvCloakKit
import Observation

@Observable @MainActor final class ItemsStore: Store {
    private let client: (any WorkspaceClient)?
    private var revision = 0
    private var dirty = true
    private var selectionRevision = 0
    private(set) var selectedSlug: DaemonText?
    private(set) var selectedItem: ItemView?
    private(set) var detailFailure: EnvCloakError?
    private(set) var rows: [ItemView] = []
    private(set) var failure: EnvCloakError?
    init(client: (any WorkspaceClient)?) { self.client = client }
    func clear() {
        revision += 1; rows = []; failure = nil; dirty = true
        selectedSlug = nil; clearDetail()
    }
    private func clearDetail() {
        selectionRevision += 1; selectedItem = nil; detailFailure = nil
    }
    func select(_ slug: DaemonText?) async {
        if selectedSlug == slug, selectedItem != nil { return }
        selectedSlug = slug; clearDetail()
        guard let slug, let client, let summary = rows.first(where: { $0.slug == slug }) else { return }
        let captured = selectionRevision
        do {
            let item = try await client.call(MetadataRequest.show(slug))
            guard captured == selectionRevision, !Task.isCancelled else { return }
            guard item.id == summary.id, item.slug == slug, item.detail != nil else { throw EnvCloakError.protocolError }
            selectedItem = item
        } catch {
            guard captured == selectionRevision, !Task.isCancelled else { return }
            detailFailure = error as? EnvCloakError ?? .protocolError
        }
    }
    func refetch(_ change: Change) async {
        guard change.contains(.items) || dirty, let client else { return }
        let captured = revision
        clearDetail()
        do {
            let result = try await client.call(ItemsList(long: true))
            guard captured == revision, !Task.isCancelled else { return }
            var ids = Set<DaemonText>()
            guard result.items.allSatisfy({ ids.insert($0.id).inserted }) else { throw EnvCloakError.protocolError }
            rows = result.items; failure = nil; dirty = false
            await select(selectedSlug)
        } catch {
            guard captured == revision else { return }
            rows = []; failure = error as? EnvCloakError ?? .protocolError; dirty = true
        }
    }
}
