import EnvCloakKit
import Foundation
import Observation

struct OpenedProject {
    let directory: DaemonText
    let check: CheckView
    var grantDirectory: DaemonText? { check.project_dir }
    var title: String { check.project_name?.escaped ?? MetadataRequest.basename(directory) }
    var profiles: [String] { Array(Set(check.bindings.compactMap { $0.profile?.escaped })).sorted() }
    func bindings(profile: String?) -> [CheckBindingView] {
        let selected = check.bindings.filter { $0.profile?.escaped == profile }
        guard profile != nil else { return selected }
        let names = Set(selected.compactMap(\.env_name))
        return (selected + check.bindings.filter { $0.profile == nil && !names.contains($0.env_name ?? DaemonText("")) })
            .sorted { ($0.env_name?.escaped ?? "") < ($1.env_name?.escaped ?? "") }
    }
}

struct ProjectInventoryRow: Identifiable {
    let id: Int
    let directory: DaemonText?
    let bindings: Int?
    static let hiddenPathMessage = "Folder path hidden: it looks like a key or token"
}

@Observable @MainActor final class ProjectsStore: Store {
    private let client: (any WorkspaceClient)?
    private let folders: ProjectFolders?
    private var revision = 0
    private var openRevision = 0
    private var manifestSignal: ManifestSignal?
    private var dirty = true
    private(set) var scope: DaemonText?
    private(set) var rows: [ProjectView] = []
    private(set) var added: [DaemonText]
    private(set) var opened: OpenedProject?
    private(set) var openedDirectory: DaemonText?
    private(set) var failure: EnvCloakError?
    private(set) var checkFailure: EnvCloakError?
    var manifestMissing: Bool { manifestSignal?.fileMissing == true }
    init(client: (any WorkspaceClient)?, folders: ProjectFolders?) {
        self.client = client; self.folders = folders; added = folders?.paths ?? []; scope = folders?.scope
    }
    var scopeDirectories: [DaemonText] { rows.map(\.dir).filter { MetadataRequest.directoryURL($0) != nil } }
    func setScope(_ scope: DaemonText?) throws {
        guard let folders else { throw EnvCloakError.protocolError }
        try folders.saveScope(scope)
        self.scope = scope
    }
    var directories: [DaemonText] {
        var result = rows.map(\.dir).filter { MetadataRequest.directoryURL($0) != nil }
        for path in added where !result.contains(path) { result.append(path) }
        return result
    }
    var inventory: [ProjectInventoryRow] {
        var result = rows.enumerated().map { index, row in
            ProjectInventoryRow(id: index, directory: MetadataRequest.directoryURL(row.dir) == nil ? nil : row.dir, bindings: row.bindings.count)
        }
        for path in added where !rows.contains(where: { $0.dir == path }) {
            result.append(ProjectInventoryRow(id: result.count, directory: path, bindings: nil))
        }
        return result
    }
    func title(_ directory: DaemonText) -> String {
        opened?.directory == directory ? opened!.title : MetadataRequest.basename(directory)
    }
    func canonicalDirectory(_ directory: DaemonText) -> DaemonText? {
        opened?.directory == directory ? opened!.check.project_dir : directory
    }
    func clear() {
        revision += 1; openRevision += 1; manifestSignal = nil; rows = []; opened = nil
        failure = nil; checkFailure = nil; dirty = true
    }
    func add(_ url: URL) throws {
        guard url.isFileURL, url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw EnvCloakError.protocolError }
        let path = DaemonText(url.path)
        if !added.contains(path) {
            guard let folders else { throw EnvCloakError.protocolError }
            try folders.save(added + [path])
            added.append(path)
        }
    }
    func refetch(_ change: Change) async {
        guard change.contains(.projects) || dirty, let client else { return }
        let captured = revision
        do {
            var next: ProjectCursor?
            var result: [ProjectView] = []
            var receivedBytes = 0
            let deadline = ContinuousClock.now.advanced(by: .seconds(30))
            var directories = Set<DaemonText>()
            repeat {
                let page = try await client.call(ProjectsList(after: next))
                receivedBytes += page.wireByteCount
                guard receivedBytes <= 16 * 1_048_576, ContinuousClock.now < deadline else {
                    throw EnvCloakError.rpc(.frameTooLarge, nil)
                }
                guard captured == revision, !Task.isCancelled else { return }
                if let cursor = page.next {
                    guard !page.projects.isEmpty, next.map({ cursor.precedes($0) }) ?? true else { throw EnvCloakError.protocolError }
                }
                for row in page.projects {
                    if row.dir != DaemonText("[not shown: looks like a key or token]") {
                        guard MetadataRequest.directoryURL(row.dir) != nil, directories.insert(row.dir).inserted else { throw EnvCloakError.protocolError }
                    }
                    result.append(row)
                }
                // Refuse oversized inventories explicitly; never publish a partial page set.
                guard result.count <= 100_000 else { throw EnvCloakError.protocolError }
                next = page.next
            } while next != nil
            rows = result; failure = nil; dirty = false
            if let scope, !scopeDirectories.contains(scope) { try setScope(nil) }
            if let openedDirectory { await open(openedDirectory) }
        } catch {
            guard captured == revision else { return }
            rows = []; opened = nil; failure = error as? EnvCloakError ?? .protocolError; dirty = true
        }
    }
    func refreshOpenIfChanged() async {
        guard let directory = openedDirectory, let url = MetadataRequest.directoryURL(directory),
              ManifestSignal(directory: url) != manifestSignal else { return }
        await open(directory)
    }
    func open(_ directory: DaemonText) async {
        guard let client else { return }
        openRevision += 1
        guard let url = MetadataRequest.directoryURL(directory) else {
            opened = nil; checkFailure = .protocolError; return
        }
        manifestSignal = ManifestSignal(directory: url)
        let captured = openRevision
        openedDirectory = directory; opened = nil; checkFailure = nil
        do {
            let check = try await client.call(MetadataRequest.check(directory))
            guard captured == openRevision, !Task.isCancelled else { return }
            opened = OpenedProject(directory: directory, check: check)
        } catch {
            guard captured == openRevision else { return }
            checkFailure = error as? EnvCloakError ?? .protocolError
        }
    }
}
