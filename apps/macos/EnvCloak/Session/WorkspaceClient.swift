import EnvCloakKit

protocol WorkspaceClient: Sendable {
    func add(_ request: consuming ItemsAdd) async throws -> AddedView
    var socketPath: DaemonText? { get }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output
}

extension WorkspaceClient {
    var socketPath: DaemonText? { nil }
    func add(_ request: consuming ItemsAdd) async throws -> AddedView { throw EnvCloakError.protocolError }
}

struct SocketWorkspaceClient: WorkspaceClient {
    let client: DaemonClient
    func add(_ request: consuming ItemsAdd) async throws -> AddedView { try await client.call(consume request) }
    var socketPath: DaemonText? { client.socketPath }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        try await client.call(method)
    }
}
