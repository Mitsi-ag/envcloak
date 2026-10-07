import EnvCloakKit

protocol WorkspaceClient: Sendable {
    var socketPath: DaemonText? { get }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output
}

extension WorkspaceClient { var socketPath: DaemonText? { nil } }

struct SocketWorkspaceClient: WorkspaceClient {
    let client: DaemonClient
    var socketPath: DaemonText? { client.socketPath }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        try await client.call(method)
    }
}
