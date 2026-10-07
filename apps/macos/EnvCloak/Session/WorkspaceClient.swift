import EnvCloakKit

protocol WorkspaceClient: Sendable {
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output
}

struct SocketWorkspaceClient: WorkspaceClient {
    let client: DaemonClient
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        try await client.call(method)
    }
}
