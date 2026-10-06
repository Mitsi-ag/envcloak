/// One ordinary call and one lock control call may be open. A lock never
/// waits behind a hung poll. Each result belongs to a local generation;
/// cancellation/lock discards earlier completions, even if already queued.
public actor DaemonClient {
    private let directory: String
    private let timeout: Duration?
    private var serial: UInt64 = 0
    private var generation: UInt64 = 0
    private var busy = [false, false]
    private var waiting: [[CheckedContinuation<Void, Never>]] = [[], []]
    #if DEBUG
    var queueObserver: (@Sendable () -> Void)?
    #endif
    private var cancellations: [UInt64: @Sendable () -> Void] = [:]

    public init() throws(EnvCloakError) {
        do { directory = try UserPaths.runtime(); timeout = nil }
        catch let error as EnvCloakError { throw error }
        catch { throw .protocolError }
    }

    // The fixture path is deliberately not a public runtime override.
    init(directory: String, timeout: Duration? = .seconds(2)) {
        self.directory = directory; self.timeout = timeout
    }

    nonisolated static func methodTimeout(_ name: String) -> Duration {
        switch name {
        case "audit.verify", "backup.create": .seconds(300)
        default: .seconds(10)
        }
    }

    #if DEBUG
    func observeQueue(_ observer: @escaping @Sendable () -> Void) { queueObserver = observer }
    #endif

    public func cancelPending() {
        if generation < UInt64.max { generation += 1 }
        for cancel in cancellations.values { cancel() }
    }

    public func call<M: DaemonMethod & ~Copyable>(_ method: consuming M) async throws(EnvCloakError) -> M.Output {
        let slot = M.name == "lock" ? 1 : 0
        if slot == 1 { cancelPending() }
        let captured = generation
        if busy[slot] {
            await withCheckedContinuation {
                waiting[slot].append($0)
                #if DEBUG
                queueObserver?()
                #endif
            }
        }
        busy[slot] = true
        defer {
            if waiting[slot].isEmpty { busy[slot] = false }
            else { waiting[slot].removeFirst().resume() }
        }
        guard !Task.isCancelled, generation == captured, generation < UInt64.max, serial < UInt64.max else { throw .protocolError }
        serial += 1
        let id = serial
        let box = MethodBox(consume method)
        let directory = directory
        let timeout = timeout ?? Self.methodTimeout(M.name)
        let operation: @Sendable () throws -> M.Output = {
            let connection = try Connection(directory: directory, timeout: timeout)
            guard !Task.isCancelled else { throw EnvCloakError.protocolError }
            let request = try box.method.request(id: id)
            try request.write(using: connection.write)
            let response = try Frame.read(using: connection.read)
            let result = try M.response(response, id: id)
            #if DEBUG
            PeerProbe.hooks?.beforeResult()
            #endif
            try connection.checkDeadline()
            return result
        }
        #if DEBUG
        let hooks = PeerProbe.hooks
        let worker = Task.detached { try PeerProbe.$hooks.withValue(hooks, operation: operation) }
        #else
        let worker = Task.detached(operation: operation)
        #endif
        cancellations[id] = { worker.cancel() }
        defer { cancellations[id] = nil }
        do {
            let result = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: { worker.cancel() }
            guard !Task.isCancelled, captured == generation else { throw EnvCloakError.protocolError }
            return result
        } catch let error as EnvCloakError { throw error }
        catch { throw .protocolError }
    }
}

/// A Sendable box keeps a noncopyable method alive while the detached
/// worker borrows it. There is still exactly one SecretBuffer owner.
private final class MethodBox<M: DaemonMethod & ~Copyable>: Sendable {
    let method: M
    init(_ method: consuming M) { self.method = consume method }
}
