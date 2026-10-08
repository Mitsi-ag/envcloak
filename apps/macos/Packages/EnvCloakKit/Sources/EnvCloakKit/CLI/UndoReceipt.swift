import Foundation

/// Private in-memory source bytes. UndoManager holds an action id only.
/// A failed or uncertain child never leaves a receipt advertised as ready.
public final class UndoReceipt: @unchecked Sendable, CustomStringConvertible {
    static let limit = 2 * 65_536 + 1024
    private let lock = NSLock()
    private var bytes: SecretBuffer
    private var ready = false
    public var description: String { "[private undo receipt]" }
    init() throws { bytes = try SecretBuffer() }
    public var available: Bool { lock.withLock { ready } }

    func use<T>(restoring: Bool, _ body: (inout SecretBuffer) throws -> T) throws -> T {
        try lock.withLock {
            guard !restoring || ready else { throw CLIError.invalidArguments }
            ready = false
            do {
                let result = try body(&bytes)
                ready = !restoring && bytes.count > 0
                if restoring { bytes = try SecretBuffer() }
                return result
            } catch {
                bytes = try SecretBuffer()
                throw error
            }
        }
    }
}
