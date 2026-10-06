public protocol DaemonMethod: ~Copyable, Sendable {
    associatedtype Output: Sendable
    static var name: String { get }
    borrowing func request(id: UInt64) throws -> Frame
    static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output
}

func requestWriter(id: UInt64, name: String) throws -> WireWriter {
    var writer = try WireWriter()
    try writer.raw("{\"jsonrpc\":\"2.0\",\"id\":" + String(id) + ",\"method\":")
    try writer.string(name)
    try writer.raw(",\"params\":{")
    return writer
}
