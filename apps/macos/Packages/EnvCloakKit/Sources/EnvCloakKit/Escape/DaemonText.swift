/// Untrusted metadata. Views use `escaped`; taking the original for a
/// subsequent request requires the daemon-text source allowlist.
public struct DaemonText: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible, WireDecodable {
    private let raw: String
    public init(_ metadata: String) { raw = metadata }
    init(wire: WireReader) throws { raw = try wire.string() }
    public var escaped: String { Escape.display(raw) }
    public var unescaped: String { raw }
    public var description: String { "[daemon text]" }
    public var debugDescription: String { description }
}
