/// Unique ownership of the value until the call ends. Metadata alone may
/// be a String. Encoding runs only after the new connection is verified.
public struct ItemsAdd: ~Copyable, DaemonMethod {
    public typealias Output = AddedView
    public static let name = "items.add"
    let value: SecretBuffer
    let slug: String?
    let provider: String?
    let field: String?
    let account: String?
    let envHint: String?
    let allowShort: Bool
    public var description: String { "[items.add]" }
    public var debugDescription: String { description }

    public init(value: consuming SecretBuffer, slug: String? = nil, provider: String? = nil,
                field: String? = nil, account: String? = nil, envHint: String? = nil, allowShort: Bool = false) {
        self.value = consume value
        self.slug = slug; self.provider = provider; self.field = field
        self.account = account; self.envHint = envHint; self.allowShort = allowShort
    }
    public borrowing func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        for (key, value) in [("slug", slug), ("provider", provider), ("field", field), ("account", account), ("env_hint", envHint)] {
            if let value { try w.string(key); try w.raw(":"); try w.string(value); try w.raw(",") }
        }
        try w.raw("\"allow_short\":" + (allowShort ? "true" : "false") + ",\"value\":")
        try w.secret(value)
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}
