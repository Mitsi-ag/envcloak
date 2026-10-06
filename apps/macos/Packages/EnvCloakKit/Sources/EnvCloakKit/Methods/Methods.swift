// EU-1 client-role calls. Each call opens and verifies a fresh connection.

public struct Status: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = StatusView
    public static let name = "status"
    public init() {}
    public var description: String { "[status]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)

        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct Lock: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = LockedView
    public static let name = "lock"
    public init() {}
    public var description: String { "[lock]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)

        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct ItemsList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = ItemsView
    public static let name = "items.list"
    public let long: Bool
    public init(long: Bool = false) { self.long = long }
    public var description: String { "[items.list]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"long\":" + (long ? "true" : "false"))
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct ItemsShow: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = ItemView
    public static let name = "items.show"
    public let slug: String
    public init(slug: String) { self.slug = slug }
    public var description: String { "[items.show]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"slug\":"); try w.string(slug)
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct ItemsCheck: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = CheckView
    public static let name = "items.check"
    public let manifest: String?
    public let refs: [String]
    public init(manifest: String? = nil, refs: [String] = []) { self.manifest = manifest; self.refs = refs }
    public var description: String { "[items.check]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        if let manifest { try w.raw("\"manifest\":"); try w.string(manifest); try w.raw(",") }
        try w.raw("\"refs\":"); try w.strings(refs)
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct GrantsList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = GrantsView
    public static let name = "grants.list"
    public init() {}
    public var description: String { "[grants.list]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)

        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct GrantsRevoke: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = RevokedView
    public static let name = "grants.revoke"
    public let grant: String?
    public init(grant: String? = nil) { self.grant = grant }
    public var description: String { "[grants.revoke]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        if let grant { try w.raw("\"grant\":"); try w.string(grant); try w.raw(",") }
        try w.raw("\"all\":" + (grant == nil ? "true" : "false"))
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct Deny: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = DeniedView
    public static let name = "deny"
    public let requestID: String
    public init(request: String) { self.requestID = request }
    public var description: String { "[deny]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request\":"); try w.string(requestID)
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AuditVerify: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AuditVerifyView
    public static let name = "audit.verify"
    public init() {}
    public var description: String { "[audit.verify]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)

        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct BackupCreate: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = BackupView
    public static let name = "backup.create"
    public init() {}
    public var description: String { "[backup.create]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)

        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}
