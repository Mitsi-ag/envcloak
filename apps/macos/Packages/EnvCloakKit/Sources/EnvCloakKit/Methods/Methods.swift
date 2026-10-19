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

public struct AppUnlockerEnrollBegin: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppUnlockerEnrollBeginView
    public static let name = "app.unlocker.enroll.begin"
    public let unlock_pub: String
    public let approve_pub: String
    public let label: String
    public let claims: [String]
    public init(unlock_pub: String, approve_pub: String, label: String, claims: [String] = []) {
        self.unlock_pub = unlock_pub
        self.approve_pub = approve_pub
        self.label = label
        self.claims = claims
    }
    public var description: String { "[app.unlocker.enroll.begin]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"unlock_pub\":"); try w.string(unlock_pub)
        try w.raw(",\"approve_pub\":"); try w.string(approve_pub)
        try w.raw(",\"label\":"); try w.string(label)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppUnlockerEnroll: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppUnlockerEnrollView
    public static let name = "app.unlocker.enroll"
    public let requestID: String
    public let claims: [String]
    public init(request: String, claims: [String] = []) {
        self.requestID = request
        self.claims = claims
    }
    public var description: String { "[app.unlocker.enroll]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request\":"); try w.string(requestID)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppUnlockBegin: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppUnlockBeginView
    public static let name = "app.unlock.begin"
    public let unlocker_id: String?
    public let claims: [String]
    public init(unlocker_id: String? = nil, claims: [String] = []) {
        self.unlocker_id = unlocker_id
        self.claims = claims
    }
    public var description: String { "[app.unlock.begin]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        var comma = false
        if let unlocker_id {
            try w.raw("\"unlocker_id\":"); try w.string(unlocker_id)
            comma = true
        }
        if !claims.isEmpty {
            if comma { try w.raw(",") }
            try w.raw("\"claims\":"); try w.strings(claims)
        }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppUnlock: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = UnlockedView
    public static let name = "app.unlock"
    public let request_id: String
    public let sealed: String
    public let claims: [String]
    public init(request_id: String, sealed: String, claims: [String] = []) {
        self.request_id = request_id
        self.sealed = sealed
        self.claims = claims
    }
    public var description: String { "[app.unlock]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request_id\":"); try w.string(request_id)
        try w.raw(",\"sealed\":"); try w.string(sealed)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppPendingList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppPendingListView
    public static let name = "app.pending.list"
    public let claims: [String]
    public init(claims: [String] = []) { self.claims = claims }
    public var description: String { "[app.pending.list]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        if !claims.isEmpty { try w.raw("\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppPendingGet: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = PendingDescriptor
    public static let name = "app.pending.get"
    public let requestID: String
    public let claims: [String]
    public init(request: String, claims: [String] = []) {
        self.requestID = request
        self.claims = claims
    }
    public var description: String { "[app.pending.get]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request\":"); try w.string(requestID)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppApprove: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = ApprovedView
    public static let name = "app.approve"
    public let requestID: String
    public let options: ApprovalOptions
    public let digest: String
    public let signature: String
    public let claims: [String]
    public init(request: String, options: ApprovalOptions, digest: String, signature: String, claims: [String] = []) {
        self.requestID = request
        self.options = options
        self.digest = digest
        self.signature = signature
        self.claims = claims
    }
    public var description: String { "[app.approve]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request\":"); try w.string(requestID)
        try w.raw(",\"options\":{\"uses\":"); try w.string(options.uses.rawValue)
        try w.raw(",\"ttl_secs\":" + String(options.ttl_secs) + ",\"live\":")
        try w.strings(options.live)
        if let standing = options.standing {
            try w.raw(",\"standing\":" + String(standing))
        }
        try w.raw("},\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct StandingList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = StandingListView
    public static let name = "standing.list"
    public init() {}
    public var description: String { "[standing.list]" }
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

public struct StandingRevoke: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = StandingRevokedView
    public static let name = "standing.revoke"
    public let id: String?
    public let agent: String?
    public let project: String?
    public let all: Bool
    public init(id: String? = nil, agent: String? = nil, project: String? = nil, all: Bool? = nil) {
        self.id = id
        self.agent = agent
        self.project = project
        self.all = all ?? (id == nil && agent == nil && project == nil)
    }
    public var description: String { "[standing.revoke]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        if let id = self.id { try w.raw("\"id\":"); try w.string(id); try w.raw(",") }
        if let agent { try w.raw("\"agent\":"); try w.string(agent); try w.raw(",") }
        if let project { try w.raw("\"project\":"); try w.string(project); try w.raw(",") }
        try w.raw("\"all\":" + (all ? "true" : "false"))
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct StandingConfirm: ~Copyable, DaemonMethod {
    public typealias Output = StandingConfirmedView
    public static let name = "standing.confirm"
    let digest: String
    let passphrase: SecretBuffer
    let claims: [String]
    public var description: String { "[standing.confirm]" }
    public var debugDescription: String { description }
    public init(digest: String, passphrase: consuming SecretBuffer, claims: [String] = []) {
        self.digest = digest
        self.passphrase = consume passphrase
        self.claims = claims
    }
    public borrowing func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"digest\":"); try w.string(digest)
        try w.raw(",\"passphrase\":")
        try w.secret(passphrase)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

