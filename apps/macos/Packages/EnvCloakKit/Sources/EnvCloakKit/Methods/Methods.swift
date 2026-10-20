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

public struct AppItemsTarget: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppItemsTargetView
    public static let name = "app.items.target"
    public let slug: String
    public let field: String?
    public let claims: [String]
    public init(slug: String, field: String? = nil, claims: [String] = []) {
        self.slug = slug
        self.field = field
        self.claims = claims
    }
    public var description: String { "[app.items.target]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"slug\":"); try w.string(slug)
        if let field { try w.raw(",\"field\":"); try w.string(field) }
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppItemsRotate: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = RotatedView
    public static let name = "app.items.rotate"
    public let target: String
    public let sealed_value: String
    public let digest: String
    public let signature: String
    public let claims: [String]
    public init(target: String, sealed_value: String, digest: String, signature: String, claims: [String] = []) {
        self.target = target
        self.sealed_value = sealed_value
        self.digest = digest
        self.signature = signature
        self.claims = claims
    }
    public var description: String { "[app.items.rotate]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"target\":"); try w.string(target)
        try w.raw(",\"sealed_value\":"); try w.string(sealed_value)
        try w.raw(",\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppItemsRemove: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = RemovedView
    public static let name = "app.items.remove"
    public let target: String
    public let digest: String
    public let signature: String
    public let claims: [String]
    public init(target: String, digest: String, signature: String, claims: [String] = []) {
        self.target = target
        self.digest = digest
        self.signature = signature
        self.claims = claims
    }
    public var description: String { "[app.items.remove]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"target\":"); try w.string(target)
        try w.raw(",\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppUnlockerAdd: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppUnlockerAddedView
    public static let name = "app.unlocker.add"
    public let label: String
    public let unlock_pub: String
    public let approve_pub: String
    public let nonce: String
    public let digest: String
    public let signature: String
    public let created_secs: UInt64
    public let claims: [String]
    public init(label: String, unlock_pub: String, approve_pub: String, nonce: String,
                digest: String, signature: String, created_secs: UInt64 = 0, claims: [String] = []) {
        self.label = label
        self.unlock_pub = unlock_pub
        self.approve_pub = approve_pub
        self.nonce = nonce
        self.digest = digest
        self.signature = signature
        self.created_secs = created_secs
        self.claims = claims
    }
    public var description: String { "[app.unlocker.add]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"label\":"); try w.string(label)
        try w.raw(",\"unlock_pub\":"); try w.string(unlock_pub)
        try w.raw(",\"approve_pub\":"); try w.string(approve_pub)
        try w.raw(",\"nonce\":"); try w.string(nonce)
        try w.raw(",\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        if created_secs > 0 { try w.raw(",\"created_secs\":" + String(created_secs)) }
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppUnlockerRemove: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppUnlockerRemovedView
    public static let name = "app.unlocker.remove"
    public let unlocker: String
    public let nonce: String
    public let digest: String
    public let signature: String
    public let created_secs: UInt64
    public let claims: [String]
    public init(unlocker: String, nonce: String, digest: String, signature: String,
                created_secs: UInt64 = 0, claims: [String] = []) {
        self.unlocker = unlocker
        self.nonce = nonce
        self.digest = digest
        self.signature = signature
        self.created_secs = created_secs
        self.claims = claims
    }
    public var description: String { "[app.unlocker.remove]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"unlocker\":"); try w.string(unlocker)
        try w.raw(",\"nonce\":"); try w.string(nonce)
        try w.raw(",\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        if created_secs > 0 { try w.raw(",\"created_secs\":" + String(created_secs)) }
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppRevealBegin: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = RevealDescriptor
    public static let name = "app.reveal.begin"
    public let requestID: String?
    public let slug: String?
    public let field: String?
    public let claims: [String]
    public init(request: String? = nil, slug: String? = nil, field: String? = nil, claims: [String] = []) {
        self.requestID = request
        self.slug = slug
        self.field = field
        self.claims = claims
    }
    public var description: String { "[app.reveal.begin]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        var comma = false
        if let requestID {
            try w.raw("\"request\":"); try w.string(requestID)
            comma = true
        }
        if let slug {
            if comma { try w.raw(",") }
            try w.raw("\"slug\":"); try w.string(slug)
            comma = true
        }
        if let field {
            if comma { try w.raw(",") }
            try w.raw("\"field\":"); try w.string(field)
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

public struct AppReveal: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppRevealView
    public static let name = "app.reveal"
    public let requestID: String
    public let digest: String
    public let signature: String
    public let app_eph_pub: String
    public let claims: [String]
    public init(request: String, digest: String, signature: String, app_eph_pub: String, claims: [String] = []) {
        self.requestID = request
        self.digest = digest
        self.signature = signature
        self.app_eph_pub = app_eph_pub
        self.claims = claims
    }
    public var description: String { "[app.reveal]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"request\":"); try w.string(requestID)
        try w.raw(",\"digest\":"); try w.string(digest)
        try w.raw(",\"signature\":"); try w.string(signature)
        try w.raw(",\"app_eph_pub\":"); try w.string(app_eph_pub)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppPasteBegin: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppPasteBeginView
    public static let name = "app.paste.begin"
    public let claims: [String]
    public init(claims: [String] = []) { self.claims = claims }
    public var description: String { "[app.paste.begin]" }
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

public struct AppPasteInspect: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppPasteInspectView
    public static let name = "app.paste.inspect"
    public let stage: String
    public let sealed: String
    public let claims: [String]
    public init(stage: String, sealed: String, claims: [String] = []) {
        self.stage = stage
        self.sealed = sealed
        self.claims = claims
    }
    public var description: String { "[app.paste.inspect]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"stage\":"); try w.string(stage)
        try w.raw(",\"sealed\":"); try w.string(sealed)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppPaste: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AddedView
    public static let name = "app.paste"
    public let stage: String
    public let slug: String?
    public let provider: String?
    public let field: String?
    public let account: String?
    public let env_hint: String?
    public let allow_short: Bool
    public let ask: String?
    public let claims: [String]
    public init(stage: String, slug: String? = nil, provider: String? = nil, field: String? = nil,
                account: String? = nil, env_hint: String? = nil, allow_short: Bool = false,
                ask: String? = nil, claims: [String] = []) {
        self.stage = stage
        self.slug = slug
        self.provider = provider
        self.field = field
        self.account = account
        self.env_hint = env_hint
        self.allow_short = allow_short
        self.ask = ask
        self.claims = claims
    }
    public var description: String { "[app.paste]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"stage\":"); try w.string(stage)
        if let slug { try w.raw(",\"slug\":"); try w.string(slug) }
        if let provider { try w.raw(",\"provider\":"); try w.string(provider) }
        if let field { try w.raw(",\"field\":"); try w.string(field) }
        if let account { try w.raw(",\"account\":"); try w.string(account) }
        if let env_hint { try w.raw(",\"env_hint\":"); try w.string(env_hint) }
        if allow_short { try w.raw(",\"allow_short\":true") }
        if let ask { try w.raw(",\"ask\":"); try w.string(ask) }
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppAsksList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppAsksListView
    public static let name = "app.asks.list"
    public let claims: [String]
    public init(claims: [String] = []) { self.claims = claims }
    public var description: String { "[app.asks.list]" }
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

public struct AppAsksDecline: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppAskDeclinedView
    public static let name = "app.asks.decline"
    public let ask: String
    public let claims: [String]
    public init(ask: String, claims: [String] = []) {
        self.ask = ask
        self.claims = claims
    }
    public var description: String { "[app.asks.decline]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"ask\":"); try w.string(ask)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppLock: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = LockedView
    public static let name = "app.lock"
    public let reason: AppLockReason
    public let claims: [String]
    public init(reason: AppLockReason, claims: [String] = []) {
        self.reason = reason
        self.claims = claims
    }
    public var description: String { "[app.lock]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        try w.raw("\"reason\":"); try w.string(reason.rawValue)
        if !claims.isEmpty { try w.raw(",\"claims\":"); try w.strings(claims) }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> Output {
        try frame.response(id: id)
    }
}

public struct AppAuditList: DaemonMethod, CustomStringConvertible, CustomDebugStringConvertible {
    public typealias Output = AppAuditListView
    public static let name = "app.audit.list"
    public let before_seq: UInt64?
    public let limit: UInt64?
    public let project: String?
    public let item: String?
    public let agent: String?
    public let kinds: [String]
    public let claims: [String]
    public init(before_seq: UInt64? = nil, limit: UInt64? = nil, project: String? = nil,
                item: String? = nil, agent: String? = nil, kinds: [String] = [], claims: [String] = []) {
        self.before_seq = before_seq
        self.limit = limit
        self.project = project
        self.item = item
        self.agent = agent
        self.kinds = kinds
        self.claims = claims
    }
    public var description: String { "[app.audit.list]" }
    public var debugDescription: String { description }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        var comma = false
        if let before_seq {
            try w.raw("\"before_seq\":" + String(before_seq))
            comma = true
        }
        if let limit {
            if comma { try w.raw(",") }
            try w.raw("\"limit\":" + String(limit))
            comma = true
        }
        if let project {
            if comma { try w.raw(",") }
            try w.raw("\"project\":"); try w.string(project)
            comma = true
        }
        if let item {
            if comma { try w.raw(",") }
            try w.raw("\"item\":"); try w.string(item)
            comma = true
        }
        if let agent {
            if comma { try w.raw(",") }
            try w.raw("\"agent\":"); try w.string(agent)
            comma = true
        }
        if !kinds.isEmpty {
            if comma { try w.raw(",") }
            try w.raw("\"kinds\":"); try w.strings(kinds)
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
