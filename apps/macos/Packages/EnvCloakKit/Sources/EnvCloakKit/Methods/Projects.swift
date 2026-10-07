/// Adopted index metadata (IPC.md). A page is not a manifest snapshot.
public struct ProjectsList: DaemonMethod {
    public typealias Output = ProjectsView
    public static let name = "projects.list"
    public let after: ProjectCursor?
    public init(after: ProjectCursor? = nil) { self.after = after }
    public func request(id: UInt64) throws -> Frame {
        var w = try requestWriter(id: id, name: Self.name)
        if let after {
            try w.raw("\"after\":{\"last_seen\":" + String(after.lastSeen) + ",\"id\":")
            try w.string(after.id)
            try w.raw("}")
        }
        try w.raw("}}")
        return w.frame()
    }
    public static func response(_ frame: borrowing Frame, id: UInt64) throws -> ProjectsView {
        try frame.response(id: id)
    }
}

public struct ProjectCursor: Sendable, Hashable, WireDecodable, CustomStringConvertible {
    public let lastSeen: UInt64
    let id: String
    public var description: String { "[project cursor]" }
    init(wire: WireReader) throws {
        let o = try wire.object(["last_seen", "id"])
        lastSeen = try o.decode("last_seen")
        id = try o.decode("id")
        let bytes = Array(id.utf8)
        guard bytes.count == 26, bytes[0] <= 55,
              bytes.allSatisfy({ "0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8.contains($0) }) else {
            throw EnvCloakError.protocolError
        }
    }
    public func precedes(_ other: ProjectCursor) -> Bool {
        lastSeen < other.lastSeen || (lastSeen == other.lastSeen && id < other.id)
    }
}

public struct ProjectsView: Sendable, WireDecodable {
    public let projects: [ProjectView]
    public let wireByteCount: Int
    public let next: ProjectCursor?
    init(wire: WireReader) throws {
        wireByteCount = wire.bytes.count
        let o = try wire.object(["projects", "next"])
        projects = try o.decode("projects")
        next = try o.optional("next")
    }
}

public struct ProjectView: Sendable, WireDecodable {
    public let dir: DaemonText
    public let manifestSHA256: DaemonText
    public let bindings: [ProjectBindingView]
    public let lastSeen: UInt64
    init(wire: WireReader) throws {
        let o = try wire.object(["dir", "manifest_sha256", "bindings", "last_seen_secs"])
        dir = try o.decode("dir")
        manifestSHA256 = try o.decode("manifest_sha256")
        bindings = try o.decode("bindings")
        lastSeen = try o.decode("last_seen_secs")
    }
}

public struct ProjectBindingView: Sendable, WireDecodable {
    public let envName: DaemonText
    public let reference: DaemonText
    init(wire: WireReader) throws {
        let o = try wire.object(["env_name", "reference"])
        envName = try o.decode("env_name")
        reference = try o.decode("reference")
    }
}
