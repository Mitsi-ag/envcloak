public struct Frame: ~Copyable {
    public static let limit = 1_048_576
    var body: SecretBuffer
    public var count: Int { body.count }
    public var description: String { "[frame]" }
    public var debugDescription: String { "[frame]" }

    init(body: consuming SecretBuffer) { self.body = consume body }

    /// Metadata fixtures and non-secret messages only. Values use the
    /// writer's base64 path, never a String initializer.
    init(text: String) throws {
        var buffer = try SecretBuffer()
        for byte in text.utf8 { try buffer.append(byte) }
        guard buffer.count > 0 else { throw EnvCloakError.protocolError }
        body = consume buffer
    }

    static func read(using read: (UnsafeMutableRawBufferPointer) throws -> Int) throws -> Frame {
        var header = [UInt8](repeating: 0, count: 4)
        var offset = 0
        while offset < 4 {
            let n = try header.withUnsafeMutableBytes {
                try read(UnsafeMutableRawBufferPointer(rebasing: $0[offset...]))
            }
            guard n > 0, n <= 4 - offset else { throw EnvCloakError.protocolError }
            offset += n
        }
        let count = header.reduce(0) { $0 * 256 + Int($1) }
        guard count > 0, count <= limit else { throw EnvCloakError.protocolError }
        var buffer = try SecretBuffer(capacity: min(16_384, count))
        while buffer.count < count {
            if buffer.count == buffer.capacity { try buffer.reserveCapacity(min(count, buffer.capacity * 2)) }
            let n = try buffer.read(upTo: min(count - buffer.count, buffer.capacity - buffer.count), using: read)
            guard n > 0 else { throw EnvCloakError.protocolError }
        }
        return Frame(body: consume buffer)
    }

    borrowing func write(using write: (UnsafeRawBufferPointer) throws -> Int) throws {
        guard count > 0, count <= Self.limit else { throw EnvCloakError.protocolError }
        let header = (0..<4).map { UInt8(truncatingIfNeeded: count >> (24 - $0 * 8)) }
        func all(_ bytes: UnsafeRawBufferPointer) throws {
            var offset = 0
            while offset < bytes.count {
                let n = try write(UnsafeRawBufferPointer(rebasing: bytes[offset...]))
                guard n > 0, n <= bytes.count - offset else { throw EnvCloakError.protocolError }
                offset += n
            }
        }
        try header.withUnsafeBytes(all)
        try body.withUnsafeBytes(all)
    }

    borrowing func response<T: WireDecodable>(id: UInt64, as: T.Type = T.self) throws -> T {
        try body.withUnsafeBytes { bytes in
            var parser = JSONParser(bytes: bytes)
            let root = try WireReader(bytes: bytes, node: parser.parse()).object(["jsonrpc", "id", "result", "error"])
            guard try root.decode("jsonrpc", as: String.self) == "2.0" else { throw EnvCloakError.protocolError }
            let result = root.fields["result"]
            let error = root.fields["error"]
            guard (result == nil) != (error == nil) else { throw EnvCloakError.protocolError }
            let responseID = try root.required("id")
            if case .null = responseID.node {
                guard error != nil else { throw EnvCloakError.protocolError }
            } else {
                guard try UInt64(wire: responseID) == id else { throw EnvCloakError.protocolError }
            }
            if let error {
                let object = try error.object(["code", "message", "data"])
                guard case .string = try object.required("message").node else { throw EnvCloakError.protocolError }
                let data = try object.required("data").object(["kind", "reason"])
                guard let kind = ErrorKind(rawValue: try data.decode("kind")),
                      try object.required("code").integer(Int64.self) == kind.code else { throw EnvCloakError.protocolError }
                // Unknown reasons are discarded. No daemon message enters an error.
                let reason = try data.optional("reason", as: String.self).flatMap(Reason.init(rawValue:))
                throw EnvCloakError.rpc(kind, reason)
            }
            guard let result else { throw EnvCloakError.protocolError }
            return try T(wire: result)
        }
    }

    borrowing func secret() throws -> SecretBuffer {
        // The result is noncopyable, so decode inside an explicitly typed
        // borrowing closure without Foundation's base64/Data conversion.
        try body.withUnsafeBytes { bytes in
            var parser = JSONParser(bytes: bytes)
            guard case .string(let range) = try parser.parse() else { throw EnvCloakError.protocolError }
            return try Base64.decode(UnsafeRawBufferPointer(rebasing: bytes[range]))
        }
    }

    borrowing func validateSecret() throws { let _ = try secret() }
}
