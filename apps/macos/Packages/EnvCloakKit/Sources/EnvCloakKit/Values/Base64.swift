enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    static func decode(_ bytes: UnsafeRawBufferPointer) throws -> SecretBuffer {
        guard bytes.count % 4 == 0 else { throw EnvCloakError.protocolError }
        var output = try SecretBuffer(capacity: bytes.count / 4 * 3)
        func sextet(_ b: UInt8) throws -> UInt8 {
            switch b {
            case 65...90: return b - 65
            case 97...122: return b - 71
            case 48...57: return b + 4
            case 43: return 62
            case 47: return 63
            default: throw EnvCloakError.protocolError
            }
        }
        for i in stride(from: 0, to: bytes.count, by: 4) {
            let a = try sextet(bytes[i])
            let b = try sextet(bytes[i + 1])
            let c = bytes[i + 2]
            let d = bytes[i + 3]
            try output.append(a << 2 | b >> 4)
            if c == 61 {
                guard d == 61, i + 4 == bytes.count, b & 15 == 0 else { throw EnvCloakError.protocolError }
            } else {
                let n = try sextet(c)
                try output.append(b << 4 | n >> 2)
                if d == 61 {
                    guard i + 4 == bytes.count, n & 3 == 0 else { throw EnvCloakError.protocolError }
                } else { try output.append(n << 6 | sextet(d)) }
            }
        }
        return output
    }

    static func encode(_ value: borrowing SecretBuffer, into out: inout SecretBuffer) throws {
        try value.withUnsafeBytes { bytes in
            for i in stride(from: 0, to: bytes.count, by: 3) {
                let a = bytes[i]
                let b = i + 1 < bytes.count ? bytes[i + 1] : 0
                let c = i + 2 < bytes.count ? bytes[i + 2] : 0
                try out.append(alphabet[Int(a >> 2)])
                try out.append(alphabet[Int((a & 3) << 4 | b >> 4)])
                try out.append(i + 1 < bytes.count ? alphabet[Int((b & 15) << 2 | c >> 6)] : 61)
                try out.append(i + 2 < bytes.count ? alphabet[Int(c & 63)] : 61)
            }
        }
    }
}
