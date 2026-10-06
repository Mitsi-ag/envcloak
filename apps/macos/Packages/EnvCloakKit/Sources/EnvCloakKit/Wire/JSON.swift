// The syntax tree stores offsets only. In particular, error.message and
// base64 values are never materialized as String or Data.
indirect enum JSONNode {
    case object([(Range<Int>, JSONNode)])
    case array([JSONNode])
    case string(Range<Int>)
    case number(Range<Int>)
    case bool(Bool)
    case null
}

struct JSONParser {
    let bytes: UnsafeRawBufferPointer
    var position = 0
    var nodes = 0

    mutating func parse() throws -> JSONNode {
        let result = try value(depth: 0)
        whitespace()
        guard position == bytes.count else { throw EnvCloakError.protocolError }
        return result
    }

    mutating func whitespace() {
        while position < bytes.count, [9, 10, 13, 32].contains(bytes[position]) { position += 1 }
    }

    mutating func take(_ byte: UInt8) -> Bool {
        whitespace()
        if position < bytes.count, bytes[position] == byte { position += 1; return true }
        return false
    }

    mutating func value(depth: Int) throws -> JSONNode {
        nodes += 1
        guard depth < 64, nodes <= 131_072 else { throw EnvCloakError.protocolError }
        whitespace()
        guard position < bytes.count else { throw EnvCloakError.protocolError }
        switch bytes[position] {
        case 123:
            position += 1
            var fields: [(Range<Int>, JSONNode)] = []
            if take(125) { return .object(fields) }
            repeat {
                whitespace()
                let key = try string()
                guard take(58) else { throw EnvCloakError.protocolError }
                fields.append((key, try value(depth: depth + 1)))
            } while take(44)
            guard take(125) else { throw EnvCloakError.protocolError }
            return .object(fields)
        case 91:
            position += 1
            var items: [JSONNode] = []
            if take(93) { return .array(items) }
            repeat { items.append(try value(depth: depth + 1)) } while take(44)
            guard take(93) else { throw EnvCloakError.protocolError }
            return .array(items)
        case 34: return .string(try string())
        case 116: try literal("true"); return .bool(true)
        case 102: try literal("false"); return .bool(false)
        case 110: try literal("null"); return .null
        default:
            let start = position
            if bytes[position] == 45 { position += 1 }
            guard position < bytes.count else { throw EnvCloakError.protocolError }
            if bytes[position] == 48 { position += 1 } else {
                guard (49...57).contains(bytes[position]) else { throw EnvCloakError.protocolError }
                digits()
            }
            if position < bytes.count, bytes[position] == 46 {
                position += 1
                let begin = position
                digits()
                guard position > begin else { throw EnvCloakError.protocolError }
            }
            if position < bytes.count, [69, 101].contains(bytes[position]) {
                position += 1
                if position < bytes.count, [43, 45].contains(bytes[position]) { position += 1 }
                let begin = position
                digits()
                guard position > begin else { throw EnvCloakError.protocolError }
            }
            return .number(start..<position)
        }
    }

    mutating func digits() {
        while position < bytes.count, (48...57).contains(bytes[position]) { position += 1 }
    }

    mutating func literal(_ text: StaticString) throws {
        let ok = text.withUTF8Buffer { expected in
            guard expected.count <= bytes.count - position else { return false }
            return expected.indices.allSatisfy { expected[$0] == bytes[position + $0] }
        }
        guard ok else { throw EnvCloakError.protocolError }
        position += text.utf8CodeUnitCount
    }

    mutating func string() throws -> Range<Int> {
        guard position < bytes.count, bytes[position] == 34 else { throw EnvCloakError.protocolError }
        position += 1
        let start = position
        while position < bytes.count {
            let b = bytes[position]
            if b == 34 {
                let range = start..<position
                try JSONString.walk(bytes, range: range) { _ in }
                position += 1
                return range
            }
            if b == 92 { position += 1 }
            position += 1
        }
        throw EnvCloakError.protocolError
    }
}

enum JSONString {
    /// Validate UTF-8 and JSON escapes without copying the string. Lone
    /// surrogates, overlong UTF-8 and raw controls are protocol errors.
    static func walk(_ bytes: UnsafeRawBufferPointer, range: Range<Int>, _ emit: (Unicode.Scalar) -> Void) throws {
        var i = range.lowerBound
        func hex(_ at: Int) throws -> UInt32 {
            guard at + 4 <= range.upperBound else { throw EnvCloakError.protocolError }
            var n: UInt32 = 0
            for j in at..<(at + 4) {
                let b = bytes[j]
                let v: UInt32
                switch b {
                case 48...57: v = UInt32(b - 48)
                case 65...70: v = UInt32(b - 55)
                case 97...102: v = UInt32(b - 87)
                default: throw EnvCloakError.protocolError
                }
                n = n * 16 + v
            }
            return n
        }
        while i < range.upperBound {
            let b = bytes[i]
            i += 1
            var n = UInt32(b)
            if b == 92 {
                guard i < range.upperBound else { throw EnvCloakError.protocolError }
                let e = bytes[i]
                i += 1
                switch e {
                case 34, 47, 92: n = UInt32(e)
                case 98: n = 8
                case 102: n = 12
                case 110: n = 10
                case 114: n = 13
                case 116: n = 9
                case 117:
                    n = try hex(i); i += 4
                    if (0xD800...0xDBFF).contains(n) {
                        guard i + 6 <= range.upperBound, bytes[i] == 92, bytes[i + 1] == 117 else {
                            throw EnvCloakError.protocolError
                        }
                        let low = try hex(i + 2)
                        guard (0xDC00...0xDFFF).contains(low) else { throw EnvCloakError.protocolError }
                        n = 0x10000 + (n - 0xD800) * 1024 + low - 0xDC00; i += 6
                    }
                default: throw EnvCloakError.protocolError
                }
            } else if b >= 128 {
                let extra: Int
                let minimum: UInt32
                switch b {
                case 0xC2...0xDF: extra = 1; minimum = 0x80; n &= 31
                case 0xE0...0xEF: extra = 2; minimum = 0x800; n &= 15
                case 0xF0...0xF4: extra = 3; minimum = 0x10000; n &= 7
                default: throw EnvCloakError.protocolError
                }
                guard i + extra <= range.upperBound else { throw EnvCloakError.protocolError }
                for _ in 0..<extra {
                    guard (0x80...0xBF).contains(bytes[i]) else { throw EnvCloakError.protocolError }
                    n = n * 64 + UInt32(bytes[i] & 63); i += 1
                }
                guard n >= minimum else { throw EnvCloakError.protocolError }
            } else if b < 32 || b == 34 { throw EnvCloakError.protocolError }
            guard let scalar = Unicode.Scalar(n) else { throw EnvCloakError.protocolError }
            emit(scalar)
        }
    }
}

/// A reader is valid only inside the frame's decoding closure. Callers
/// decode typed metadata; no reader or pointer leaves that closure.
struct WireReader {
    let bytes: UnsafeRawBufferPointer
    let node: JSONNode

    func object(_ allowed: [String]) throws -> WireObject {
        guard case .object(let fields) = node else { throw EnvCloakError.protocolError }
        var result: [String: WireReader] = [:]
        for (range, node) in fields {
            // Compare in place, including escaped keys, without retaining
            // an attacker-controlled unknown key in a String.
            var candidates = allowed.map { Array($0.unicodeScalars) }
            var offset = 0
            try JSONString.walk(bytes, range: range) { scalar in
                candidates = candidates.filter { offset < $0.count && $0[offset] == scalar }
                offset += 1
            }
            guard let index = allowed.indices.first(where: {
                let scalars = Array(allowed[$0].unicodeScalars)
                return scalars.count == offset && candidates.contains(scalars)
            }), result[allowed[index]] == nil else { throw EnvCloakError.protocolError }
            result[allowed[index]] = WireReader(bytes: bytes, node: node)
        }
        return WireObject(fields: result)
    }

    func string() throws -> String {
        guard case .string(let range) = node else { throw EnvCloakError.protocolError }
        var result = ""
        try JSONString.walk(bytes, range: range) { result.unicodeScalars.append($0) }
        return result
    }

    func integer<T: FixedWidthInteger>(_ type: T.Type) throws -> T {
        guard case .number(let range) = node, !range.isEmpty else { throw EnvCloakError.protocolError }
        var result: T = 0
        var negative = false
        for i in range {
            let b = bytes[i]
            if i == range.lowerBound, b == 45, T.isSigned { negative = true; continue }
            guard (48...57).contains(b) else { throw EnvCloakError.protocolError }
            let (multiplied, overflow) = result.multipliedReportingOverflow(by: 10)
            let (next, overflow2) = negative
                ? multiplied.subtractingReportingOverflow(T(b - 48))
                : multiplied.addingReportingOverflow(T(b - 48))
            guard !overflow, !overflow2 else { throw EnvCloakError.protocolError }
            result = next
        }
        return result
    }
}

struct WireObject {
    let fields: [String: WireReader]
    func required(_ name: String) throws -> WireReader {
        guard let reader = fields[name] else { throw EnvCloakError.protocolError }
        return reader
    }
    func decode<T: WireDecodable>(_ name: String, as: T.Type = T.self) throws -> T {
        try T(wire: required(name))
    }
    func optional<T: WireDecodable>(_ name: String, as: T.Type = T.self) throws -> T? {
        guard let reader = fields[name] else { return nil }
        if case .null = reader.node { return nil }
        return try T(wire: reader)
    }
}

protocol WireDecodable { init(wire: WireReader) throws }
extension String: WireDecodable { init(wire: WireReader) throws { self = try wire.string() } }
extension Bool: WireDecodable {
    init(wire: WireReader) throws {
        guard case .bool(let b) = wire.node else { throw EnvCloakError.protocolError }; self = b
    }
}
extension UInt64: WireDecodable { init(wire: WireReader) throws { self = try wire.integer(Self.self) } }
extension UInt32: WireDecodable { init(wire: WireReader) throws { self = try wire.integer(Self.self) } }
extension UInt8: WireDecodable { init(wire: WireReader) throws { self = try wire.integer(Self.self) } }
extension Int32: WireDecodable { init(wire: WireReader) throws { self = try wire.integer(Self.self) } }
extension Array: WireDecodable where Element: WireDecodable {
    init(wire: WireReader) throws {
        guard case .array(let nodes) = wire.node else { throw EnvCloakError.protocolError }
        self = try nodes.map { try Element(wire: WireReader(bytes: wire.bytes, node: $0)) }
    }
}
