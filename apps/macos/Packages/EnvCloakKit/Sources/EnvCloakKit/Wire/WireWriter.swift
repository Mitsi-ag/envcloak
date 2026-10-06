struct WireWriter: ~Copyable {
    var buffer: SecretBuffer
    init() throws { buffer = try SecretBuffer() }
    mutating func raw(_ metadata: String) throws {
        for b in metadata.utf8 { try buffer.append(b) }
    }
    mutating func string(_ metadata: String) throws {
        try buffer.append(34)
        for scalar in metadata.unicodeScalars {
            switch scalar.value {
            case 34: try raw("\\\"")
            case 92: try raw("\\\\")
            case 8: try raw("\\b")
            case 12: try raw("\\f")
            case 10: try raw("\\n")
            case 13: try raw("\\r")
            case 9: try raw("\\t")
            case 0...31:
                let hex = String(scalar.value, radix: 16)
                try raw("\\u" + String(repeating: "0", count: 4 - hex.count) + hex)
            default: try raw(String(scalar))
            }
        }
        try buffer.append(34)
    }
    mutating func strings(_ values: [String]) throws {
        try raw("[")
        for (index, value) in values.enumerated() {
            if index > 0 { try raw(",") }
            try string(value)
        }
        try raw("]")
    }
    mutating func secret(_ value: borrowing SecretBuffer) throws {
        try buffer.append(34)
        try Base64.encode(value, into: &buffer)
        try buffer.append(34)
    }
    consuming func frame() -> Frame { Frame(body: consume buffer) }
}
