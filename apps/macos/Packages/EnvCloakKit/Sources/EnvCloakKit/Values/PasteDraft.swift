import Foundation

public enum PasteError: Error { case empty, multipleLines, invalid, tooLarge }

/// The one documented SecureField String copy is cleared at first change.
/// Only metadata, never the value, can leave this unique draft as text.
public struct PasteDraft: ~Copyable {
    public private(set) var value: SecretBuffer
    public let droppedLineEnding: Bool
    public private(set) var envName: String?
    public private(set) var characters: Int
    private var valueOffset: Int?
    private var envValueCharacters: Int?

    public init(taking text: inout String) throws {
        defer { text = "" }
        guard text.utf8.count <= 65_536 else { throw PasteError.tooLarge }
        let droppedLineEnding = text.unicodeScalars.last?.value == 10
        if droppedLineEnding {
            text.unicodeScalars.removeLast()
            if text.unicodeScalars.last?.value == 13 { text.unicodeScalars.removeLast() }
        }
        guard !text.isEmpty else { throw PasteError.empty }
        guard !text.utf8.contains(10), !text.utf8.contains(13) else { throw PasteError.multipleLines }
        guard !text.utf8.contains(0) else { throw PasteError.invalid }
        let characters = text.count
        var value = try SecretBuffer(capacity: text.utf8.count)
        try text.withUTF8 { try value.append(contentsOf: UnsafeRawBufferPointer($0)) }
        var envName: String?
        var valueOffset: Int?
        var envValueCharacters: Int?
        if let equal = text.utf8.firstIndex(of: 61) {
            let nameBytes = text.utf8[..<equal]
            if !nameBytes.isEmpty, nameBytes.count <= 128,
               nameBytes.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
               let first = nameBytes.first, !(48...57).contains(first), !Self.valueShaped(nameBytes) {
                envName = String(decoding: nameBytes, as: UTF8.self)
                valueOffset = nameBytes.count + 1
                envValueCharacters = text[text.index(after: equal)...].count
            }
        }
        self.value = consume value
        self.characters = characters
        self.droppedLineEnding = droppedLineEnding
        self.envName = envName
        self.valueOffset = valueOffset
        self.envValueCharacters = envValueCharacters
    }

    // An '=' may be padding on an opaque value. Match the policy's long
    // mixed alphanumeric run rule before copying a proposed variable name.
    private static func valueShaped(_ bytes: Substring.UTF8View) -> Bool {
        var run = 0
        var classes: UInt8 = 0
        for byte in bytes {
            let kind: UInt8
            switch byte {
            case 97...122: kind = 1
            case 65...90: kind = 2
            case 48...57: kind = 4
            default: run = 0; classes = 0; continue
            }
            run += 1; classes |= kind
            if run >= 24 && classes.nonzeroBitCount >= 2 { return true }
        }
        return false
    }

    public mutating func useEnvLine() throws {
        guard let offset = valueOffset, offset < value.count else { throw PasteError.empty }
        var next = try SecretBuffer(capacity: value.count - offset)
        try value.withUnsafeBytes { try next.append(contentsOf: UnsafeRawBufferPointer(rebasing: $0[offset...])) }
        // Counted from the transient field view before it was cleared, so
        // grapheme clusters stay consistent without another secret String.
        characters = envValueCharacters ?? 0
        value = consume next
        valueOffset = nil
        envValueCharacters = nil
    }

    public consuming func takeValue() -> SecretBuffer { value }
}
