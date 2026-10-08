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
        if let equal = text.utf8.firstIndex(of: 61) {
            let nameBytes = text.utf8[..<equal]
            if !nameBytes.isEmpty, nameBytes.count <= 128,
               nameBytes.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
               let first = nameBytes.first, !(48...57).contains(first) {
                envName = String(decoding: nameBytes, as: UTF8.self)
                valueOffset = nameBytes.count + 1
            }
        }
        self.value = consume value
        self.characters = characters
        self.droppedLineEnding = droppedLineEnding
        self.envName = envName
        self.valueOffset = valueOffset
    }

    public mutating func useEnvLine() throws {
        guard let offset = valueOffset, offset < value.count else { throw PasteError.empty }
        var next = try SecretBuffer(capacity: value.count - offset)
        try value.withUnsafeBytes { try next.append(contentsOf: UnsafeRawBufferPointer(rebasing: $0[offset...])) }
        // UTF-8 was validated by Swift when the field was read. Count Unicode
        // scalar starts without producing another secret String.
        characters = next.withUnsafeBytes { $0.reduce(0) { $0 + ($1 & 0xc0 != 0x80 ? 1 : 0) } }
        value = consume next
        valueOffset = nil
    }

    public consuming func takeValue() -> SecretBuffer { value }
}
