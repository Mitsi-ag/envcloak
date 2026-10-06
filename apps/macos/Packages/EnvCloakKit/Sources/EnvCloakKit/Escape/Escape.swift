public enum Escape {
    /// GRANTS.md Rendering, kept equal to Rust and an independent Unicode oracle.
    public static func display(_ text: String) -> String {
        var out = ""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 92: out += "\\\\"
            case 10: out += "\\n"
            case 13: out += "\\r"
            case 9: out += "\\t"
            case 0...31, 127...159, 0xAD, 0x34F, 0x600...0x605, 0x61C, 0x6DD,
                 0x70F, 0x890...0x891, 0x8E2, 0x115F...0x1160, 0x17B4...0x17B5,
                 0x180B...0x180F, 0x200B...0x200F, 0x2028...0x202E, 0x2060...0x206F,
                 0x3164, 0xFE00...0xFE0F, 0xFEFF, 0xFFA0, 0xFFF9...0xFFFB,
                 0x110BD, 0x110CD, 0x13430...0x1343F, 0x1BCA0...0x1BCA3,
                 0x1D173...0x1D17A, 0xE0000...0xE0FFF:
                out += "\\u{" + String(scalar.value, radix: 16) + "}"
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out
    }
}
