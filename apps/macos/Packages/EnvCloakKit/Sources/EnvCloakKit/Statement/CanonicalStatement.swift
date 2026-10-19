import CryptoKit
import Foundation

public struct RenderedArgv: Equatable, Sendable {
    public struct Line: Equatable, Sendable, Identifiable {
        public let index: Int
        public let text: String

        public var id: Int { index }

        public init(index: Int, text: String) {
            self.index = index
            self.text = text
        }

        public var formatted: String {
            "[\(index)] \(text)"
        }
    }

    public let allLines: [Line]
    public let truncatedLines: [Line]
    public let hiddenByteCount: Int

    public var isTruncated: Bool {
        hiddenByteCount > 0
    }
}

public enum CanonicalStatement {
    public static let domain = Data("envcloak-statement/2\n".utf8)
    public static let domainV1 = Data("envcloak-statement/1\n".utf8)
    public static let renderLimit = 2048
    public static let hidden = "[not shown: looks like a key or token]"
    public static let valueRun = 24

    private struct Encoder {
        var data: Data

        init(domain: Data) {
            self.data = domain
        }

        mutating func str(_ value: String) {
            let utf8 = Array(value.utf8)
            let len = UInt32(clamping: utf8.count)
            data.append(UInt8((len >> 24) & 0xFF))
            data.append(UInt8((len >> 16) & 0xFF))
            data.append(UInt8((len >> 8) & 0xFF))
            data.append(UInt8(len & 0xFF))
            data.append(contentsOf: utf8)
        }

        mutating func num(_ value: UInt64) {
            str(String(value))
        }

        mutating func signed(_ value: Int32) {
            str(String(value))
        }

        mutating func count(_ value: Int) {
            str(String(value))
        }

        mutating func flag(_ value: Bool) {
            str(value ? "1" : "0")
        }
    }

    public static func encode(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> Data {
        encodeInternal(descriptor, options: options, domain: domain, includeProposals: true)
    }

    public static func encodeV1(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> Data {
        encodeInternal(descriptor, options: options, domain: domainV1, includeProposals: false)
    }

    private static func encodeInternal(
        _ p: PendingDescriptor,
        options o: ApprovalOptions,
        domain: Data,
        includeProposals: Bool
    ) -> Data {
        var e = Encoder(domain: domain)
        e.str(p.request.raw)
        e.str(p.nonce.raw)
        e.num(p.created_secs)
        e.num(p.expires_in_secs)
        e.str(p.subject.kind.rawValue)
        e.str(p.subject.label?.raw ?? "")
        e.flag(p.subject.label != nil)
        e.signed(p.subject.caller_pid)
        e.signed(p.subject.root.pid)
        e.num(p.subject.root.start_time)
        e.str(p.subject.root.exe?.raw ?? "")
        e.flag(p.subject.root.exe != nil)
        e.str(p.project.dir.raw)
        e.str(p.project.manifest.raw)
        e.str(p.project.manifest_sha256.raw)
        e.flag(p.project.new_project)
        e.count(p.bindings.count)
        for b in p.bindings {
            e.str(b.env_name.raw)
            e.str(b.slug.raw)
            e.str(b.item.raw)
            e.str(b.field.raw)
            e.str(b.field_name.raw)
            e.str(b.classification.raw)
            e.flag(b.first_use)
            e.flag(b.granted)
        }
        if includeProposals {
            e.count(p.proposals.count)
            for x in p.proposals {
                e.str(x.env_name.raw)
                e.str(x.live_slug.raw)
                e.str(x.test_slug.raw)
                e.str(x.test_field?.raw ?? "")
                e.flag(x.test_field != nil)
                switch x.source {
                case .env:
                    e.str("env")
                case .profile(let profile):
                    e.str("profile")
                    e.str(profile.raw)
                case .envFile(let line):
                    e.str("env_file")
                    e.num(UInt64(line))
                case .ref:
                    e.str("ref")
                }
            }
        }
        e.str(p.mode.rawValue)
        e.count(p.argv.count)
        for arg in p.argv {
            e.str(arg.raw)
        }
        e.str(o.uses.rawValue)
        e.num(o.ttl_secs)
        e.count(o.live.count)
        for l in o.live {
            e.str(l)
        }
        if let m = p.managed {
            e.str("managed")
            e.str(m.name.raw)
            e.flag(m.written_by_migrate_mcp)
            e.str(m.launch?.raw ?? "")
            e.flag(m.launch != nil)
            e.num(m.revision ?? 0)
            e.flag(m.revision != nil)
            e.str(m.class?.raw ?? "")
            e.str(m.strength?.raw ?? "")
            e.str(m.origin?.raw ?? "")
            e.flag(m.origin != nil)
        }
        if let standingSecs = o.standing {
            e.str("standing")
            e.num(standingSecs)
            e.flag(p.standing != nil)
            if let s = p.standing {
                e.str(s.exe.raw)
                e.str(s.linux_sha256?.raw ?? "")
                e.flag(s.linux_sha256 != nil)
                e.str(s.recognized_release?.raw ?? "")
                e.flag(s.recognized_release != nil)
                e.str(s.appends_to?.raw ?? "")
                e.flag(s.appends_to != nil)
            }
        }
        return e.data
    }

    public static func digest(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> Data {
        Data(SHA256.hash(data: encode(descriptor, options: options)))
    }

    public static func digestHex(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> String {
        HexCoding.encode(digest(descriptor, options: options))
    }

    public static func digestV1Hex(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> String {
        HexCoding.encode(Data(SHA256.hash(data: encodeV1(descriptor, options: options))))
    }

    public static func liveGuarded(_ kind: SubjectKind) -> Bool {
        switch kind {
        case .agent, .unknown:
            return true
        case .terminal:
            return false
        }
    }

    public static func untickedLive(_ descriptor: PendingDescriptor, options: ApprovalOptions) -> [String] {
        guard liveGuarded(descriptor.subject.kind) else {
            return []
        }
        return descriptor.bindings
            .filter { $0.classification.raw == "live" && !options.live.contains($0.env_name.raw) }
            .map(\.env_name.escaped)
    }

    public static func valueShaped(_ s: String) -> Bool {
        var run = 0
        var classes: UInt8 = 0
        for b in s.utf8 {
            let c: UInt8
            if b >= 0x61 && b <= 0x7A {
                c = 1
            } else if b >= 0x41 && b <= 0x5A {
                c = 2
            } else if b >= 0x30 && b <= 0x39 {
                c = 4
            } else {
                run = 0
                classes = 0
                continue
            }
            run += 1
            classes |= c
            if run >= valueRun && classes.nonzeroBitCount >= 2 {
                return true
            }
        }
        return false
    }

    public static func isDisplayEscaped(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0...31, 127...159, 0xAD, 0x34F, 0x600...0x605, 0x61C, 0x6DD,
             0x70F, 0x890...0x891, 0x8E2, 0x115F...0x1160, 0x17B4...0x17B5,
             0x180B...0x180F, 0x200B...0x200F, 0x2028...0x202E, 0x2060...0x206F,
             0x3164, 0xFE00...0xFE0F, 0xFEFF, 0xFFA0, 0xFFF9...0xFFFB,
             0x110BD, 0x110CD, 0x13430...0x1343F, 0x1BCA0...0x1BCA3,
             0x1D173...0x1D17A, 0xE0000...0xE0FFF:
            return true
        default:
            return false
        }
    }

    public static func shownName(_ s: String, looksLikeValue: (String) -> Bool = valueShaped) -> String {
        if looksLikeValue(s) {
            return hidden
        }
        return Escape.display(s)
    }

    public static func shellWord(_ s: String) -> String? {
        if s.isEmpty || s.unicodeScalars.contains(where: isDisplayEscaped) {
            return nil
        }
        let safePunctuation = Set("/._-+=:,@%".utf8)
        let allSafe = s.utf8.allSatisfy { b in
            (b >= 0x30 && b <= 0x39)
                || (b >= 0x41 && b <= 0x5A)
                || (b >= 0x61 && b <= 0x7A)
                || safePunctuation.contains(b)
        }
        if allSafe {
            return s
        }
        let escapedQuotes = s.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escapedQuotes)'"
    }

    public static func renderArgv(_ argv: [DaemonText]) -> RenderedArgv {
        let allLines = argv.enumerated().map { idx, arg in
            RenderedArgv.Line(index: idx, text: arg.escaped)
        }
        var fullRendered = ""
        for line in allLines {
            fullRendered += "    [\(line.index)] \(line.text)\n"
        }
        let fullUTF8Count = fullRendered.utf8.count
        if fullUTF8Count <= renderLimit {
            return RenderedArgv(allLines: allLines, truncatedLines: allLines, hiddenByteCount: 0)
        }

        var truncatedLines: [RenderedArgv.Line] = []
        var usedBytes = 0
        for line in allLines {
            let lineFormatted = "    [\(line.index)] \(line.text)\n"
            let lineBytes = lineFormatted.utf8.count
            if usedBytes + lineBytes <= renderLimit {
                truncatedLines.append(line)
                usedBytes += lineBytes
            } else {
                let remaining = renderLimit - usedBytes
                if remaining > 0 {
                    let prefix = utf8Prefix(of: lineFormatted, maxBytes: remaining)
                    let trimmed = prefix.hasPrefix("    [\(line.index)] ")
                        ? String(prefix.dropFirst("    [\(line.index)] ".count))
                        : prefix
                    truncatedLines.append(RenderedArgv.Line(index: line.index, text: trimmed))
                    usedBytes += prefix.utf8.count
                }
                break
            }
        }
        let hidden = max(0, fullUTF8Count - usedBytes)
        return RenderedArgv(allLines: allLines, truncatedLines: truncatedLines, hiddenByteCount: hidden)
    }

    private static func utf8Prefix(of string: String, maxBytes: Int) -> String {
        var result = ""
        var count = 0
        for scalar in string.unicodeScalars {
            let scalarBytes = scalar.utf8.count
            if count + scalarBytes > maxBytes {
                break
            }
            result.unicodeScalars.append(scalar)
            count += scalarBytes
        }
        return result
    }
}

extension Proposal {
    var rawReference: String {
        if let f = test_field {
            return "\(test_slug.raw)#\(f.raw)"
        }
        return test_slug.raw
    }

    public var reference: String {
        if let f = test_field {
            return "\(test_slug.escaped)#\(f.escaped)"
        }
        return test_slug.escaped
    }

    public var canApplyAutomatically: Bool {
        switch source {
        case .env, .profile:
            return true
        case .envFile, .ref:
            return false
        }
    }

    public func refCommandArguments(manifest: DaemonText) -> [String]? {
        switch source {
        case .env:
            return ["ref", "--manifest", manifest.raw, "\(env_name.raw)=\(rawReference)"]
        case .profile(let profile):
            return ["ref", "--manifest", manifest.raw, "--profile", profile.raw, "\(env_name.raw)=\(rawReference)"]
        case .envFile, .ref:
            return nil
        }
    }

    public func shownReference(
        looksLikeValue: (String) -> Bool = CanonicalStatement.valueShaped
    ) -> String {
        let slug = CanonicalStatement.shownName(test_slug.raw, looksLikeValue: looksLikeValue)
        if let f = test_field {
            return "\(slug)#\(CanonicalStatement.shownName(f.raw, looksLikeValue: looksLikeValue))"
        }
        return slug
    }

    public func commandLineAdvice(
        looksLikeValue: (String) -> Bool = CanonicalStatement.valueShaped
    ) -> String? {
        let name = CanonicalStatement.shownName(env_name.raw, looksLikeValue: looksLikeValue)
        let ref = shownReference(looksLikeValue: looksLikeValue)
        switch source {
        case .env, .profile:
            return nil
        case .envFile(let line):
            return "set line \(line) of the --env-file to `\(name)=envcloak://\(ref)`"
        case .ref:
            return "give `--ref \(name)=\(ref)` in place of the --ref for \(name)"
        }
    }

    public func advice(
        manifest: DaemonText,
        looksLikeValue: (String) -> Bool = CanonicalStatement.valueShaped
    ) -> String {
        if let line = commandLineAdvice(looksLikeValue: looksLikeValue) {
            return line
        }
        let name = CanonicalStatement.shownName(env_name.raw, looksLikeValue: looksLikeValue)
        let ref = shownReference(looksLikeValue: looksLikeValue)
        let profilePart: String
        if case .profile(let profile) = source {
            profilePart = " --profile \(CanonicalStatement.shownName(profile.raw, looksLikeValue: looksLikeValue))"
        } else {
            profilePart = ""
        }
        if let m = CanonicalStatement.shellWord(manifest.raw) {
            return "run `envcloak ref --manifest \(m)\(profilePart) \(name)=\(ref)`"
        }
        return "run `envcloak ref\(profilePart) \(name)=\(ref)` in the directory of the manifest \(manifest.escaped)"
    }
}
