import CryptoKit
import Foundation

enum VectorToolError: Error {
    case usage
    case hex
    case openFailed
}

func decodeHex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    guard bytes.count.isMultiple(of: 2) else {
        throw VectorToolError.hex
    }
    var out = Data(capacity: bytes.count / 2)
    var index = 0
    while index < bytes.count {
        let hi = try nibble(bytes[index])
        let lo = try nibble(bytes[index + 1])
        out.append((hi << 4) | lo)
        index += 2
    }
    return out
}

func nibble(_ ascii: UInt8) throws -> UInt8 {
    switch ascii {
    case 0x30...0x39:
        return ascii - 0x30
    case 0x61...0x66:
        return ascii - 0x61 + 10
    case 0x41...0x46:
        return ascii - 0x41 + 10
    default:
        throw VectorToolError.hex
    }
}

func encodeHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func run() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let cmd = args.first else {
        throw VectorToolError.usage
    }
    switch cmd {
    case "p256-keygen":
        guard args.count == 1 else { throw VectorToolError.usage }
        let priv = P256.KeyAgreement.PrivateKey()
        print("\(encodeHex(priv.rawRepresentation)) \(encodeHex(priv.publicKey.x963Representation))")

    case "p256-seal":
        guard args.count == 4 else { throw VectorToolError.usage }
        let pubBytes = try decodeHex(args[1])
        let info = try decodeHex(args[2])
        let pt = try decodeHex(args[3])
        let pubKey = try P256.KeyAgreement.PublicKey(x963Representation: pubBytes)
        var sender = try HPKE.Sender(
            recipientKey: pubKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info
        )
        let ct = try sender.seal(pt)
        print("\(encodeHex(sender.encapsulatedKey)) \(encodeHex(ct))")

    case "p256-open":
        guard args.count == 5 else { throw VectorToolError.usage }
        let privBytes = try decodeHex(args[1])
        let info = try decodeHex(args[2])
        let enc = try decodeHex(args[3])
        let ct = try decodeHex(args[4])
        let privKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privBytes)
        var recipient = try HPKE.Recipient(
            privateKey: privKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info,
            encapsulatedKey: enc
        )
        let pt = try recipient.open(ct)
        print(encodeHex(pt))

    case "x25519-keygen":
        guard args.count == 1 else { throw VectorToolError.usage }
        let priv = Curve25519.KeyAgreement.PrivateKey()
        print("\(encodeHex(priv.rawRepresentation)) \(encodeHex(priv.publicKey.rawRepresentation))")

    case "x25519-seal":
        guard args.count == 4 else { throw VectorToolError.usage }
        let pubBytes = try decodeHex(args[1])
        let aad = try decodeHex(args[2])
        let pt = try decodeHex(args[3])
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubBytes)
        var sender = try HPKE.Sender(
            recipientKey: pubKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data()
        )
        let ct = try sender.seal(pt, authenticating: aad)
        var sealed = Data()
        sealed.append(sender.encapsulatedKey)
        sealed.append(ct)
        print(encodeHex(sealed))

    case "x25519-open":
        guard args.count == 4 else { throw VectorToolError.usage }
        let privBytes = try decodeHex(args[1])
        let aad = try decodeHex(args[2])
        let sealed = try decodeHex(args[3])
        guard sealed.count >= 32 else { throw VectorToolError.openFailed }
        let enc = sealed.prefix(32)
        let ct = sealed.dropFirst(32)
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privBytes)
        var recipient = try HPKE.Recipient(
            privateKey: privKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(),
            encapsulatedKey: enc
        )
        let pt = try recipient.open(ct, authenticating: aad)
        print(encodeHex(pt))

    default:
        throw VectorToolError.usage
    }
}

do {
    try run()
} catch {
    fputs("hpke-vectors: \(error)\n", stderr)
    exit(1)
}
