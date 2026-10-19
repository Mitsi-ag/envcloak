import CryptoKit
import Foundation
import os

public struct SealedEnvelopeHex: Sendable, Equatable {
    public let encHex: String
    public let ciphertextHex: String

    public init(encHex: String, ciphertextHex: String) {
        self.encHex = encHex
        self.ciphertextHex = ciphertextHex
    }
}

public enum SoftwareKeyError: Error, Equatable {
    case invalidParameters
    case sealFailed
}

/// Software P-256 stand-in for `UnlockKeyAgreement` in headless CI and unit tests (M3-11; gate g2).
public final class SoftwareUnlockKey: @unchecked Sendable {
    public let privateKey: P256.KeyAgreement.PrivateKey
    private let lock = NSLock()
    private var _openCount = 0
    private var _lastReason: String?
    public var simulatedFailure: (any Error)?

    public init(privateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyX963: Data {
        privateKey.publicKey.x963Representation
    }

    public var publicKeyHex: String {
        Self.encodeHex(publicKeyX963)
    }

    public var openCount: Int {
        lock.withLock { _openCount }
    }

    public var lastReason: String? {
        lock.withLock { _lastReason }
    }

    public func recordOpen(reason: String) throws {
        try lock.withLock {
            _openCount += 1
            _lastReason = reason
            if let err = simulatedFailure {
                throw err
            }
        }
    }

    public static func encodeHex(_ data: Data) -> String {
        let hexChars = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(hexChars[Int(byte >> 4)])
            out.append(hexChars[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func decodeHex(_ hex: String, expectedByteCount: Int? = nil) -> Data? {
        let utf8 = Array(hex.utf8)
        guard utf8.count.isMultiple(of: 2) else { return nil }
        let byteCount = utf8.count / 2
        if let expected = expectedByteCount, byteCount != expected {
            return nil
        }
        var data = Data(capacity: byteCount)
        var idx = 0
        while idx < utf8.count {
            guard let hi = hexValue(utf8[idx]), let lo = hexValue(utf8[idx + 1]) else {
                return nil
            }
            data.append((hi << 4) | lo)
            idx += 2
        }
        return data
    }

    private static func hexValue(_ ascii: UInt8) -> UInt8? {
        switch ascii {
        case 0x30...0x39: return ascii - 0x30
        case 0x41...0x46: return ascii - 0x41 + 10
        case 0x61...0x66: return ascii - 0x61 + 10
        default: return nil
        }
    }

    public static func hpkeInfo(vaultIDHex: String, unlockerIDHex: String, epoch: UInt32) -> Data? {
        guard let vaultID = decodeHex(vaultIDHex, expectedByteCount: 16),
              let unlockerID = decodeHex(unlockerIDHex, expectedByteCount: 16) else {
            return nil
        }
        var info = Data("envcloak/v1/unlocker/se".utf8)
        info.append(vaultID)
        info.append(unlockerID)
        var beEpoch = epoch.bigEndian
        withUnsafeBytes(of: &beEpoch) { info.append(contentsOf: $0) }
        return info
    }

    public static func resealAAD(requestID: String, challengeHex: String) -> Data? {
        guard !requestID.isEmpty,
              let challenge = decodeHex(challengeHex, expectedByteCount: 32) else {
            return nil
        }
        var aad = Data(requestID.utf8)
        aad.append(challenge)
        return aad
    }

    public static func sealEnvelopeHex(
        vmk: Data,
        recipientPublicKey: P256.KeyAgreement.PublicKey,
        vaultIDHex: String,
        unlockerIDHex: String,
        epoch: UInt32
    ) throws -> SealedEnvelopeHex {
        guard let info = hpkeInfo(vaultIDHex: vaultIDHex, unlockerIDHex: unlockerIDHex, epoch: epoch) else {
            throw SoftwareKeyError.invalidParameters
        }
        var sender = try HPKE.Sender(
            recipientKey: recipientPublicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info
        )
        let ct = try sender.seal(vmk)
        return SealedEnvelopeHex(
            encHex: encodeHex(sender.encapsulatedKey),
            ciphertextHex: encodeHex(ct)
        )
    }

    public static func openResealed(
        sealedHex: String,
        daemonPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        requestID: String,
        challengeHex: String
    ) throws -> Data {
        guard let sealed = decodeHex(sealedHex, expectedByteCount: 80),
              let aad = resealAAD(requestID: requestID, challengeHex: challengeHex) else {
            throw SoftwareKeyError.sealFailed
        }
        let enc = sealed.prefix(32)
        let ct = sealed.dropFirst(32)
        var recipient = try HPKE.Recipient(
            privateKey: daemonPrivateKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: Data(),
            encapsulatedKey: enc
        )
        return try recipient.open(ct, authenticating: aad)
    }
}

/// Software P-256 stand-in for `ApprovalSigner` in headless CI and unit tests (M3-11, M3-12; gate g2).
public final class SoftwareApprovalSigner: @unchecked Sendable {
    public let privateKey: P256.Signing.PrivateKey
    private let lock = NSLock()
    private var _signCount = 0
    private var _invalidatedCount = 0
    private var _lastReason: String?
    private var _lastStatementBytes: Data?
    public var simulatedFailure: (any Error)?
    public var signDelayNanoseconds: UInt64 = 0

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyX963: Data {
        privateKey.publicKey.x963Representation
    }

    public var publicKeyHex: String {
        SoftwareUnlockKey.encodeHex(publicKeyX963)
    }

    public var signCount: Int {
        lock.withLock { _signCount }
    }

    public var invalidatedCount: Int {
        lock.withLock { _invalidatedCount }
    }

    public var lastReason: String? {
        lock.withLock { _lastReason }
    }

    public var lastStatementBytes: Data? {
        lock.withLock { _lastStatementBytes }
    }

    public func invalidateActiveContext() {
        lock.withLock {
            _invalidatedCount += 1
        }
    }

    public func signRaw(_ statementBytes: Data, reason: String) async throws -> Data {
        let (delay, err) = lock.withLock {
            _signCount += 1
            _lastReason = reason
            _lastStatementBytes = statementBytes
            return (signDelayNanoseconds, simulatedFailure)
        }
        if delay > 0 {
            try await Task.sleep(nanoseconds: delay)
        }
        if let err {
            throw err
        }
        let digest = SHA256.hash(data: statementBytes)
        let signature = try privateKey.signature(for: digest)
        return signature.rawRepresentation
    }
}
