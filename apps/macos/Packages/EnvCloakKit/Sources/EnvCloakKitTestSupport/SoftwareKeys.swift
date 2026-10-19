import CryptoKit
import EnvCloakKit
import Foundation
import os

/// Software P-256 stand-in for `UnlockKeyAgreement` in headless CI and unit tests (M3-11; gate g2).
public final class SoftwareUnlockKey: UnlockKeyAgreement, @unchecked Sendable {
    public let privateKey: P256.KeyAgreement.PrivateKey
    private let lock = NSLock()
    private var _openCount = 0
    private var _lastReason: String?
    public var simulatedError: SEUnlockError?

    public init(privateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyX963: Data {
        privateKey.publicKey.x963Representation
    }

    public var publicKeyHex: String {
        HexCoding.encode(publicKeyX963)
    }

    public var openCount: Int {
        lock.withLock { _openCount }
    }

    public var lastReason: String? {
        lock.withLock { _lastReason }
    }

    public func openAndReseal(_ begin: AppUnlockBeginView, reason: String) async throws -> String {
        try lock.withLock {
            _openCount += 1
            _lastReason = reason
            if let err = simulatedError {
                throw err
            }
        }
        return try SEHPKE.openAndResealWithKey(begin, privateKey: privateKey)
    }

    public static func sealEnvelope(
        vmk: Data,
        recipientPublicKey: P256.KeyAgreement.PublicKey,
        vaultIDHex: String,
        unlockerIDHex: String,
        epoch: UInt32
    ) throws -> SeEnvelopeView {
        let info = try SEHPKE.hpkeInfo(vaultIDHex: vaultIDHex, unlockerIDHex: unlockerIDHex, epoch: epoch)
        var sender = try HPKE.Sender(
            recipientKey: recipientPublicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: info
        )
        let ct = try sender.seal(vmk)
        return SeEnvelopeView(
            enc: DaemonText(HexCoding.encode(sender.encapsulatedKey)),
            ciphertext: DaemonText(HexCoding.encode(ct))
        )
    }

    public static func openResealed(
        sealedHex: String,
        daemonPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        requestID: String,
        challengeHex: String
    ) throws -> Data {
        guard let sealed = HexCoding.decode(sealedHex, expectedByteCount: SEHPKE.resealByteCount) else {
            throw SEUnlockError.sealFailed
        }
        let enc = sealed.prefix(32)
        let ct = sealed.dropFirst(32)
        let aad = try SEHPKE.resealAAD(requestID: requestID, challengeHex: challengeHex)
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
public final class SoftwareApprovalSigner: ApprovalSigner, @unchecked Sendable {
    public let privateKey: P256.Signing.PrivateKey
    private let lock = NSLock()
    private var _signCount = 0
    private var _invalidatedCount = 0
    private var _lastReason: String?
    private var _lastStatementBytes: Data?
    public var simulatedError: SignerError?
    public var signDelayNanoseconds: UInt64 = 0

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyX963: Data {
        privateKey.publicKey.x963Representation
    }

    public var publicKeyHex: String {
        HexCoding.encode(publicKeyX963)
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

    public func sign(_ statementBytes: Data, reason: String) async throws -> P256RawSignature {
        let (delay, err) = lock.withLock {
            _signCount += 1
            _lastReason = reason
            _lastStatementBytes = statementBytes
            return (signDelayNanoseconds, simulatedError)
        }
        if delay > 0 {
            try await Task.sleep(nanoseconds: delay)
        }
        if let err {
            throw err
        }
        let digest = SHA256.hash(data: statementBytes)
        let signature = try privateKey.signature(for: digest)
        return try P256RawSignature(rawRepresentation: signature.rawRepresentation)
    }
}
