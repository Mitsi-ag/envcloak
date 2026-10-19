import CryptoKit
import Darwin
import Foundation
import LocalAuthentication

public enum SEUnlockError: Error, Equatable, Sendable {
    case invalidChallenge
    case invalidEnvelope
    case openFailed
    case sealFailed
    case notInteractiveSession
    case userCancelled
    case keyStore(KeyStoreError)
}

/// Protocol seam for opening the vault's HPKE P-256 envelope and resealing the
/// 32-byte VMK to the daemon's single-use X25519 public key (M3-11; gate g2).
public protocol UnlockKeyAgreement: Sendable {
    func openAndReseal(_ begin: AppUnlockBeginView, reason: String) async throws -> String
}

public enum SEHPKE {
    public static let infoPrefix = Array("envcloak/v1/unlocker/se".utf8)
    public static let vmkByteCount = 32
    public static let resealByteCount = 80

    public static func hpkeInfo(vaultIDHex: String, unlockerIDHex: String, epoch: UInt32) throws(SEUnlockError) -> Data {
        guard let vaultID = HexCoding.decode(vaultIDHex, expectedByteCount: 16),
              let unlockerID = HexCoding.decode(unlockerIDHex, expectedByteCount: 16) else {
            throw .invalidEnvelope
        }
        var out = Data(capacity: infoPrefix.count + 16 + 16 + 4)
        out.append(contentsOf: infoPrefix)
        out.append(vaultID)
        out.append(unlockerID)
        out.append(UInt8((epoch >> 24) & 0xFF))
        out.append(UInt8((epoch >> 16) & 0xFF))
        out.append(UInt8((epoch >> 8) & 0xFF))
        out.append(UInt8(epoch & 0xFF))
        return out
    }

    public static func resealAAD(requestID: String, challengeHex: String) throws(SEUnlockError) -> Data {
        guard !requestID.isEmpty,
              let challenge = HexCoding.decode(challengeHex, expectedByteCount: 32) else {
            throw .invalidChallenge
        }
        var aad = Data(requestID.utf8)
        aad.append(challenge)
        return aad
    }

    public static func openAndResealWithKey<K: HPKEDiffieHellmanPrivateKey>(
        _ begin: AppUnlockBeginView,
        privateKey: K
    ) throws(SEUnlockError) -> String {
        guard let enc = HexCoding.decode(begin.envelope.enc.raw, expectedByteCount: 65),
              let ciphertext = HexCoding.decode(begin.envelope.ciphertext.raw, expectedByteCount: 48),
              let daemonPubBytes = HexCoding.decode(begin.daemon_eph_pub.raw, expectedByteCount: 32) else {
            throw .invalidEnvelope
        }
        let info = try Self.hpkeInfo(
            vaultIDHex: begin.vault_id.raw,
            unlockerIDHex: begin.unlocker_id.raw,
            epoch: begin.epoch
        )
        let aad = try Self.resealAAD(
            requestID: begin.request_id.raw,
            challengeHex: begin.challenge.raw
        )

        do {
            var vmkBuffer = try SecretBuffer(capacity: vmkByteCount)
            var recipient = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: .P256_SHA256_AES_GCM_256,
                info: info,
                encapsulatedKey: enc
            )
            var opened = try recipient.open(ciphertext)
            defer {
                opened.withUnsafeMutableBytes { ptr in
                    if let base = ptr.baseAddress {
                        _ = memset_s(base, ptr.count, 0, ptr.count)
                    }
                }
            }
            guard opened.count == vmkByteCount else {
                throw SEUnlockError.openFailed
            }
            try opened.withUnsafeBytes { rawPtr in
                try vmkBuffer.append(contentsOf: rawPtr)
            }
            return try Self.sealVMK(vmkBuffer, daemonPubBytes: daemonPubBytes, aad: aad)
        } catch let error as SEUnlockError {
            throw error
        } catch {
            if ContextFactory.isNotInteractive(error) {
                throw .notInteractiveSession
            }
            if ContextFactory.isCancelled(error) {
                throw .userCancelled
            }
            throw .openFailed
        }
    }

    private static func sealVMK(
        _ vmkBuffer: borrowing SecretBuffer,
        daemonPubBytes: Data,
        aad: Data
    ) throws(SEUnlockError) -> String {
        do {
            let daemonPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: daemonPubBytes)
            var sender = try HPKE.Sender(
                recipientKey: daemonPub,
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: Data()
            )
            let sealedCiphertext = try vmkBuffer.withUnsafeBytes { vmkBytes in
                try sender.seal(vmkBytes, authenticating: aad)
            }
            let encapped = sender.encapsulatedKey
            guard encapped.count == 32, sealedCiphertext.count == 48 else {
                throw SEUnlockError.sealFailed
            }
            var combined = Data(capacity: resealByteCount)
            combined.append(encapped)
            combined.append(sealedCiphertext)
            return HexCoding.encode(combined)
        } catch let error as SEUnlockError {
            throw error
        } catch {
            throw .sealFailed
        }
    }
}

public struct SecureEnclaveUnlockKey: UnlockKeyAgreement {
    private let keyStore: KeyStore
    private let contextFactory: ContextFactory

    public init(keyStore: KeyStore = KeyStore(), contextFactory: ContextFactory = ContextFactory()) {
        self.keyStore = keyStore
        self.contextFactory = contextFactory
    }

    public func openAndReseal(_ begin: AppUnlockBeginView, reason: String = ContextFactory.unlockReason) async throws -> String {
        let context = contextFactory.make(reason: reason)
        defer { context.invalidate() }
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try keyStore.loadUnlockKey(authenticationContext: context)
        } catch {
            throw SEUnlockError.keyStore(error)
        }
        return try SEHPKE.openAndResealWithKey(begin, privateKey: key)
    }
}
