import CryptoKit
import Foundation
import LocalAuthentication
import os

public enum SignerError: Error, Equatable, Sendable {
    case invalidSignature
    case signingFailed
    case notInteractiveSession
    case userCancelled
    case keyStore(KeyStoreError)
}

/// A 64-byte raw P-256 ECDSA signature (`r (32) || s (32)`).
public struct P256RawSignature: Equatable, Sendable {
    public static let byteCount = 64

    public let rawRepresentation: Data

    public init(rawRepresentation: Data) throws(SignerError) {
        guard rawRepresentation.count == Self.byteCount else {
            throw .invalidSignature
        }
        self.rawRepresentation = rawRepresentation
    }

    public var hex: String {
        HexCoding.encode(rawRepresentation)
    }
}

/// Protocol seam for signing canonical approval or write statements with the
/// enrolled P-256 `approve` key (M3-11, M3-12; gate g2).
public protocol ApprovalSigner: Sendable {
    func sign(_ statementBytes: Data, reason: String) async throws -> P256RawSignature
    func invalidateActiveContext()
}

extension ApprovalSigner {
    public func invalidateActiveContext() {}
}

public final class SecureEnclaveApprovalSigner: ApprovalSigner, @unchecked Sendable {
    private let keyStore: KeyStore
    private let contextFactory: ContextFactory
    private let lock = NSLock()
    private var activeContext: LAContext?

    public init(keyStore: KeyStore = KeyStore(), contextFactory: ContextFactory = ContextFactory()) {
        self.keyStore = keyStore
        self.contextFactory = contextFactory
    }

    public func invalidateActiveContext() {
        let ctx = lock.withLock { () -> LAContext? in
            let old = activeContext
            activeContext = nil
            return old
        }
        ctx?.invalidate()
    }

    public func sign(_ statementBytes: Data, reason: String) async throws -> P256RawSignature {
        let context = contextFactory.make(reason: reason)
        lock.withLock { activeContext = context }
        defer {
            lock.withLock {
                if activeContext === context {
                    activeContext = nil
                }
            }
            context.invalidate()
        }

        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try keyStore.loadApproveKey(authenticationContext: context)
        } catch {
            throw SignerError.keyStore(error)
        }

        let digest = SHA256.hash(data: statementBytes)
        do {
            let signature = try key.signature(for: digest)
            return try P256RawSignature(rawRepresentation: signature.rawRepresentation)
        } catch let error as SignerError {
            throw error
        } catch {
            if ContextFactory.isNotInteractive(error) {
                throw SignerError.notInteractiveSession
            }
            if ContextFactory.isCancelled(error) {
                throw SignerError.userCancelled
            }
            throw SignerError.signingFailed
        }
    }
}
