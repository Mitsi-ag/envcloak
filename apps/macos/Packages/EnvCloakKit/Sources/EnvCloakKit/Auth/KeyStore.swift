import CryptoKit
import Foundation
import LocalAuthentication
import Security

public enum KeyStoreError: Error, Equatable, Sendable {
    case secureEnclaveUnavailable
    case accessControlCreationFailed(OSStatus)
    case keychainFailure(OSStatus)
    case keysNotEnrolled
    case invalidKeyData
    case notInteractiveSession
    case userCancelled
}

public struct EnrolledPublicKeys: Sendable, Equatable {
    /// 65-byte SEC1 uncompressed P-256 `unlock` public key as 130 lowercase hex characters.
    public let unlockPublicKeyHex: String
    /// 65-byte SEC1 uncompressed P-256 `approve` public key as 130 lowercase hex characters.
    public let approvePublicKeyHex: String

    public init(unlockPublicKeyHex: String, approvePublicKeyHex: String) {
        self.unlockPublicKeyHex = unlockPublicKeyHex
        self.approvePublicKeyHex = approvePublicKeyHex
    }
}

public protocol KeyBlobStorage: Sendable {
    func readBlob(account: String) throws(KeyStoreError) -> Data?
    func writeBlob(_ data: Data, account: String) throws(KeyStoreError)
    func deleteBlob(account: String) throws(KeyStoreError)
}

/// Persists opaque Secure Enclave key blobs exclusively in the macOS data
/// protection keychain (`WhenUnlockedThisDeviceOnly`, `Synchronizable = false`),
/// never in a file or defaults store (SPEC §5, R-M3-18).
public struct DataProtectionKeychainBlobStorage: KeyBlobStorage {
    public let service: String
    public let accessGroup: String?
    public let enabled: Bool

    public init(
        service: String = "ai.envcloak.se-keys",
        accessGroup: String? = nil,
        enabled: Bool = true
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.enabled = enabled
    }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public func readBlob(account: String) throws(KeyStoreError) -> Data? {
        guard enabled else { return nil }
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw .keychainFailure(status)
        }
        guard let data = item as? Data else {
            throw .invalidKeyData
        }
        return data
    }

    public func writeBlob(_ data: Data, account: String) throws(KeyStoreError) {
        guard enabled else { return }
        try deleteBlob(account: account)
        var attributes = baseQuery(account: account)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = data
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw .keychainFailure(status)
        }
    }

    public func deleteBlob(account: String) throws(KeyStoreError) {
        guard enabled else { return }
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw .keychainFailure(status)
        }
    }
}

public struct KeyStore: Sendable {
    public static let unlockAccount = "unlock"
    public static let approveAccount = "approve"

    private let storage: any KeyBlobStorage

    public init(storage: any KeyBlobStorage = DataProtectionKeychainBlobStorage()) {
        self.storage = storage
    }

    public static var isSecureEnclaveAvailable: Bool {
        SecureEnclave.isAvailable
    }

    public func hasEnrolledKeys() -> Bool {
        guard let unlock = try? storage.readBlob(account: Self.unlockAccount),
              let approve = try? storage.readBlob(account: Self.approveAccount) else {
            return false
        }
        return !unlock.isEmpty && !approve.isEmpty
    }

    public static func makeAccessControl(touchIDOnly: Bool = false) throws(KeyStoreError) -> SecAccessControl {
        let flags: SecAccessControlCreateFlags = touchIDOnly
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .userPresence]
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            throw .accessControlCreationFailed(errSecParam)
        }
        return ac
    }

    /// Creates or loads the `unlock` and `approve` Secure Enclave P-256 keys,
    /// stores their opaque `dataRepresentation` in the data protection keychain,
    /// and returns their 65-byte uncompressed SEC1 public keys as lowercase hex.
    public func loadOrCreatePublicKeys(touchIDOnly: Bool = false) throws(KeyStoreError) -> EnrolledPublicKeys {
        guard SecureEnclave.isAvailable else {
            throw .secureEnclaveUnavailable
        }
        if let unlockBlob = try storage.readBlob(account: Self.unlockAccount),
           let approveBlob = try storage.readBlob(account: Self.approveAccount),
           let unlockKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: unlockBlob),
           let approveKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: approveBlob) {
            return EnrolledPublicKeys(
                unlockPublicKeyHex: HexCoding.encode(unlockKey.publicKey.x963Representation),
                approvePublicKeyHex: HexCoding.encode(approveKey.publicKey.x963Representation)
            )
        }
        let accessControl = try Self.makeAccessControl(touchIDOnly: touchIDOnly)
        guard let unlockKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl),
              let approveKey = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl) else {
            throw .secureEnclaveUnavailable
        }
        try storage.writeBlob(unlockKey.dataRepresentation, account: Self.unlockAccount)
        try storage.writeBlob(approveKey.dataRepresentation, account: Self.approveAccount)
        return EnrolledPublicKeys(
            unlockPublicKeyHex: HexCoding.encode(unlockKey.publicKey.x963Representation),
            approvePublicKeyHex: HexCoding.encode(approveKey.publicKey.x963Representation)
        )
    }

    public func loadUnlockKey(authenticationContext: LAContext) throws(KeyStoreError) -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw .secureEnclaveUnavailable
        }
        guard let blob = try storage.readBlob(account: Self.unlockAccount) else {
            throw .keysNotEnrolled
        }
        guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob,
            authenticationContext: authenticationContext
        ) else {
            throw .invalidKeyData
        }
        return key
    }

    public func loadApproveKey(authenticationContext: LAContext) throws(KeyStoreError) -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw .secureEnclaveUnavailable
        }
        guard let blob = try storage.readBlob(account: Self.approveAccount) else {
            throw .keysNotEnrolled
        }
        guard let key = try? SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: blob,
            authenticationContext: authenticationContext
        ) else {
            throw .invalidKeyData
        }
        return key
    }

    public struct StagedKeyPair: Sendable, Equatable {
        public let keys: EnrolledPublicKeys
        public let unlockBlob: Data
        public let approveBlob: Data

        public init(keys: EnrolledPublicKeys, unlockBlob: Data, approveBlob: Data) {
            self.keys = keys
            self.unlockBlob = unlockBlob
            self.approveBlob = approveBlob
        }
    }

    public func stageNewPublicKeys(touchIDOnly: Bool) throws(KeyStoreError) -> StagedKeyPair {
        guard SecureEnclave.isAvailable else {
            throw .secureEnclaveUnavailable
        }
        let accessControl = try Self.makeAccessControl(touchIDOnly: touchIDOnly)
        guard let unlockKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl),
              let approveKey = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl) else {
            throw .secureEnclaveUnavailable
        }
        let keys = EnrolledPublicKeys(
            unlockPublicKeyHex: HexCoding.encode(unlockKey.publicKey.x963Representation),
            approvePublicKeyHex: HexCoding.encode(approveKey.publicKey.x963Representation)
        )
        return StagedKeyPair(
            keys: keys,
            unlockBlob: unlockKey.dataRepresentation,
            approveBlob: approveKey.dataRepresentation
        )
    }

    public func commitStagedKeys(_ staged: StagedKeyPair) throws(KeyStoreError) {
        try storage.writeBlob(staged.unlockBlob, account: Self.unlockAccount)
        try storage.writeBlob(staged.approveBlob, account: Self.approveAccount)
    }

    public func deleteKeys() throws(KeyStoreError) {
        try storage.deleteBlob(account: Self.unlockAccount)
        try storage.deleteBlob(account: Self.approveAccount)
    }
}

public enum HexCoding {
    private static let digits = Array("0123456789abcdef".utf8)

    public static func encode<D: DataProtocol>(_ data: D) -> String {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(data.count * 2)
        for b in data {
            bytes.append(digits[Int(b >> 4)])
            bytes.append(digits[Int(b & 0x0f)])
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    public static func decode(_ hex: String, expectedByteCount: Int? = nil) -> Data? {
        let utf8 = Array(hex.utf8)
        guard utf8.count % 2 == 0 else { return nil }
        if let expectedByteCount, utf8.count != expectedByteCount * 2 {
            return nil
        }
        var out = Data(capacity: utf8.count / 2)
        func nibble(_ b: UInt8) -> UInt8? {
            switch b {
            case 48...57: return b - 48
            case 65...70: return b - 55
            case 97...102: return b - 87
            default: return nil
            }
        }
        for i in stride(from: 0, to: utf8.count, by: 2) {
            guard let hi = nibble(utf8[i]), let lo = nibble(utf8[i + 1]) else {
                return nil
            }
            out.append((hi << 4) | lo)
        }
        return out
    }
}
