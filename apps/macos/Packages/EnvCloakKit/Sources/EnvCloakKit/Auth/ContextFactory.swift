import Foundation
import LocalAuthentication

public enum BiometryWording: String, Sendable, Equatable {
    case touchID
    case password

    public var approveButtonTitle: String {
        switch self {
        case .touchID: "Approve with Touch ID"
        case .password: "Approve with password"
        }
    }

    public var unlockButtonTitle: String {
        switch self {
        case .touchID: "Unlock with Touch ID"
        case .password: "Unlock with password"
        }
    }

    public var replaceButtonTitle: String {
        switch self {
        case .touchID: "Replace with Touch ID"
        case .password: "Replace with password"
        }
    }

    public var removeButtonTitle: String {
        switch self {
        case .touchID: "Remove with Touch ID"
        case .password: "Remove with password"
        }
    }

    public var revealButtonTitle: String {
        switch self {
        case .touchID: "Reveal with Touch ID"
        case .password: "Reveal with password"
        }
    }
}

/// Builds a fresh `LAContext` per unlock, approval, reveal or signed write
/// with `touchIDAuthenticationAllowableReuseDuration = 0` (SPEC §5, §10b;
/// gate g3). No context is ever reused across operations.
public struct ContextFactory: Sendable {
    public static let unlockReason = "unlock your vault"
    public let wordingOverride: BiometryWording?

    public init(wordingOverride: BiometryWording? = nil) {
        self.wordingOverride = wordingOverride
    }

    public func make(reason: String) -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = Self.sanitizedReason(reason)
        return context
    }

    public func wording() -> BiometryWording {
        if let wordingOverride {
            return wordingOverride
        }
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if context.biometryType == .touchID, error == nil {
            return .touchID
        }
        return .password
    }

    public static func approvalReason(command: String, project: String, keyCount: Int) -> String {
        let keyWord = keyCount == 1 ? "key" : "keys"
        return "approve \(command) in \(project) with \(keyCount) \(keyWord)"
    }

    public static func replaceReason(slug: String, field: String? = nil) -> String {
        if let field, !field.isEmpty, field != "value" {
            return "replace \(slug)#\(field)"
        }
        return "replace \(slug)"
    }

    public static func removeReason(slug: String) -> String {
        "remove \(slug)"
    }

    public static func revealReason(slug: String, field: String? = nil) -> String {
        if let field, !field.isEmpty, field != "value" {
            return "reveal \(slug)#\(field)"
        }
        return "reveal \(slug)"
    }

    public static func unlockerAddReason(label: String) -> String {
        "add Touch ID unlocker \(label)"
    }

    public static func unlockerRemoveReason(target: String) -> String {
        "remove \(target) unlocker"
    }

    public static func sanitizedReason(_ reason: String) -> String {
        let trimmed = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("envcloak ") {
            return String(trimmed.dropFirst(9)).trimmingCharacters(in: .whitespaces)
        }
        return trimmed.isEmpty ? unlockReason : trimmed
    }

    public static func isNotInteractive(_ error: any Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == LAErrorDomain && nsError.code == LAError.notInteractive.rawValue
    }

    public static func isCancelled(_ error: any Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == LAErrorDomain else { return false }
        return nsError.code == LAError.userCancel.rawValue
            || nsError.code == LAError.appCancel.rawValue
            || nsError.code == LAError.systemCancel.rawValue
    }
}
