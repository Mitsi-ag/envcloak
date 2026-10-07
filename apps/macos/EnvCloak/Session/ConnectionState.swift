import EnvCloakKit

enum ConnectionState: Equatable {
    case connecting, noDaemon, unverified(PeerCheck), noVault, locked, ready, readOnly, unavailable

    // The current metadata RPCs refuse a tampered vault (State.unlocked).
    var canReadMetadata: Bool { self == .ready }
    var canLock: Bool { self == .ready || self == .readOnly }

    var title: String {
        switch self {
        case .connecting: "Connecting to EnvCloak's background process"
        case .noDaemon: "No daemon answered, so no key was released."
        case .unverified: "EnvCloak could not verify its background process, so nothing was sent to it."
        case .noVault: "No vault yet."
        case .locked: "EnvCloak is locked. Agents get no keys until you unlock."
        case .ready: "Unlocked"
        case .readOnly: "The vault failed its integrity check, so it is open read-only."
        case .unavailable: "The vault is unavailable."
        }
    }
    var detail: String {
        switch self {
        case .noDaemon: "Start the background process, then try again."
        case .unverified(let check):
            switch check {
            case .directoryOwner: "The socket's folder is not yours."
            case .peerUID, .socketOwner: "Another user's process is listening."
            case .codeIdentity: "Its code signature is not EnvCloak's."
            default: "The socket's location or permissions could not be verified."
            }
        case .noVault: "Create one in Terminal with envcloak vault create."
        case .readOnly: "No approvals or changes are possible. Recover from a backup with your Recovery Kit."
        case .unavailable: "No metadata could be read. Check the vault in Terminal."
        default: ""
        }
    }
    var action: String? {
        switch self {
        case .connecting, .ready: nil
        case .noDaemon: "Start background process"
        case .unverified: "Show details"
        case .noVault: "Copy command"
        case .locked: "Copy envcloak unlock"
        case .readOnly: "How to recover"
        case .unavailable: "Copy envcloak status"
        }
    }
}
