// Fixed tokens from envcloak-ipc/proto.rs. The Rust vectors check parity.
public enum PeerCheck: String, Sendable {
    case directoryType, directoryOwner, directoryMode, parent, socketType, socketOwner
    case socketMode, socketOptions, peerUID, path, changed, codeIdentity
}

public enum EnvCloakError: Error, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case daemonUnavailable
    case daemonUnverified(PeerCheck)
    case rpc(ErrorKind, Reason?)
    case protocolError

    public var description: String {
        switch self {
        case .daemonUnavailable: "daemon_unavailable"
        case .daemonUnverified(let check): "daemon_unverified (" + check.rawValue + ")"
        case .rpc(let kind, let reason): kind.rawValue + (reason.map { " (" + $0.rawValue + ")" } ?? "")
        case .protocolError: "protocol_error"
        }
    }
    public var debugDescription: String { description }
}

public enum ErrorKind: String, CaseIterable, Sendable {
    case parseError = "parse_error"
    case invalidRequest = "invalid_request"
    case methodNotFound = "method_not_found"
    case invalidParams = "invalid_params"
    case roleDenied = "role_denied"
    case vaultLocked = "vault_locked"
    case noVault = "no_vault"
    case vaultExists = "vault_exists"
    case wrongPassphrase = "wrong_passphrase"
    case passphraseRejected = "passphrase_rejected"
    case kdfParams = "kdf_params"
    case busy = "busy"
    case traced = "traced"
    case vaultUnavailable = "vault_unavailable"
    case frameTooLarge = "frame_too_large"
    case evidence = "evidence"
    case manifestInvalid = "manifest_invalid"
    case bindingUnresolved = "binding_unresolved"
    case policyDenied = "policy_denied"
    case modeUnsupported = "mode_unsupported"
    case noSuchRequest = "no_such_request"
    case statementMismatch = "statement_mismatch"
    case proofRefused = "proof_refused"
    case tooManyAttempts = "too_many_attempts"
    case vaultTampered = "vault_tampered"
    case tooManyGrants = "too_many_grants"
    case invalidOptions = "invalid_options"
    case auditUnavailable = "audit_unavailable"
    case noSuchItem = "no_such_item"
    case itemExists = "item_exists"
    case invalidItem = "invalid_item"
    case backupFailed = "backup_failed"
    case planChanged = "plan_changed"
    case noSuchBackup = "no_such_backup"
    case filesBackupFailed = "files_backup_failed"
    case tooManyChecks = "too_many_checks"
    case auditFailed = "audit_failed"
    case backupUnusable = "backup_unusable"
    case tooManyPending = "too_many_pending"
    case notBackupOwner = "not_backup_owner"
    case restoreRefused = "restore_refused"
    case noSuchLease = "no_such_lease"
    case backupFrozen = "backup_frozen"
    case loginReference = "login_reference"
    case liveNotTicked = "live_not_ticked"
    case managedCommandMismatch = "managed_command_mismatch"
    case managedLaunchChanged = "managed_launch_changed"
    case codeSelectingEnv = "code_selecting_env"
    case runnerUnavailable = "runner_unavailable"
    case `internal` = "internal"

    public var code: Int64 {
        switch self {
        case .parseError: -32700
        case .invalidRequest: -32600
        case .methodNotFound: -32601
        case .invalidParams: -32602
        case .roleDenied: -32001
        case .vaultLocked: -32002
        case .noVault: -32003
        case .vaultExists: -32004
        case .wrongPassphrase: -32005
        case .passphraseRejected: -32006
        case .kdfParams: -32007
        case .busy: -32008
        case .traced: -32009
        case .vaultUnavailable: -32010
        case .frameTooLarge: -32011
        case .evidence: -32012
        case .manifestInvalid: -32013
        case .bindingUnresolved: -32014
        case .policyDenied: -32015
        case .modeUnsupported: -32016
        case .noSuchRequest: -32017
        case .statementMismatch: -32018
        case .proofRefused: -32019
        case .tooManyAttempts: -32020
        case .vaultTampered: -32021
        case .tooManyGrants: -32022
        case .invalidOptions: -32023
        case .auditUnavailable: -32024
        case .noSuchItem: -32025
        case .itemExists: -32026
        case .invalidItem: -32027
        case .backupFailed: -32028
        case .planChanged: -32029
        case .noSuchBackup: -32030
        case .filesBackupFailed: -32031
        case .tooManyChecks: -32032
        case .auditFailed: -32033
        case .backupUnusable: -32034
        case .tooManyPending: -32035
        case .notBackupOwner: -32036
        case .restoreRefused: -32048
        case .noSuchLease: -32049
        case .backupFrozen: -32050
        case .loginReference: -32037
        case .liveNotTicked: -32038
        case .managedCommandMismatch: -32039
        case .managedLaunchChanged: -32040
        case .codeSelectingEnv: -32041
        case .runnerUnavailable: -32042
        case .internal: -32099
        }
    }
}

public enum Reason: String, CaseIterable, Sendable {
    case not_text
    case not_utf8
    case control_character
    case too_short
    case common
    case busy
    case damaged
    case unsupported_version
    case permissions
    case disk_full
    case storage
    case io
    case migration
    case caller_gone
    case ancestry_changed
    case ancestry_hidden
    case ancestry_unreadable
    case caller_is_init
    case too_large
    case syntax
    case duplicate_key
    case unknown_key
    case wrong_type
    case invalid_env_name
    case invalid_profile_name
    case nested_profile
    case invalid_reference
    case invalid_project_name
    case loose_policy
    case invalid_policy
    case unknown_profile
    case duplicate_env_name
    case invalid_path
    case not_found
    case symlinked_manifest
    case not_regular_file
    case not_owned
    case directory_changed
    case unknown_item
    case unknown_field
    case ambiguous_field
    case no_field
    case card_reference
    case issuer_credential_reference
    case unknown_item_class
    case ttl_zero
    case ttl_too_long
    case live_not_bound
    case repeated
    case root_denied
    case denials_full
    case audit_failed
    case pending_per_root
    case pending_total
    case item_changed
    case invalid_slug
    case invalid_field
    case unknown_provider
    case invalid_account
    case looks_like_value
    case empty_value
    case nul_byte
    case value_too_large
    case no_free_slug
    case requester_terminal
    case result_unrecorded
    case created_by_agent
    case substituted
    case limited
    case code_selecting_variable
    case interpreter_option
    case wrapper_program
    case disguised_launcher
    case key_shaped
    case invalid_header
    case header_bindings
}
