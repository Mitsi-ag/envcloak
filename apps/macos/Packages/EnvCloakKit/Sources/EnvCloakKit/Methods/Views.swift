// Typed metadata from IPC.md. Every nested object refuses unknown fields.

public enum SubjectKind: String, Sendable, WireDecodable {
    case `agent` = "agent"
    case `terminal` = "terminal"
    case `unknown` = "unknown"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum Mode: String, Sendable, WireDecodable {
    case `inject` = "inject"
    case `proxy` = "proxy"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum Uses: String, Sendable, WireDecodable {
    case `once` = "once"
    case `session` = "session"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum VaultState: String, Sendable, WireDecodable {
    case `absent` = "absent"
    case `locked` = "locked"
    case `unlocked` = "unlocked"
    case `unavailable` = "unavailable"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum Integrity: String, Sendable, WireDecodable {
    case `ok` = "ok"
    case `tampered` = "tampered"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum LockReason: String, Sendable, WireDecodable {
    case `request` = "request"
    case `idle` = "idle"
    case `sleep` = "sleep"
    case `signal` = "signal"
    case `restore` = "restore"
    case `screenLock` = "screen_lock"
    case `sessionResign` = "session_resign"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum KeychainAnchorState: String, Sendable, WireDecodable {
    case `matched` = "matched"
    case `ahead` = "ahead"
    case `missing` = "missing"
    case `none` = "none"
    case `unavailable` = "unavailable"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum AuditProblemKind: String, Sendable, WireDecodable {
    case `altered` = "altered"
    case `chainBroken` = "chain_broken"
    case `missing` = "missing"
    case `reordered` = "reordered"
    case `segmentDamaged` = "segment_damaged"
    case `unreadable` = "unreadable"
    case `anchorMismatch` = "anchor_mismatch"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum AnchorState: String, Sendable, WireDecodable {
    case `none` = "none"
    case `matched` = "matched"
    case `mismatch` = "mismatch"
    case `missing` = "missing"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum ExposureSourceView: String, Sendable, WireDecodable {
    case `transcript` = "transcript"
    case `gitHistory` = "git_history"
    case `configBackup` = "config_backup"
    case `syncedFolder` = "synced_folder"
    case `shellProfile` = "shell_profile"
    case `agentConfig` = "agent_config"
    case `envFile` = "env_file"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum ItemClassView: String, Sendable, WireDecodable {
    case `secret` = "secret"
    case `card` = "card"
    case `issuerCredential` = "issuer_credential"
    case `login` = "login"
    case `other` = "other"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum ClassificationView: String, Sendable, WireDecodable {
    case `unknown` = "unknown"
    case `test` = "test"
    case `live` = "live"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum LengthClass: String, Sendable, WireDecodable {
    case `ok` = "ok"
    case `short` = "short"
    case `tooShort` = "too_short"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public enum RefStatus: String, Sendable, WireDecodable {
    case `ok` = "ok"
    case `unknownItem` = "unknown_item"
    case `unknownField` = "unknown_field"
    case `ambiguousField` = "ambiguous_field"
    case `noField` = "no_field"
    case `cardReference` = "card_reference"
    case `issuerCredentialReference` = "issuer_credential_reference"
    case `unknownItemClass` = "unknown_item_class"
    case `loginReference` = "login_reference"
    case `invalidReference` = "invalid_reference"
    case `looksLikeValue` = "looks_like_value"
    case `unchecked` = "unchecked"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public struct StatusView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `daemon`: DaemonView
    public let `vault`: VaultView
    public let `lock`: LockView
    public let `approvals`: ApprovalsView
    public let `audit`: AuditStatusView
    public let `app_requests`: UInt32
    public var description: String { "[StatusView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["daemon", "vault", "lock", "approvals", "audit", "app_requests"])
        self.`daemon` = try o.decode("daemon")
        self.`vault` = try o.decode("vault")
        self.`lock` = try o.decode("lock")
        self.`approvals` = try o.decode("approvals")
        self.`audit` = try o.decode("audit")
        self.`app_requests` = try o.optional("app_requests") ?? 0
    }
}

public struct DaemonView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `version`: String
    public let `pid`: UInt32
    public let `hardening`: HardeningView
    public let `runtime_dir_fallback`: Bool
    public var description: String { "[DaemonView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["version", "pid", "hardening", "runtime_dir_fallback"])
        self.`version` = Self.sanitizeVersion(try o.decode("version"))
        self.`pid` = try o.decode("pid")
        self.`hardening` = try o.decode("hardening")
        self.`runtime_dir_fallback` = try o.decode("runtime_dir_fallback")
    }
    private static func sanitizeVersion(_ text: String) -> String {
        let ok = (1...32).contains(text.utf8.count) && text.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [43, 45, 46].contains($0)
        }
        return ok ? text : "unrecognized"
    }
}

public struct HardeningView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `core_dumps_off`: Bool
    public let `non_dumpable`: Bool
    public let `hardened_runtime`: Bool?
    public var description: String { "[HardeningView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["core_dumps_off", "non_dumpable", "hardened_runtime"])
        self.`core_dumps_off` = try o.decode("core_dumps_off")
        self.`non_dumpable` = try o.decode("non_dumpable")
        self.`hardened_runtime` = try o.optional("hardened_runtime")
    }
}

public struct VaultView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `state`: VaultState
    public let `integrity`: Integrity?
    public let `read_only`: Bool
    public let `unavailable`: String?
    public let `busy`: Bool
    public let `failed_unlocks`: UInt32
    public let `keychain_anchor`: KeychainAnchorState
    public var description: String { "[VaultView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["state", "integrity", "read_only", "unavailable", "busy", "failed_unlocks", "keychain_anchor"])
        self.`state` = try o.decode("state")
        self.`integrity` = try o.optional("integrity")
        self.`read_only` = try o.decode("read_only")
        self.`unavailable` = try o.optional("unavailable", as: String.self).map {
            switch $0 {
            case "damaged", "unsupported_version", "permissions", "disk_full", "storage", "io", "migration", "busy": $0
            default: "unknown"
            }
        }
        self.`busy` = try o.decode("busy")
        self.`failed_unlocks` = try o.decode("failed_unlocks")
        self.`keychain_anchor` = try o.optional("keychain_anchor") ?? .unavailable
    }
}

public struct LockView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `last_reason`: LockReason?
    public let `idle_limit_secs`: UInt64
    public let `idle_remaining_secs`: UInt64?
    public var description: String { "[LockView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["last_reason", "idle_limit_secs", "idle_remaining_secs"])
        self.`last_reason` = try o.optional("last_reason")
        self.`idle_limit_secs` = try o.decode("idle_limit_secs")
        self.`idle_remaining_secs` = try o.optional("idle_remaining_secs")
    }
}

public struct ApprovalsView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `grants`: UInt32
    public let `pending`: UInt32
    public let `standing`: UInt32
    public let `policy_epoch_unverified`: Bool
    public let `proof_failures`: UInt32
    public let `proof_wait_secs`: UInt64
    public var description: String { "[ApprovalsView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["grants", "pending", "standing", "policy_epoch_unverified", "proof_failures", "proof_wait_secs"])
        self.`grants` = try o.decode("grants")
        self.`pending` = try o.decode("pending")
        self.`standing` = try o.optional("standing") ?? 0
        self.`policy_epoch_unverified` = try o.optional("policy_epoch_unverified") ?? false
        self.`proof_failures` = try o.decode("proof_failures")
        self.`proof_wait_secs` = try o.decode("proof_wait_secs")
    }
}

public struct AuditStatusView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `open`: Bool
    public let `head_seq`: UInt64?
    public let `unanchored`: UInt64
    public let `anchor_failed`: Bool
    public let `queued`: UInt64
    public let `dropped`: UInt64
    public var description: String { "[AuditStatusView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["open", "head_seq", "unanchored", "anchor_failed", "queued", "dropped"])
        self.`open` = try o.decode("open")
        self.`head_seq` = try o.optional("head_seq")
        self.`unanchored` = try o.decode("unanchored")
        self.`anchor_failed` = try o.decode("anchor_failed")
        self.`queued` = try o.decode("queued")
        self.`dropped` = try o.decode("dropped")
    }
}

public struct DeniedView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `root_auto_denied`: Bool
    public var description: String { "[DeniedView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["root_auto_denied"])
        self.`root_auto_denied` = try o.decode("root_auto_denied")
    }
}

public struct GrantsView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `grants`: [GrantView]
    public var description: String { "[GrantsView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["grants"])
        self.`grants` = try o.decode("grants")
    }
}

public struct GrantView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `id`: DaemonText
    public let `kind`: SubjectKind
    public let `label`: DaemonText?
    public let `root_pid`: Int32
    public let `root_exe`: DaemonText?
    public let `project_dir`: DaemonText
    public let `bindings`: [GrantBindingView]
    public let `mode`: Mode
    public let `uses`: Uses
    public let `created_secs`: UInt64
    public let `remaining_secs`: UInt64
    public var description: String { "[GrantView]" }
    public var debugDescription: String { description }
    public init(id: DaemonText, kind: SubjectKind, label: DaemonText? = nil, root_pid: Int32, root_exe: DaemonText? = nil,
                project_dir: DaemonText, bindings: [GrantBindingView], mode: Mode, uses: Uses,
                created_secs: UInt64, remaining_secs: UInt64) {
        self.id = id
        self.kind = kind
        self.label = label
        self.root_pid = root_pid
        self.root_exe = root_exe
        self.project_dir = project_dir
        self.bindings = bindings
        self.mode = mode
        self.uses = uses
        self.created_secs = created_secs
        self.remaining_secs = remaining_secs
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["id", "kind", "label", "root_pid", "root_exe", "project_dir", "bindings", "mode", "uses", "created_secs", "remaining_secs"])
        self.`id` = try o.decode("id")
        self.`kind` = try o.decode("kind")
        self.`label` = try o.optional("label")
        self.`root_pid` = try o.decode("root_pid")
        self.`root_exe` = try o.optional("root_exe")
        self.`project_dir` = try o.decode("project_dir")
        self.`bindings` = try o.decode("bindings")
        self.`mode` = try o.decode("mode")
        self.`uses` = try o.decode("uses")
        self.`created_secs` = try o.decode("created_secs")
        self.`remaining_secs` = try o.decode("remaining_secs")
    }
}

public struct GrantBindingView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `env_name`: DaemonText
    public let `slug`: DaemonText
    public let `live`: Bool
    public var description: String { "[GrantBindingView]" }
    public var debugDescription: String { description }
    public init(env_name: DaemonText, slug: DaemonText, live: Bool) {
        self.env_name = env_name
        self.slug = slug
        self.live = live
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["env_name", "slug", "live"])
        self.`env_name` = try o.decode("env_name")
        self.`slug` = try o.decode("slug")
        self.`live` = try o.decode("live")
    }
}

public struct RevokedView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `revoked`: UInt64
    public var description: String { "[RevokedView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["revoked"])
        self.`revoked` = try o.decode("revoked")
    }
}

public struct LockedView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `was_unlocked`: Bool
    public var description: String { "[LockedView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["was_unlocked"])
        self.`was_unlocked` = try o.decode("was_unlocked")
    }
}

public struct AuditVerifyView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `segments`: UInt64
    public let `entries`: UInt64
    public let `last_seq`: UInt64
    public let `first_problem`: AuditProblemView?
    public let `problems`: UInt64
    public let `anchor`: AnchorView
    public let `unanchored_tail`: SeqRange?
    public let `torn_tail`: Bool
    public let `torn_bytes`: UInt64
    public let `live_head_matches`: Bool?
    public let `queued`: UInt64
    public let `dropped`: UInt64
    public var description: String { "[AuditVerifyView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["segments", "entries", "last_seq", "first_problem", "problems", "anchor", "unanchored_tail", "torn_tail", "torn_bytes", "live_head_matches", "queued", "dropped"])
        self.`segments` = try o.decode("segments")
        self.`entries` = try o.decode("entries")
        self.`last_seq` = try o.decode("last_seq")
        self.`first_problem` = try o.optional("first_problem")
        self.`problems` = try o.decode("problems")
        self.`anchor` = try o.decode("anchor")
        self.`unanchored_tail` = try o.optional("unanchored_tail")
        self.`torn_tail` = try o.decode("torn_tail")
        self.`torn_bytes` = try o.decode("torn_bytes")
        self.`live_head_matches` = try o.optional("live_head_matches")
        self.`queued` = try o.decode("queued")
        self.`dropped` = try o.decode("dropped")
    }
}

public struct AuditProblemView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `seq`: UInt64
    public let `kind`: AuditProblemKind
    public var description: String { "[AuditProblemView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["seq", "kind"])
        self.`seq` = try o.decode("seq")
        self.`kind` = try o.decode("kind")
    }
}

public struct AnchorView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `state`: AnchorState
    public let `seq`: UInt64?
    public var description: String { "[AnchorView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["state", "seq"])
        self.`state` = try o.decode("state")
        self.`seq` = try o.optional("seq")
    }
}

public struct SeqRange: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `first`: UInt64
    public let `last`: UInt64
    public var description: String { "[SeqRange]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["first", "last"])
        self.`first` = try o.decode("first")
        self.`last` = try o.decode("last")
    }
}

public struct ItemsView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `items`: [ItemView]
    public var description: String { "[ItemsView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["items"])
        self.`items` = try o.decode("items")
    }
}

public struct ItemView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `id`: DaemonText
    public let `slug`: DaemonText
    public let `class`: ItemClassView
    public let `title`: DaemonText
    public let `provider`: DaemonText?
    public let `classification`: ClassificationView
    public let `env_hint`: DaemonText?
    public let `allow_short`: Bool
    public let `fields`: [FieldView]
    public let `created_secs`: UInt64
    public let `updated_secs`: UInt64
    public let `rotated_secs`: UInt64?
    public let `expires_secs`: UInt64?
    public let `last_used_secs`: UInt64?
    public let `account`: AccountView?
    public let `detail`: ItemDetailView?
    public let `exposed`: ExposedView?
    public var description: String { "[ItemView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["id", "slug", "class", "title", "provider", "classification", "env_hint", "allow_short", "fields", "created_secs", "updated_secs", "rotated_secs", "expires_secs", "last_used_secs", "account", "detail", "exposed"])
        self.`id` = try o.decode("id")
        self.`slug` = try o.decode("slug")
        self.`class` = try o.decode("class")
        self.`title` = try o.decode("title")
        self.`provider` = try o.optional("provider")
        self.`classification` = try o.decode("classification")
        self.`env_hint` = try o.optional("env_hint")
        self.`allow_short` = try o.decode("allow_short")
        self.`fields` = try o.decode("fields")
        self.`created_secs` = try o.decode("created_secs")
        self.`updated_secs` = try o.decode("updated_secs")
        self.`rotated_secs` = try o.optional("rotated_secs")
        self.`expires_secs` = try o.optional("expires_secs")
        self.`last_used_secs` = try o.optional("last_used_secs")
        self.`account` = try o.optional("account")
        self.`detail` = try o.optional("detail")
        self.`exposed` = try o.optional("exposed")
    }
}

public struct ExposedView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `since_secs`: UInt64
    public let `sources`: [ExposureSourceView]
    public let `count`: UInt64
    public var description: String { "[ExposedView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["since_secs", "sources", "count"])
        self.`since_secs` = try o.decode("since_secs")
        self.`sources` = try o.decode("sources")
        self.`count` = try o.decode("count")
    }
}

public struct FieldView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `name`: DaemonText
    public let `prior_count`: UInt8
    public let `created_secs`: UInt64
    public let `updated_secs`: UInt64
    public var description: String { "[FieldView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["name", "prior_count", "created_secs", "updated_secs"])
        self.`name` = try o.decode("name")
        self.`prior_count` = try o.decode("prior_count")
        self.`created_secs` = try o.decode("created_secs")
        self.`updated_secs` = try o.decode("updated_secs")
    }
}

public struct AccountView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `email`: DaemonText?
    public let `label`: DaemonText?
    public let `org_id`: DaemonText?
    public var description: String { "[AccountView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["email", "label", "org_id"])
        self.`email` = try o.optional("email")
        self.`label` = try o.optional("label")
        self.`org_id` = try o.optional("org_id")
    }
}

public struct ItemDetailView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `allowed_hosts`: [DaemonText]
    public let `tags`: [DaemonText]
    public let `links`: LinksView
    public let `last_used_secs`: UInt64?
    public let `notes`: DaemonText?
    public var description: String { "[ItemDetailView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["allowed_hosts", "tags", "links", "last_used_secs", "notes"])
        self.`allowed_hosts` = try o.decode("allowed_hosts")
        self.`tags` = try o.decode("tags")
        self.`links` = try o.decode("links")
        self.`last_used_secs` = try o.optional("last_used_secs")
        self.`notes` = try o.optional("notes")
    }
}

public struct LinksView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `docs`: DaemonText?
    public let `billing`: DaemonText?
    public let `keys_page`: DaemonText?
    public let `dashboard`: DaemonText?
    public var description: String { "[LinksView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["docs", "billing", "keys_page", "dashboard"])
        self.`docs` = try o.optional("docs")
        self.`billing` = try o.optional("billing")
        self.`keys_page` = try o.optional("keys_page")
        self.`dashboard` = try o.optional("dashboard")
    }
}

public struct AddedView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `item`: ItemView
    public let `field`: DaemonText
    public let `detected`: DaemonText?
    public let `ambiguous`: Bool
    public let `length`: LengthClass
    public var description: String { "[AddedView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["item", "field", "detected", "ambiguous", "length"])
        self.`item` = try o.decode("item")
        self.`field` = try o.decode("field")
        self.`detected` = try o.optional("detected")
        self.`ambiguous` = try o.decode("ambiguous")
        self.`length` = try o.decode("length")
    }
}

public struct CheckView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `project_dir`: DaemonText?
    public let `project_name`: DaemonText?
    public let `bindings`: [CheckBindingView]
    public let `refs`: [RefStatus]
    public var description: String { "[CheckView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["project_dir", "project_name", "bindings", "refs"])
        self.`project_dir` = try o.optional("project_dir")
        self.`project_name` = try o.optional("project_name")
        self.`bindings` = try o.decode("bindings")
        self.`refs` = try o.decode("refs")
    }
}

public struct BackupView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `path`: DaemonText
    public let `file_name`: DaemonText
    public let `items`: UInt64
    public let `bytes`: UInt64
    public let `created_secs`: UInt64
    public var description: String { "[BackupView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["path", "file_name", "items", "bytes", "created_secs"])
        self.`path` = try o.decode("path")
        self.`file_name` = try o.decode("file_name")
        self.`items` = try o.decode("items")
        self.`bytes` = try o.decode("bytes")
        self.`created_secs` = try o.decode("created_secs")
    }
}

public struct CheckBindingView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `profile`: DaemonText?
    public let `env_name`: DaemonText?
    public let `reference`: DaemonText?
    public let `status`: RefStatus
    public var description: String { "[CheckBindingView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["profile", "env_name", "reference", "status"])
        self.`profile` = try o.optional("profile")
        self.`env_name` = try o.optional("env_name")
        self.`reference` = try o.optional("reference")
        self.`status` = try o.decode("status")
    }
}

extension ExposureSourceView {
    public var label: String {
        switch self {
        case .transcript: "agent transcripts"
        case .gitHistory: "git history"
        case .configBackup: "config backups"
        case .syncedFolder: "synced folders"
        case .shellProfile: "shell profiles"
        case .agentConfig: "agent configs"
        case .envFile: ".env files"
        }
    }
}

extension ExposedView {
    public var bannerText: String {
        let places = sources.isEmpty ? "local files" : sources.map(\.label).joined(separator: ", ")
        let files = count == 1 ? "1 file" : "\(count) files"
        return "Found in past \(places) (\(files)). Replace it at the provider: EnvCloak cannot recall copies already sent to a model provider."
    }
}

public struct FirstRunProviderView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `provider`: DaemonText
    public let `keys`: UInt64
    public let `live_keys`: UInt64
    public var description: String { "[FirstRunProviderView]" }
    public var debugDescription: String { description }
    public init(provider: DaemonText, keys: UInt64, live_keys: UInt64) {
        self.provider = provider
        self.keys = keys
        self.live_keys = live_keys
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["provider", "keys", "live_keys"])
        self.`provider` = try o.decode("provider")
        self.`keys` = try o.decode("keys")
        self.`live_keys` = try o.decode("live_keys")
    }
    public var displayName: String {
        let text = provider.escaped
        switch text.lowercased() {
        case "openai": return "OpenAI"
        case "anthropic": return "Anthropic"
        case "stripe": return "Stripe"
        case "github": return "GitHub"
        case "aws": return "AWS"
        case "google": return "Google"
        case "cloudflare": return "Cloudflare"
        case "supabase": return "Supabase"
        case "vercel": return "Vercel"
        case "linear": return "Linear"
        case "slack": return "Slack"
        case "resend": return "Resend"
        case "twilio": return "Twilio"
        default: return text
        }
    }
    public var summaryLabel: String {
        live_keys > 0 ? "\(displayName) \(keys), \(live_keys) live" : "\(displayName) \(keys)"
    }
}

public struct FirstRunAccountView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `email`: DaemonText
    public let `keys`: UInt64
    public var description: String { "[FirstRunAccountView]" }
    public var debugDescription: String { description }
    public init(email: DaemonText, keys: UInt64) {
        self.email = email
        self.keys = keys
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["email", "keys"])
        self.`email` = try o.decode("email")
        self.`keys` = try o.decode("keys")
    }
    public var summaryLabel: String {
        "\(email.escaped) (\(keys))"
    }
}

public struct FirstRunLeakedPlaceView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `source`: ExposureSourceView
    public let `subject`: DaemonText?
    public let `files`: UInt64
    public let `occurrences`: UInt64
    public var description: String { "[FirstRunLeakedPlaceView]" }
    public var debugDescription: String { description }
    public init(source: ExposureSourceView, subject: DaemonText? = nil, files: UInt64, occurrences: UInt64) {
        self.source = source
        self.subject = subject
        self.files = files
        self.occurrences = occurrences
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["source", "subject", "files", "occurrences"])
        self.`source` = try o.decode("source")
        self.`subject` = try o.optional("subject")
        self.`files` = try o.decode("files")
        self.`occurrences` = try o.decode("occurrences")
    }
    public var placeSummary: String {
        let label = subject?.escaped
        let kind: String = switch source {
        case .transcript:
            if let label, !label.isEmpty { "\(label) transcripts" } else { "agent transcripts" }
        case .gitHistory: "git history"
        case .configBackup:
            if let label, !label.isEmpty { "\(label) config backups" } else { "config backups" }
        case .syncedFolder:
            if let label, !label.isEmpty { "\(label) synced folder" } else { "synced folders" }
        case .shellProfile: "shell profiles"
        case .agentConfig:
            if let label, !label.isEmpty { "\(label) configs" } else { "agent configs" }
        case .envFile: ".env files"
        }
        return "\(kind), \(files) \(files == 1 ? "file" : "files")"
    }
}

public struct FirstRunLeakedItemView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `slug`: DaemonText
    public let `provider`: DaemonText?
    public let `classification`: ClassificationView
    public let `rotate_url`: DaemonText?
    public let `places`: [FirstRunLeakedPlaceView]
    public var description: String { "[FirstRunLeakedItemView]" }
    public var debugDescription: String { description }
    public init(slug: DaemonText, provider: DaemonText? = nil, classification: ClassificationView = .unknown, rotate_url: DaemonText? = nil, places: [FirstRunLeakedPlaceView]) {
        self.slug = slug
        self.provider = provider
        self.classification = classification
        self.rotate_url = rotate_url
        self.places = places
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["slug", "provider", "classification", "rotate_url", "places"])
        self.`slug` = try o.decode("slug")
        self.`provider` = try o.optional("provider")
        self.`classification` = try o.decode("classification")
        self.`rotate_url` = try o.optional("rotate_url")
        self.`places` = try o.decode("places")
    }
    public var whereSummary: String {
        places.map(\.placeSummary).joined(separator: "; ")
    }
}

public struct FirstRunProjectPlaintextView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `project`: DaemonText
    public let `dir`: DaemonText
    public let `files`: [DaemonText]
    public let `keys`: UInt64
    public var description: String { "[FirstRunProjectPlaintextView]" }
    public var debugDescription: String { description }
    public init(project: DaemonText, dir: DaemonText, files: [DaemonText], keys: UInt64) {
        self.project = project
        self.dir = dir
        self.files = files
        self.keys = keys
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["project", "dir", "files", "keys"])
        self.`project` = try o.decode("project")
        self.`dir` = try o.decode("dir")
        self.`files` = try o.decode("files")
        self.`keys` = try o.decode("keys")
    }
    public var summaryLabel: String {
        let joined = files.map(\.escaped).joined(separator: ", ")
        return "\(project.escaped): \(joined) (\(keys) \(keys == 1 ? "key" : "keys"))"
    }
}

public struct FirstRunReportView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `version`: UInt32
    public let `keys_found`: UInt64
    public let `projects`: UInt64
    public let `already_leaked`: UInt64
    public let `plaintext_files`: UInt64
    public let `providers`: [FirstRunProviderView]
    public let `accounts`: [FirstRunAccountView]
    public let `leaked`: [FirstRunLeakedItemView]
    public let `plaintext_projects`: [FirstRunProjectPlaintextView]
    public var description: String { "[FirstRunReportView]" }
    public var debugDescription: String { description }
    public init(version: UInt32 = 1, keys_found: UInt64, projects: UInt64, already_leaked: UInt64, plaintext_files: UInt64,
                providers: [FirstRunProviderView], accounts: [FirstRunAccountView],
                leaked: [FirstRunLeakedItemView], plaintext_projects: [FirstRunProjectPlaintextView]) {
        self.version = version
        self.keys_found = keys_found
        self.projects = projects
        self.already_leaked = already_leaked
        self.plaintext_files = plaintext_files
        self.providers = providers
        self.accounts = accounts
        self.leaked = leaked
        self.plaintext_projects = plaintext_projects
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["version", "keys_found", "projects", "already_leaked", "plaintext_files", "providers", "accounts", "leaked", "plaintext_projects"])
        let version: UInt32 = try o.decode("version")
        guard version == 1 else { throw EnvCloakError.protocolError }
        self.`version` = version
        self.`keys_found` = try o.decode("keys_found")
        self.`projects` = try o.decode("projects")
        self.`already_leaked` = try o.decode("already_leaked")
        self.`plaintext_files` = try o.decode("plaintext_files")
        self.`providers` = try o.decode("providers")
        self.`accounts` = try o.decode("accounts")
        self.`leaked` = try o.decode("leaked")
        self.`plaintext_projects` = try o.decode("plaintext_projects")
    }
}

public enum UnlockerEnrollState: String, Sendable, Equatable, WireDecodable {
    case `pending` = "pending"
    case `enrolled` = "enrolled"
    case `denied` = "denied"
    case `expired` = "expired"
    init(wire: WireReader) throws {
        guard let value = Self(rawValue: try wire.string()) else { throw EnvCloakError.protocolError }
        self = value
    }
}

public struct AppUnlockerEnrollBeginView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `request`: DaemonText
    public let `expires_in_secs`: UInt64
    public var description: String { "[AppUnlockerEnrollBeginView]" }
    public var debugDescription: String { description }
    public init(request: DaemonText, expires_in_secs: UInt64) {
        self.request = request
        self.expires_in_secs = expires_in_secs
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["request", "expires_in_secs"])
        self.`request` = try o.decode("request")
        self.`expires_in_secs` = try o.decode("expires_in_secs")
    }
}

public struct AppUnlockerEnrollView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `state`: UnlockerEnrollState
    public let `unlocker_id`: DaemonText?
    public var description: String { "[AppUnlockerEnrollView]" }
    public var debugDescription: String { description }
    public init(state: UnlockerEnrollState, unlocker_id: DaemonText? = nil) {
        self.state = state
        self.unlocker_id = unlocker_id
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["state", "unlocker_id"])
        let state: UnlockerEnrollState = try o.decode("state")
        let unlockerID: DaemonText? = try o.optional("unlocker_id")
        guard (state == .enrolled) == (unlockerID != nil) else { throw EnvCloakError.protocolError }
        self.`state` = state
        self.`unlocker_id` = unlockerID
    }
}

public struct SeEnvelopeView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `enc`: DaemonText
    public let `ciphertext`: DaemonText
    public var description: String { "[SeEnvelopeView]" }
    public var debugDescription: String { description }
    public init(enc: DaemonText, ciphertext: DaemonText) {
        self.enc = enc
        self.ciphertext = ciphertext
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["enc", "ciphertext"])
        self.`enc` = try o.decode("enc")
        self.`ciphertext` = try o.decode("ciphertext")
    }
}

public struct AppUnlockBeginView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `request_id`: DaemonText
    public let `unlocker_id`: DaemonText
    public let `vault_id`: DaemonText
    public let `epoch`: UInt32
    public let `challenge`: DaemonText
    public let `envelope`: SeEnvelopeView
    public let `daemon_eph_pub`: DaemonText
    public var description: String { "[AppUnlockBeginView]" }
    public var debugDescription: String { description }
    public init(request_id: DaemonText, unlocker_id: DaemonText, vault_id: DaemonText, epoch: UInt32,
                challenge: DaemonText, envelope: SeEnvelopeView, daemon_eph_pub: DaemonText) {
        self.request_id = request_id
        self.unlocker_id = unlocker_id
        self.vault_id = vault_id
        self.epoch = epoch
        self.challenge = challenge
        self.envelope = envelope
        self.daemon_eph_pub = daemon_eph_pub
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["request_id", "unlocker_id", "vault_id", "epoch", "challenge", "envelope", "daemon_eph_pub"])
        self.`request_id` = try o.decode("request_id")
        self.`unlocker_id` = try o.decode("unlocker_id")
        self.`vault_id` = try o.decode("vault_id")
        self.`epoch` = try o.decode("epoch")
        self.`challenge` = try o.decode("challenge")
        self.`envelope` = try o.decode("envelope")
        self.`daemon_eph_pub` = try o.decode("daemon_eph_pub")
    }
}

public struct UnlockedView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `integrity`: Integrity
    public let `read_only`: Bool
    public let `already`: Bool
    public var description: String { "[UnlockedView]" }
    public var debugDescription: String { description }
    public init(integrity: Integrity, read_only: Bool, already: Bool) {
        self.integrity = integrity
        self.read_only = read_only
        self.already = already
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["integrity", "read_only", "already"])
        self.`integrity` = try o.decode("integrity")
        self.`read_only` = try o.decode("read_only")
        self.`already` = try o.decode("already")
    }
}

public struct AppPendingView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `request`: DaemonText
    public let `age_secs`: UInt64
    public let `expires_in_secs`: UInt64
    public let `kind`: SubjectKind
    public let `agent`: DaemonText?
    public let `project`: DaemonText
    public let `bindings`: [DaemonText]
    public let `more_bindings`: UInt64
    public let `statement_domain`: DaemonText
    public var description: String { "[AppPendingView]" }
    public var debugDescription: String { description }
    public init(request: DaemonText, age_secs: UInt64, expires_in_secs: UInt64, kind: SubjectKind,
                agent: DaemonText? = nil, project: DaemonText, bindings: [DaemonText],
                more_bindings: UInt64 = 0, statement_domain: DaemonText = DaemonText("envcloak-statement/2")) {
        self.request = request
        self.age_secs = age_secs
        self.expires_in_secs = expires_in_secs
        self.kind = kind
        self.agent = agent
        self.project = project
        self.bindings = bindings
        self.more_bindings = more_bindings
        self.statement_domain = statement_domain
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["request", "age_secs", "expires_in_secs", "kind", "agent", "project", "bindings", "more_bindings", "statement_domain"])
        self.`request` = try o.decode("request")
        self.`age_secs` = try o.decode("age_secs")
        self.`expires_in_secs` = try o.decode("expires_in_secs")
        self.`kind` = try o.decode("kind")
        self.`agent` = try o.optional("agent")
        self.`project` = try o.decode("project")
        self.`bindings` = try o.decode("bindings")
        self.`more_bindings` = try o.decode("more_bindings")
        self.`statement_domain` = try o.decode("statement_domain")
    }
}

public struct AppPendingListView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `requests`: [AppPendingView]
    public var description: String { "[AppPendingListView]" }
    public var debugDescription: String { description }
    public init(requests: [AppPendingView]) {
        self.requests = requests
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["requests"])
        self.`requests` = try o.decode("requests")
    }
}

public struct ProcessSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `pid`: Int32
    public let `start_time`: UInt64
    public let `exe`: DaemonText?
    public var description: String { "[ProcessSummary]" }
    public var debugDescription: String { description }
    public init(pid: Int32, start_time: UInt64, exe: DaemonText? = nil) {
        self.pid = pid
        self.start_time = start_time
        self.exe = exe
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["pid", "start_time", "exe"])
        self.`pid` = try o.decode("pid")
        self.`start_time` = try o.decode("start_time")
        self.`exe` = try o.optional("exe")
    }
}

public struct SubjectSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `kind`: SubjectKind
    public let `label`: DaemonText?
    public let `caller_pid`: Int32
    public let `root`: ProcessSummary
    public var description: String { "[SubjectSummary]" }
    public var debugDescription: String { description }
    public init(kind: SubjectKind, label: DaemonText? = nil, caller_pid: Int32, root: ProcessSummary) {
        self.kind = kind
        self.label = label
        self.caller_pid = caller_pid
        self.root = root
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["kind", "label", "caller_pid", "root"])
        self.`kind` = try o.decode("kind")
        self.`label` = try o.optional("label")
        self.`caller_pid` = try o.decode("caller_pid")
        self.`root` = try o.decode("root")
    }
}

public struct ProjectSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `dir`: DaemonText
    public let `manifest`: DaemonText
    public let `manifest_sha256`: DaemonText
    public let `new_project`: Bool
    public var description: String { "[ProjectSummary]" }
    public var debugDescription: String { description }
    public init(dir: DaemonText, manifest: DaemonText, manifest_sha256: DaemonText, new_project: Bool) {
        self.dir = dir
        self.manifest = manifest
        self.manifest_sha256 = manifest_sha256
        self.new_project = new_project
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["dir", "manifest", "manifest_sha256", "new_project"])
        self.`dir` = try o.decode("dir")
        self.`manifest` = try o.decode("manifest")
        self.`manifest_sha256` = try o.decode("manifest_sha256")
        self.`new_project` = try o.decode("new_project")
    }
}

public struct BindingSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `env_name`: DaemonText
    public let `slug`: DaemonText
    public let `item`: DaemonText
    public let `field`: DaemonText
    public let `field_name`: DaemonText
    public let `classification`: DaemonText
    public let `first_use`: Bool
    public let `granted`: Bool
    public var description: String { "[BindingSummary]" }
    public var debugDescription: String { description }
    public init(env_name: DaemonText, slug: DaemonText, item: DaemonText, field: DaemonText,
                field_name: DaemonText, classification: DaemonText, first_use: Bool, granted: Bool) {
        self.env_name = env_name
        self.slug = slug
        self.item = item
        self.field = field
        self.field_name = field_name
        self.classification = classification
        self.first_use = first_use
        self.granted = granted
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["env_name", "slug", "item", "field", "field_name", "classification", "first_use", "granted"])
        self.`env_name` = try o.decode("env_name")
        self.`slug` = try o.decode("slug")
        self.`item` = try o.decode("item")
        self.`field` = try o.decode("field")
        self.`field_name` = try o.decode("field_name")
        self.`classification` = try o.decode("classification")
        self.`first_use` = try o.decode("first_use")
        self.`granted` = try o.decode("granted")
    }
    public var classificationView: ClassificationView {
        ClassificationView(rawValue: classification.raw) ?? .unknown
    }
}

public enum BindingSource: Sendable, Equatable, Hashable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    case env
    case profile(DaemonText)
    case envFile(UInt32)
    case ref
    public var description: String { "[BindingSource]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["layer", "profile", "line"])
        let layer: String = try o.decode("layer")
        let profile: DaemonText? = try o.optional("profile")
        let line: UInt32? = try o.optional("line")
        switch (layer, profile, line) {
        case ("env", nil, nil): self = .env
        case ("profile", let p?, nil): self = .profile(p)
        case ("env_file", nil, let l?): self = .envFile(l)
        case ("ref", nil, nil): self = .ref
        default: throw EnvCloakError.protocolError
        }
    }
}

public struct Proposal: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `env_name`: DaemonText
    public let `live_slug`: DaemonText
    public let `test_slug`: DaemonText
    public let `test_field`: DaemonText?
    public let `source`: BindingSource
    public var description: String { "[Proposal]" }
    public var debugDescription: String { description }
    public init(env_name: DaemonText, live_slug: DaemonText, test_slug: DaemonText,
                test_field: DaemonText? = nil, source: BindingSource = .env) {
        self.env_name = env_name
        self.live_slug = live_slug
        self.test_slug = test_slug
        self.test_field = test_field
        self.source = source
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["env_name", "live_slug", "test_slug", "test_field", "source"])
        self.`env_name` = try o.decode("env_name")
        self.`live_slug` = try o.decode("live_slug")
        self.`test_slug` = try o.decode("test_slug")
        self.`test_field` = try o.optional("test_field")
        self.`source` = try o.decode("source")
    }
    public var testReferenceDisplay: String {
        if let field = test_field {
            return "\(test_slug.escaped)#\(field.escaped)"
        }
        return test_slug.escaped
    }
}

public struct ManagedSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `name`: DaemonText
    public let `written_by_migrate_mcp`: Bool
    public let `launch`: DaemonText?
    public let `revision`: UInt64?
    public let `class`: DaemonText?
    public let `strength`: DaemonText?
    public let `origin`: DaemonText?
    public var description: String { "[ManagedSummary]" }
    public var debugDescription: String { description }
    public init(name: DaemonText, written_by_migrate_mcp: Bool, launch: DaemonText? = nil,
                revision: UInt64? = nil, class: DaemonText? = nil, strength: DaemonText? = nil,
                origin: DaemonText? = nil) {
        self.name = name
        self.written_by_migrate_mcp = written_by_migrate_mcp
        self.launch = launch
        self.revision = revision
        self.class = `class`
        self.strength = strength
        self.origin = origin
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["name", "written_by_migrate_mcp", "launch", "revision", "class", "strength", "origin"])
        self.`name` = try o.decode("name")
        self.`written_by_migrate_mcp` = try o.decode("written_by_migrate_mcp")
        self.`launch` = try o.optional("launch")
        self.`revision` = try o.optional("revision")
        self.`class` = try o.optional("class")
        self.`strength` = try o.optional("strength")
        self.`origin` = try o.optional("origin")
    }
}

public struct StandingSummary: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `exe`: DaemonText
    public let `linux_sha256`: DaemonText?
    public let `recognized_release`: DaemonText?
    public let `appends_to`: DaemonText?
    public var description: String { "[StandingSummary]" }
    public var debugDescription: String { description }
    public init(exe: DaemonText, linux_sha256: DaemonText? = nil,
                recognized_release: DaemonText? = nil, appends_to: DaemonText? = nil) {
        self.exe = exe
        self.linux_sha256 = linux_sha256
        self.recognized_release = recognized_release
        self.appends_to = appends_to
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["exe", "linux_sha256", "recognized_release", "appends_to"])
        self.`exe` = try o.decode("exe")
        self.`linux_sha256` = try o.optional("linux_sha256")
        self.`recognized_release` = try o.optional("recognized_release")
        self.`appends_to` = try o.optional("appends_to")
    }
}

public struct PendingDescriptor: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `request`: DaemonText
    public let `nonce`: DaemonText
    public let `created_secs`: UInt64
    public let `expires_in_secs`: UInt64
    public let `subject`: SubjectSummary
    public let `project`: ProjectSummary
    public let `bindings`: [BindingSummary]
    public let `proposals`: [Proposal]
    public let `mode`: Mode
    public let `argv`: [DaemonText]
    public let `managed`: ManagedSummary?
    public let `standing`: StandingSummary?
    public var description: String { "[PendingDescriptor]" }
    public var debugDescription: String { description }
    public init(request: DaemonText, nonce: DaemonText, created_secs: UInt64, expires_in_secs: UInt64,
                subject: SubjectSummary, project: ProjectSummary, bindings: [BindingSummary],
                proposals: [Proposal] = [], mode: Mode = .inject, argv: [DaemonText],
                managed: ManagedSummary? = nil, standing: StandingSummary? = nil) {
        self.request = request
        self.nonce = nonce
        self.created_secs = created_secs
        self.expires_in_secs = expires_in_secs
        self.subject = subject
        self.project = project
        self.bindings = bindings
        self.proposals = proposals
        self.mode = mode
        self.argv = argv
        self.managed = managed
        self.standing = standing
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["request", "nonce", "created_secs", "expires_in_secs", "subject", "project", "bindings", "proposals", "mode", "argv", "managed", "standing"])
        self.`request` = try o.decode("request")
        self.`nonce` = try o.decode("nonce")
        self.`created_secs` = try o.decode("created_secs")
        self.`expires_in_secs` = try o.decode("expires_in_secs")
        self.`subject` = try o.decode("subject")
        self.`project` = try o.decode("project")
        self.`bindings` = try o.decode("bindings")
        self.`proposals` = try o.decode("proposals")
        self.`mode` = try o.decode("mode")
        self.`argv` = try o.decode("argv")
        self.`managed` = try o.optional("managed")
        self.`standing` = try o.optional("standing")
    }
}

public struct ApprovalOptions: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `uses`: Uses
    public let `ttl_secs`: UInt64
    public let `live`: [String]
    public let `standing`: UInt64?
    public var description: String { "[ApprovalOptions]" }
    public var debugDescription: String { description }
    public init(uses: Uses, ttl_secs: UInt64, live: [String] = [], standing: UInt64? = nil) {
        self.uses = uses
        self.ttl_secs = ttl_secs
        self.live = live
        self.standing = standing
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["uses", "ttl_secs", "live", "standing"])
        self.`uses` = try o.decode("uses")
        self.`ttl_secs` = try o.decode("ttl_secs")
        self.`live` = try o.decode("live")
        self.`standing` = try o.optional("standing")
    }
}

public typealias ApproveOptions = ApprovalOptions

public struct ApprovedView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `grant`: DaemonText
    public let `expires_in_secs`: UInt64
    public let `standing`: DaemonText?
    public let `standing_expires_in_secs`: UInt64?
    public var description: String { "[ApprovedView]" }
    public var debugDescription: String { description }
    public init(grant: DaemonText, expires_in_secs: UInt64, standing: DaemonText? = nil, standing_expires_in_secs: UInt64? = nil) {
        self.grant = grant
        self.expires_in_secs = expires_in_secs
        self.standing = standing
        self.standing_expires_in_secs = standing_expires_in_secs
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["grant", "expires_in_secs", "standing", "standing_expires_in_secs"])
        self.`grant` = try o.decode("grant")
        self.`expires_in_secs` = try o.decode("expires_in_secs")
        self.`standing` = try o.optional("standing")
        self.`standing_expires_in_secs` = try o.optional("standing_expires_in_secs")
    }
}

public struct StandingView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `id`: DaemonText
    public let `agent_id`: DaemonText
    public let `agent_name`: DaemonText
    public let `identity`: DaemonText
    public let `project_dir`: DaemonText
    public let `launch`: DaemonText?
    public let `revision`: UInt64?
    public let `bindings`: [DaemonText]
    public let `created_secs`: UInt64
    public let `remaining_secs`: UInt64
    public let `not_after_secs`: UInt64
    public var description: String { "[StandingView]" }
    public var debugDescription: String { description }
    public init(id: DaemonText, agent_id: DaemonText, agent_name: DaemonText, identity: DaemonText,
                project_dir: DaemonText, launch: DaemonText? = nil, revision: UInt64? = nil,
                bindings: [DaemonText], created_secs: UInt64, remaining_secs: UInt64, not_after_secs: UInt64) {
        self.id = id
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.identity = identity
        self.project_dir = project_dir
        self.launch = launch
        self.revision = revision
        self.bindings = bindings
        self.created_secs = created_secs
        self.remaining_secs = remaining_secs
        self.not_after_secs = not_after_secs
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["id", "agent_id", "agent_name", "identity", "project_dir", "launch", "revision", "bindings", "created_secs", "remaining_secs", "not_after_secs"])
        self.`id` = try o.decode("id")
        self.`agent_id` = try o.decode("agent_id")
        self.`agent_name` = try o.decode("agent_name")
        self.`identity` = try o.decode("identity")
        self.`project_dir` = try o.decode("project_dir")
        self.`launch` = try o.optional("launch")
        self.`revision` = try o.optional("revision")
        self.`bindings` = try o.decode("bindings")
        self.`created_secs` = try o.decode("created_secs")
        self.`remaining_secs` = try o.decode("remaining_secs")
        self.`not_after_secs` = try o.decode("not_after_secs")
    }
    public var scopeLabel: String {
        "any \(agent_name.escaped) session in this project, including one started by another program, gets these keys without asking"
    }
}

public struct StandingListView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `standing`: [StandingView]
    public let `policy_epoch_unverified`: Bool
    public var description: String { "[StandingListView]" }
    public var debugDescription: String { description }
    public init(standing: [StandingView], policy_epoch_unverified: Bool = false) {
        self.standing = standing
        self.policy_epoch_unverified = policy_epoch_unverified
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["standing", "policy_epoch_unverified"])
        self.`standing` = try o.decode("standing")
        self.`policy_epoch_unverified` = try o.optional("policy_epoch_unverified") ?? false
    }
}

public struct StandingRevokedView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `revoked`: UInt64
    public let `grants_ended`: UInt64
    public var description: String { "[StandingRevokedView]" }
    public var debugDescription: String { description }
    public init(revoked: UInt64, grants_ended: UInt64) {
        self.revoked = revoked
        self.grants_ended = grants_ended
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["revoked", "grants_ended"])
        self.`revoked` = try o.decode("revoked")
        self.`grants_ended` = try o.decode("grants_ended")
    }
}

public struct StandingConfirmedView: Sendable, Equatable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `records`: UInt64
    public let `generation`: UInt64
    public var description: String { "[StandingConfirmedView]" }
    public var debugDescription: String { description }
    public init(records: UInt64, generation: UInt64) {
        self.records = records
        self.generation = generation
    }
    init(wire: WireReader) throws {
        let o = try wire.object(["records", "generation"])
        self.`records` = try o.decode("records")
        self.`generation` = try o.decode("generation")
    }
}

