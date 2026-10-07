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
    public var description: String { "[StatusView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["daemon", "vault", "lock", "approvals", "audit"])
        self.`daemon` = try o.decode("daemon")
        self.`vault` = try o.decode("vault")
        self.`lock` = try o.decode("lock")
        self.`approvals` = try o.decode("approvals")
        self.`audit` = try o.decode("audit")
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
    public var description: String { "[VaultView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["state", "integrity", "read_only", "unavailable", "busy", "failed_unlocks"])
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
    public let `proof_failures`: UInt32
    public let `proof_wait_secs`: UInt64
    public var description: String { "[ApprovalsView]" }
    public var debugDescription: String { description }
    init(wire: WireReader) throws {
        let o = try wire.object(["grants", "pending", "proof_failures", "proof_wait_secs"])
        self.`grants` = try o.decode("grants")
        self.`pending` = try o.decode("pending")
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

public struct GrantView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
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

public struct GrantBindingView: Sendable, WireDecodable, CustomStringConvertible, CustomDebugStringConvertible {
    public let `env_name`: DaemonText
    public let `slug`: DaemonText
    public let `live`: Bool
    public var description: String { "[GrantBindingView]" }
    public var debugDescription: String { description }
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
