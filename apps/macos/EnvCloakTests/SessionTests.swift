import CryptoKit
import Foundation
import SwiftUI
import XCTest
import EnvCloakKitTestSupport
@testable import EnvCloak
@testable import EnvCloakKit

extension SoftwareUnlockKey: @retroactive UnlockKeyAgreement {
    public func openAndReseal(_ begin: AppUnlockBeginView, reason: String) async throws -> String {
        try recordOpen(reason: reason)
        return try SEHPKE.openAndResealWithKey(begin, privateKey: privateKey)
    }

    public static func sealEnvelope(
        vmk: Data,
        recipientPublicKey: P256.KeyAgreement.PublicKey,
        vaultIDHex: String,
        unlockerIDHex: String,
        epoch: UInt32
    ) throws -> SeEnvelopeView {
        let hex = try sealEnvelopeHex(
            vmk: vmk,
            recipientPublicKey: recipientPublicKey,
            vaultIDHex: vaultIDHex,
            unlockerIDHex: unlockerIDHex,
            epoch: epoch
        )
        return SeEnvelopeView(enc: DaemonText(hex.encHex), ciphertext: DaemonText(hex.ciphertextHex))
    }
}

extension SoftwareApprovalSigner: @retroactive ApprovalSigner {
    public func sign(_ statementBytes: Data, reason: String) async throws -> P256RawSignature {
        let raw = try await signRaw(statementBytes, reason: reason)
        return try P256RawSignature(rawRepresentation: raw)
    }
}

/// Scripted metadata passes through FakeDaemon and the real socket client. No fixture reads the account's runtime path.
actor ScriptedClient: WorkspaceClient {
    var counts: [String: Int] = [:]
    var head: UInt64 = 1
    var grants = 0
    var pending = 0
    var vault = "unlocked"
    var integrity = "ok"
    var readOnly = false
    var busyResponses = 0
    func busy(_ count: Int) { busyResponses = count }
    var idleLimit: UInt64 = 3600
    var lockReason = "sleep"
    nonisolated let socketPath: DaemonText? = DaemonText("/tmp/ec05-fixture\u{202e}/envcloakd.sock")
    func idle(_ seconds: UInt64) { idleLimit = seconds; lockReason = "idle" }
    var failure: EnvCloakError?
    var projectFailure = false
    var itemCount = 1
    var pageMode = "single"
    var revokeFailure = false
    var hostileSlugs = true
    var fieldNameSuffix = ""
    func fieldSuffix(_ text: String) { fieldNameSuffix = text }
    var hostileSurfaceMetadata = false
    var unopenedHostilePath = false
    var checkedName: String? = "project\u{202e}\u{1b}[31m"
    func unopenedBasenameFixture(name: String? = "Benign manifest name") {
        unopenedHostilePath = true; pageMode = "two"; checkedName = name
    }
    private var hostileSuffix: String { hostileSurfaceMetadata ? "\u{202e}\u{1b}[31m" : "" }
    func hostileMetadata() { hostileSurfaceMetadata = true; grants = 1; adoptedBinding = true }
    func plainSlugs() { hostileSlugs = false }
    var showFailure = false
    var wrongDetail = false
    func detailResponse(fails: Bool = false, wrong: Bool = false) { showFailure = fails; wrongDetail = wrong }
    var bindingNames: [String]?
    var bindingReference = "fixture-0"
    private var holdCheck = false
    private var checkContinuation: CheckedContinuation<Void, Never>?
    func bindings(_ names: [String], reference: String = "fixture-0") { bindingNames = names; bindingReference = reference }
    func holdNextCheck() { holdCheck = true }
    func releaseCheck() { checkContinuation?.resume(); checkContinuation = nil }
    var adoptedBinding = false
    func adoptBinding() { adoptedBinding = true }
    func pages(_ mode: String) { pageMode = mode }
    func loseRevokeResponse() { revokeFailure = true }
    func configure(head: UInt64? = nil, grants: Int? = nil, pending: Int? = nil,
                   vault: String? = nil, integrity: String? = nil, readOnly: Bool? = nil, failure: EnvCloakError? = nil,
                   projectFailure: Bool = false, itemCount: Int = 1) {
        if let head { self.head = head }
        if let grants { self.grants = grants }
        if let pending { self.pending = pending }
        if let vault { self.vault = vault }
        if let integrity { self.integrity = integrity }
        if let readOnly { self.readOnly = readOnly }
        self.failure = failure; self.projectFailure = projectFailure; self.itemCount = itemCount
    }
    var exposedItemIndices: Set<Int> = []
    func expose(_ indices: Set<Int>) { exposedItemIndices = indices }
    var standingCount = 0
    func setStandingCount(_ count: Int) { standingCount = count }
    var enrollState = "enrolled"
    func setEnrollState(_ state: String) { enrollState = state }
    var unlockBeginData: [String: Any]?
    func setUnlockBegin(_ data: [String: Any]) { unlockBeginData = data }
    var approveError: EnvCloakError?
    func setApproveError(_ err: EnvCloakError?) { approveError = err }
    var pendingNonce = String(repeating: "ab", count: 32)
    func setPendingNonce(_ nonce: String) { pendingNonce = nonce }
    var lastApprovedDigest: String?
    var lastApprovedSignature: String?
    func approvedReceipt() -> (digest: String?, signature: String?) { (lastApprovedDigest, lastApprovedSignature) }
    let daemonEphKey = Curve25519.KeyAgreement.PrivateKey()
    var lastWriteDigest: String?
    var lastWriteSignature: String?
    var lastRotatedSealedValue: String?
    var lastRevealDigest: String?
    var lastRevealSignature: String?
    var lastRevealAppEphPub: String?
    var revealSecretPlaintext = "sk_test_synthetic_reveal_42"
    func setRevealPlaintext(_ value: String) { revealSecretPlaintext = value }
    func writeReceipt() -> (digest: String?, signature: String?, sealed: String?) {
        (lastWriteDigest, lastWriteSignature, lastRotatedSealedValue)
    }
    func revealReceipt() -> (digest: String?, signature: String?, appEphPub: String?) {
        (lastRevealDigest, lastRevealSignature, lastRevealAppEphPub)
    }
    var asksCount = 0
    func setAsksCount(_ count: Int) { asksCount = count }
    var hostileAskAccount = false
    func setHostileAskAccount(_ enabled: Bool) { hostileAskAccount = enabled }
    var incrementTargetId = false
    var targetCounter = 0
    func setIncrementTargetId(_ enabled: Bool) { incrementTargetId = enabled }
    var lastUnlockBeginUnlockerID: String?
    func unlockBeginUnlockerID() -> String? { lastUnlockBeginUnlockerID }
    var removedUnlockers: [String] = []
    func removedUnlockerIDs() -> [String] { removedUnlockers }
    var rotateErrors: [EnvCloakError] = []
    func queueRotateErrors(_ errors: [EnvCloakError]) { rotateErrors = errors }
    var removeErrors: [EnvCloakError] = []
    func queueRemoveErrors(_ errors: [EnvCloakError]) { removeErrors = errors }
    var pasteBeginErrors: [EnvCloakError] = []
    func queuePasteBeginErrors(_ errors: [EnvCloakError]) { pasteBeginErrors = errors }
    var pasteInspectErrors: [EnvCloakError] = []
    func queuePasteInspectErrors(_ errors: [EnvCloakError]) { pasteInspectErrors = errors }
    var pasteCommitErrors: [EnvCloakError] = []
    func queuePasteCommitErrors(_ errors: [EnvCloakError]) { pasteCommitErrors = errors }
    var lastPastedProvider: String?
    var lastPastedAccount: String?
    func pasteReceipt() -> (provider: String?, account: String?) { (lastPastedProvider, lastPastedAccount) }
    var appLockReasons: [AppLockReason] = []
    func recordedAppLockReasons() -> [AppLockReason] { appLockReasons }
    var auditHasMorePages = false
    func setAuditHasMorePages(_ enabled: Bool) { auditHasMorePages = enabled }
    var auditVerifyPayload: [String: Any]?
    func setAuditVerifyPayload(_ payload: [String: Any]?) { auditVerifyPayload = payload }
    func calls(_ name: String) -> Int { counts[name, default: 0] }
    private func item(_ i: Int) -> [String: Any] {
        var row: [String: Any] = ["id": "item-\(i)", "slug": "fixture-\(i)" + (hostileSlugs ? "\u{202e}\u{1b}[31m" : ""), "class": "secret", "title": "Fixture \(i)" + hostileSuffix,
         "provider": "example" + hostileSuffix, "classification": "test", "env_hint": "VARIABLE", "allow_short": false,
         "fields": ["value", "secondary"].map { ["name": $0 + fieldNameSuffix, "prior_count": 0, "created_secs": 1, "updated_secs": 1] as [String: Any] },
         "last_used_secs": 123, "created_secs": 1, "updated_secs": 1, "account": ["email": "fixture@example.invalid" + hostileSuffix]]
        if exposedItemIndices.contains(i) {
            row["exposed"] = ["since_secs": 100, "sources": ["transcript"], "count": 14] as [String: Any]
        }
        return row
    }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        counts[M.name, default: 0] += 1
        if let failure { throw failure }
        let result: [String: Any]
        switch M.name {
        case "status":
            let busy = busyResponses > 0
            if busy { busyResponses -= 1 }
            result = [
            "daemon": ["version": "fixture", "pid": 42, "hardening": ["core_dumps_off": true, "non_dumpable": false], "runtime_dir_fallback": false],
            "vault": ["state": busy ? "locked" : vault, "integrity": integrity, "read_only": readOnly, "busy": busy, "failed_unlocks": 0],
            "lock": ["last_reason": lockReason, "idle_limit_secs": idleLimit],
            "approvals": ["grants": grants, "pending": pending, "proof_failures": 0, "proof_wait_secs": 0],
            "audit": ["open": true, "head_seq": head, "unanchored": 0, "anchor_failed": false, "queued": 0, "dropped": 0],
            "app_requests": asksCount]
        case "items.list": result = ["items": (0..<itemCount).map { item($0) }]
        case "items.show":
            if showFailure { throw EnvCloakError.protocolError }
            let index = (method as? ItemsShow)?.slug.hasPrefix("fixture-1") == true ? 1 : 0
            var full = item(wrongDetail ? 99 : index)
            full["detail"] = ["allowed_hosts": ["api.example.invalid"], "tags": ["fixture"],
                              "links": ["docs": "https://example.invalid/docs", "keys_page": "https://example.invalid/keys"], "last_used_secs": 123,
                              "notes": "Notes \(head)\u{202e}"] as [String: Any]
            result = full
        case "projects.list":
            if projectFailure { throw EnvCloakError.protocolError }
            let nextPage = (method as? ProjectsList)?.after != nil
            if pageMode == "fail-second" && nextPage { throw EnvCloakError.protocolError }
            let next: Any = !["single", "hidden-one-page", "duplicate-real"].contains(pageMode) && (!nextPage || pageMode == "repeat")
                ? ["last_seen": 2, "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"] : NSNull()
            let directory = pageMode.hasPrefix("hidden") ? "[not shown: looks like a key or token]" : (nextPage ? "/tmp/second" : "/tmp/project") + (nextPage && unopenedHostilePath ? "\u{202e}\u{1b}[31m" : hostileSuffix)
            let row: [String: Any] = ["dir": directory, "manifest_sha256": String(repeating: "a", count: 64), "bindings": adoptedBinding ? [["env_name": "VARIABLE", "reference": "envcloak://fixture-0\u{202e}\u{1b}[31m"]] : [], "last_seen_secs": nextPage ? 1 : 2]
            result = ["projects": ["hidden-one-page", "duplicate-real"].contains(pageMode) ? [row, row] : [row], "next": next]

        case "items.check":
            if holdCheck {
                holdCheck = false
                await withCheckedContinuation { checkContinuation = $0 }
            }
            if let names = bindingNames {
                result = ["project_dir": "/tmp/project", "project_name": "Fixture", "bindings": names.map {
                    ["env_name": $0, "reference": "envcloak://" + bindingReference, "status": "ok"]
                }, "refs": []]
                break
            }
            result = ["project_dir": "/tmp/project" + hostileSuffix, "project_name": checkedName as Any? ?? NSNull(), "bindings": [
            ["env_name": "VARIABLE" + hostileSuffix, "reference": hostileSurfaceMetadata ? "envcloak://fixture-0" + hostileSuffix : hostileSlugs ? "envcloak://fixture" : "envcloak://fixture-0", "status": "ok"],
            ["profile": "test", "env_name": "VARIABLE", "reference": "envcloak://second", "status": "unknown_item"]], "refs": []]
        case "grants.list": result = ["grants": (0..<grants).map { idx in [
            "id": idx == 0 ? "fixture-grant" : "fixture-grant-\(idx)",
            "kind": "terminal", "label": "Fixture grant" + hostileSuffix, "root_pid": 42,
            "project_dir": "/tmp/project" + hostileSuffix, "bindings": [["env_name": "VARIABLE" + hostileSuffix, "slug": "fixture-0" + hostileSuffix, "live": false]],
            "mode": "inject", "uses": "session", "created_secs": 1, "remaining_secs": 3600] as [String: Any] }]
        case "grants.revoke":
            if revokeFailure { throw EnvCloakError.protocolError }
            result = ["revoked": 1]
        case "standing.list":
            result = [
                "standing": standingCount == 0 ? [] : [[
                    "id": "standing-1",
                    "agent_id": "claude_code",
                    "agent_name": "claude_code" + hostileSuffix,
                    "identity": "com.anthropic.claude-code",
                    "project_dir": "/tmp/project" + hostileSuffix,
                    "bindings": ["VARIABLE"],
                    "created_secs": 10,
                    "remaining_secs": 604_800,
                    "not_after_secs": 604_810,
                ]],
                "policy_epoch_unverified": false,
            ]
        case "standing.revoke":
            standingCount = 0
            result = ["revoked": 1, "grants_ended": 0]
        case "app.pending.list":
            result = [
                "requests": (0..<pending).map { idx in
                    [
                        "request": "REQ\(idx)ABCD",
                        "age_secs": 5,
                        "expires_in_secs": 540,
                        "kind": "agent",
                        "agent": "claude_code" + hostileSuffix,
                        "project": "/tmp/project" + hostileSuffix,
                        "bindings": ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"],
                        "more_bindings": 0,
                        "statement_domain": "envcloak-statement/2",
                    ] as [String: Any]
                }
            ]
        case "app.pending.get":
            let reqId = (method as? AppPendingGet)?.requestID ?? "REQ0ABCD"
            result = [
                "request": reqId,
                "nonce": pendingNonce,
                "created_secs": 1000,
                "expires_in_secs": 540,
                "subject": [
                    "kind": "agent",
                    "label": "claude_code" + hostileSuffix,
                    "caller_pid": 100,
                    "root": [
                        "pid": 90,
                        "start_time": 123_456,
                        "exe": "/usr/local/bin/claude",
                    ],
                ],
                "project": [
                    "dir": "/tmp/project" + hostileSuffix,
                    "manifest": "/tmp/project/envcloak.toml",
                    "manifest_sha256": String(repeating: "c", count: 64),
                    "new_project": false,
                ],
                "bindings": [
                    [
                        "env_name": "STRIPE_SECRET_KEY",
                        "slug": "stripe/acme-live",
                        "item": "item-live-1",
                        "field": "field-live-1",
                        "field_name": "value",
                        "classification": "live",
                        "first_use": true,
                        "granted": false,
                    ],
                    [
                        "env_name": "OPENAI_API_KEY",
                        "slug": "openai/acme-test",
                        "item": "item-test-1",
                        "field": "field-test-1",
                        "field_name": "value",
                        "classification": "test",
                        "first_use": false,
                        "granted": false,
                    ],
                    [
                        "env_name": "ALREADY_COVERED",
                        "slug": "cov/key",
                        "item": "item-cov-1",
                        "field": "field-cov-1",
                        "field_name": "value",
                        "classification": "test",
                        "first_use": false,
                        "granted": true,
                    ],
                ],
                "proposals": [
                    [
                        "env_name": "STRIPE_SECRET_KEY",
                        "live_slug": "stripe/acme-live",
                        "test_slug": "stripe/acme-test",
                        "source": ["layer": "env"],
                    ]
                ],
                "mode": "inject",
                "argv": ["npm", "test" + hostileSuffix],
            ]
        case "app.approve":
            if let approveError { throw approveError }
            if let req = method as? AppApprove {
                lastApprovedDigest = req.digest
                lastApprovedSignature = req.signature
            }
            if pending > 0 { pending -= 1 }
            grants += 1
            result = ["grant": "grant-approved-1", "expires_in_secs": 28800]
        case "deny":
            if pending > 0 { pending -= 1 }
            result = ["root_auto_denied": false]
        case "app.unlock.begin":
            lastUnlockBeginUnlockerID = (method as? AppUnlockBegin)?.unlocker_id
            guard let unlockBeginData else { throw EnvCloakError.rpc(.noUnlocker, nil) }
            result = unlockBeginData
        case "app.unlock":
            vault = "unlocked"
            result = ["integrity": "ok", "read_only": false, "already": false]
        case "app.unlocker.enroll.begin":
            result = ["request": "ENROL123", "expires_in_secs": 600]
        case "app.unlocker.enroll":
            result = [
                "state": enrollState,
                "unlocker_id": enrollState == "enrolled" ? "unlocker-1" : NSNull(),
            ]
        case "app.items.target":
            let slug = (method as? AppItemsTarget)?.slug ?? "fixture-0"
            if slug.hasPrefix("unlocker"), slug != "unlocker:add", slug != "unlocker:remove" {
                throw EnvCloakError.rpc(.noSuchItem, nil)
            }
            let field = (method as? AppItemsTarget)?.field ?? "value"
            let ephHex = daemonEphKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
            targetCounter += 1
            let targetID = incrementTargetId ? "target-\(targetCounter)" : "target-1"
            result = [
                "target": targetID,
                "nonce": pendingNonce,
                "daemon_eph_pub": ephHex,
                "vault_id": "vault-0",
                "item": "item-0",
                "slug": slug,
                "field": field,
                "field_name": field,
                "classification": "test",
                "prior_count": 1,
                "grants": 1,
                "created_secs": 1000,
                "expires_in_secs": 60,
            ]
        case "app.items.rotate":
            if !rotateErrors.isEmpty {
                throw rotateErrors.removeFirst()
            }
            if let req = method as? AppItemsRotate {
                lastWriteDigest = req.digest
                lastWriteSignature = req.signature
                lastRotatedSealedValue = req.sealed_value
            }
            head += 1
            result = [
                "slug": "fixture-0",
                "field": "value",
                "prior_count": 2,
                "length": "ok",
                "classification": "test",
                "reclassified_from": NSNull(),
                "grants_ended": 0,
            ]
        case "app.items.remove":
            if !removeErrors.isEmpty {
                throw removeErrors.removeFirst()
            }
            if let req = method as? AppItemsRemove {
                lastWriteDigest = req.digest
                lastWriteSignature = req.signature
            }
            head += 1
            result = [
                "slug": "fixture-0",
                "grants_ended": 1,
                "backup": "/tmp/backup.vault",
            ]
        case "app.unlocker.add":
            if let req = method as? AppUnlockerAdd {
                lastWriteDigest = req.digest
                lastWriteSignature = req.signature
            }
            head += 1
            result = ["unlocker_id": "ffeeddccbbaa99887766554433221100"]
        case "app.unlocker.remove":
            if let req = method as? AppUnlockerRemove {
                lastWriteDigest = req.digest
                lastWriteSignature = req.signature
                removedUnlockers.append(req.unlocker)
            }
            head += 1
            result = ["removed": (method as? AppUnlockerRemove)?.unlocker ?? "passphrase"]
        case "app.reveal.begin":
            let slug = (method as? AppRevealBegin)?.slug ?? "fixture-0"
            let field = (method as? AppRevealBegin)?.field ?? "value"
            result = [
                "request": "REV12345",
                "nonce": pendingNonce,
                "vault_id": "vault-0",
                "item": "item-0",
                "slug": slug,
                "field": field,
                "field_name": field,
                "classification": "test",
                "created_secs": 1000,
                "expires_in_secs": 60,
            ]
        case "app.reveal":
            guard let req = method as? AppReveal else { throw EnvCloakError.protocolError }
            lastRevealDigest = req.digest
            lastRevealSignature = req.signature
            lastRevealAppEphPub = req.app_eph_pub
            let aad = try SEHPKE.revealAAD(
                requestID: req.requestID,
                challengeHex: pendingNonce,
                appEphPubHex: req.app_eph_pub
            )
            var secBuf = try SecretBuffer(capacity: revealSecretPlaintext.utf8.count)
            try revealSecretPlaintext.withUTF8 { try secBuf.append(contentsOf: UnsafeRawBufferPointer($0)) }
            let sealedHex = try SEHPKE.sealSecretToX25519(
                secBuf,
                recipientPubHex: req.app_eph_pub,
                aad: aad
            )
            result = ["sealed_value": sealedHex]
        case "app.paste.begin":
            if !pasteBeginErrors.isEmpty {
                throw pasteBeginErrors.removeFirst()
            }
            let ephHex = daemonEphKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
            result = [
                "stage": "STAGE123",
                "daemon_eph_pub": ephHex,
                "expires_in_secs": 120,
            ]
        case "app.paste.inspect":
            if !pasteInspectErrors.isEmpty {
                throw pasteInspectErrors.removeFirst()
            }
            result = [
                "provider": "openai" + hostileSuffix,
                "detected": "openai",
                "ambiguous": false,
                "classification": "live",
                "length": "ok",
                "suggested_slug": "openai-work",
                "env_hint": "OPENAI_API_KEY",
            ]
        case "app.paste":
            if !pasteCommitErrors.isEmpty {
                throw pasteCommitErrors.removeFirst()
            }
            let req = method as? AppPaste
            lastPastedProvider = req?.provider
            lastPastedAccount = req?.account
            var addedItem = item(0)
            addedItem["slug"] = req?.slug ?? "openai-work"
            addedItem["provider"] = req?.provider ?? "openai"
            addedItem["classification"] = "live"
            head += 1
            if asksCount > 0 { asksCount -= 1 }
            result = [
                "item": addedItem,
                "field": "value",
                "detected": "openai",
                "ambiguous": false,
                "length": "ok",
            ]
        case "app.asks.list":
            let accountVal = hostileAskAccount ? "dev\\acct@example.com" : "dev@example.com"
            result = [
                "asks": (0..<asksCount).map { idx in
                    [
                        "ask": "ASK\(idx)ABCD",
                        "created_secs": 1000,
                        "expires_in_secs": 540,
                        "requester": [
                            "kind": "agent",
                            "label": "cursor",
                            "caller_pid": 555,
                            "root": [
                                "pid": 550,
                                "start_time": 100,
                                "exe": "/usr/local/bin/cursor",
                            ],
                        ],
                        "provider": "openai" + hostileSuffix,
                        "project_dir": "/tmp/project",
                        "account": accountVal,
                        "env_hint": "OPENAI_API_KEY",
                        "note": NSNull(),
                    ] as [String: Any]
                }
            ]
        case "app.asks.decline":
            if asksCount > 0 { asksCount -= 1 }
            result = ["declined": "ASK0ABCD"]
        case "app.lock":
            if let req = method as? AppLock {
                appLockReasons.append(req.reason)
                lockReason = req.reason.rawValue
            }
            let wasUnlocked = vault == "unlocked"
            vault = "locked"
            grants = 0
            result = ["was_unlocked": wasUnlocked]
        case "app.audit.list":
            let req = method as? AppAuditList
            if let beforeSeq = req?.before_seq, beforeSeq == 2 {
                result = [
                    "entries": [
                        [
                            "seq": 1,
                            "time_secs": 900,
                            "kind": "unlock",
                            "outcome": "ok",
                            "subject": NSNull(),
                            "project_dir": NSNull(),
                            "slugs": [],
                            "argv_masked": [],
                            "reason": "touch_id",
                            "grant": NSNull(),
                            "request": NSNull(),
                        ] as [String: Any]
                    ],
                    "next_before_seq": NSNull(),
                ]
            } else {
                result = [
                    "entries": [
                        [
                            "seq": 2,
                            "time_secs": 1000,
                            "kind": "delivered",
                            "outcome": "ok",
                            "subject": [
                                "kind": "agent",
                                "agent": "claude_code" + hostileSuffix,
                                "pid": 100,
                                "root_pid": 90,
                                "root_exe": "/usr/local/bin/claude",
                            ] as [String: Any],
                            "project_dir": "/tmp/project" + hostileSuffix,
                            "slugs": ["stripe/acme-test" + hostileSuffix],
                            "argv_masked": ["npm", "test" + hostileSuffix, "--token=[REDACTED]"],
                            "reason": NSNull(),
                            "grant": "grant-1",
                            "request": "REQ0ABCD",
                        ] as [String: Any]
                    ],
                    "next_before_seq": auditHasMorePages ? 2 : NSNull(),
                ]
            }
        case "audit.verify":
            result = auditVerifyPayload ?? [
                "segments": 1,
                "entries": 2,
                "last_seq": 2,
                "first_problem": NSNull(),
                "problems": 0,
                "anchor": [
                    "state": "matched",
                    "seq": 2,
                ] as [String: Any],
                "unanchored_tail": NSNull(),
                "torn_tail": false,
                "torn_bytes": 0,
                "live_head_matches": true,
                "queued": 0,
                "dropped": 0,
            ]
        case "lock": vault = "locked"; result = ["was_unlocked": true]
        default: throw EnvCloakError.protocolError
        }
        let data = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": result])
        let text = String(decoding: data, as: UTF8.self)
        let directory = "/tmp/ec05-fake-" + UUID().uuidString.prefix(8)
        let daemon = try FakeDaemon(directory: directory) { _ in FakeDaemon.frame(text) }
        defer { daemon.stop() }
        let client = DaemonClient(directory: directory)
        return try await client.call(method)
    }
}


final class SessionTests: XCTestCase {
    @MainActor func testRemovalRequiresAnExistingSelectionInTheCurrentProfile() async throws {
        let client = ScriptedClient(); await client.plainSlugs()
        let session = VaultSession(client: client); await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        let project = try XCTUnwrap(session.projects.opened)
        XCTAssertNil(project.removal(of: nil, profile: nil))
        XCTAssertNil(project.removal(of: "ABSENT", profile: nil))
        XCTAssertNil(project.removal(of: "VARIABLE", profile: "staging"), "Inherited rows cannot be removed from another profile")
        let edit = try XCTUnwrap(project.removal(of: "VARIABLE", profile: "test"))
        XCTAssertEqual(edit.envName, "VARIABLE")
        XCTAssertEqual(edit.profile, "test")
        XCTAssertEqual(edit.previous, DaemonText("envcloak://second"))
        XCTAssertNil(edit.reference)
    }

    @MainActor func testHiddenPathsAreRowsNotDirectoryIdentities() async {
        for mode in ["hidden-one-page", "hidden-pages"] {
            let client = ScriptedClient(); await client.pages(mode)
            let store = ProjectsStore(client: client, folders: nil)
            await store.refetch(.projects)
            XCTAssertNil(store.failure)
            XCTAssertEqual(store.rows.count, 2)
            XCTAssertEqual(store.inventory.count, 2)
            XCTAssertEqual(Set(store.inventory.map(\.id)).count, 2)
            XCTAssertTrue(store.directories.isEmpty)
            XCTAssertTrue(store.inventory.allSatisfy { $0.directory == nil })
        }
        let client = ScriptedClient(); await client.pages("duplicate-real")
        let store = ProjectsStore(client: client, folders: nil)
        await store.refetch(.projects)
        XCTAssertEqual(store.failure, .protocolError)
        XCTAssertTrue(store.rows.isEmpty)
    }

    @MainActor func testAliasUsesCheckedIdentityAndKeepsNavigationPath() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await session.openProject(DaemonText("/tmp/selected-alias"))
        XCTAssertEqual(session.projects.opened?.directory, DaemonText("/tmp/selected-alias"))
        XCTAssertEqual(session.projects.opened?.grantDirectory, DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.canonicalDirectory(DaemonText("/tmp/selected-alias")), DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.title(DaemonText("/tmp/project")), "project\\u{202e}\\u{1b}[31m")
    }

    @MainActor func testProjectSearchDependencyNeverReportsFalseAbsence() async {
        let client = ScriptedClient(); await client.adoptBinding()
        let session = VaultSession(client: client)
        await client.configure(projectFailure: true)
        await session.poll()
        for query in ["project:fixture", "PROJECT:fixture", "class:test  project:fixture", "project:"] {
            XCTAssertTrue(session.keysUnavailable(query: query, scope: nil))
        }
        XCTAssertTrue(session.keysUnavailable(query: "", scope: DaemonText("/tmp/project")))
        for query in ["", "provider:example", "project", "unknown:project:fixture"] {
            XCTAssertFalse(session.keysUnavailable(query: query, scope: nil))
        }
        for query in ["provider:example", "account:fixture@example.invalid", "class:test", "Fixture"] {
            XCTAssertFalse(session.keysUnavailable(query: query, scope: nil))
            XCTAssertEqual(session.filteredKeys(query: query, filter: .all, scope: nil).count, 1)
        }
        await client.configure()
        await session.poll()
        XCTAssertFalse(session.keysUnavailable(query: "project:project", scope: nil))
        XCTAssertEqual(session.filteredKeys(query: "project:project", filter: .all, scope: nil).count, 1)
        XCTAssertEqual(session.filteredKeys(query: "project:missing", filter: .all, scope: nil).count, 0)
    }

    @MainActor func testSelectedMetadataUsesShowAndRefreshes() async throws {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(item.detail)
        XCTAssertEqual(item.last_used_secs, 123)
        await session.selectKey(item.slug)
        XCTAssertEqual(session.items.selectedItem?.detail?.notes?.escaped, "Notes 1\\u{202e}")
        XCTAssertEqual(session.items.selectedItem?.detail?.allowed_hosts.first?.escaped, "api.example.invalid")
        await client.configure(head: 2)
        await session.poll()
        XCTAssertEqual(session.items.selectedItem?.detail?.notes?.escaped, "Notes 2\\u{202e}")
        let shows = await client.calls("items.show")
        XCTAssertEqual(shows, 2)
        await client.detailResponse(fails: true)
        await session.selectKey(nil); await session.selectKey(item.slug)
        XCTAssertNil(session.items.selectedItem)
        XCTAssertEqual(session.items.detailFailure, .protocolError)
        await client.detailResponse(wrong: true)
        await session.selectKey(item.slug)
        XCTAssertNil(session.items.selectedItem)
        XCTAssertEqual(session.items.detailFailure, .protocolError)
    }

    @MainActor func testSelectionLockAndCancellationDiscardLateDetails() async throws {
        for operation in ["selection", "lock", "cancel"] {
            let barrier = ItemBarrierClient(method: "items.show")
            await barrier.client.configure(itemCount: 2)
            let session = VaultSession(client: barrier); await session.poll()
            let slug = try XCTUnwrap(session.items.rows.first?.slug)
            let load = Task { await session.selectKey(slug) }
            await barrier.arrived()
            if operation == "lock" { await session.lock() }
            else if operation == "selection" { await session.selectKey(nil) }
            else { load.cancel() }
            await barrier.release(); await load.value
            XCTAssertNil(session.items.selectedItem, operation)
        }
    }

    @MainActor func testInvalidProjectSelectionDiscardsEarlierCheck() async {
        let barrier = ItemBarrierClient(method: "items.check")
        let store = ProjectsStore(client: barrier, folders: nil)
        let load = Task { await store.open(DaemonText("/tmp/first")) }
        await barrier.arrived()
        await store.open(DaemonText("not a path"))
        await barrier.release(); await load.value
        XCTAssertNil(store.opened)
        XCTAssertEqual(store.checkFailure, .protocolError)
        XCTAssertNil(store.openedDirectory)
        await store.refetch(.projects)
        XCTAssertNil(store.opened)
    }

    @MainActor func testFailedInventoryInvalidatesConcurrentDetailReads() async throws {
        let check = ItemBarrierClient(method: "items.check")
        let projects = ProjectsStore(client: check, folders: nil)
        let opening = Task { await projects.open(DaemonText("/tmp/project")) }
        await check.arrived()
        await check.client.configure(projectFailure: true)
        await projects.refetch(.projects)
        await check.release(); await opening.value
        XCTAssertNotNil(projects.failure)
        XCTAssertNil(projects.opened)

        let client = FailingRefreshClient()
        let items = ItemsStore(client: client); await items.refetch(.items)
        let slug = try XCTUnwrap(items.rows.first?.slug)
        let refreshing = Task { await items.refetch(.items) }
        await client.arrived()
        await items.select(slug)
        XCTAssertNotNil(items.selectedItem)
        await client.release(); await refreshing.value
        XCTAssertNotNil(items.failure)
        XCTAssertTrue(items.rows.isEmpty)
        XCTAssertNil(items.selectedItem)
    }

    @MainActor func testUpgradeReadOnlyKeepsMetadataAndRefusesWrites() async throws {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await client.configure(grants: 1, pending: 1, readOnly: true)
        await session.poll()
        XCTAssertTrue(session.state.canReadMetadata)
        XCTAssertTrue(session.state.canLock)
        XCTAssertNotEqual(session.state, .ready)
        XCTAssertNotEqual(session.state, .readOnly)
        XCTAssertEqual(session.items.rows.count, 1)
        XCTAssertEqual(session.projects.rows.count, 1)
        XCTAssertEqual(session.grants.rows.count, 1)
        XCTAssertEqual(session.pendingCount, 0)
        await session.selectKey(session.items.rows.first?.slug)
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertNotNil(session.items.selectedItem?.detail)
        XCTAssertNotNil(session.projects.opened)
        await session.revoke(DaemonText("fixture-grant"))
        let revokes = await client.calls("grants.revoke")
        XCTAssertEqual(revokes, 0)
        await session.lock()
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
        await client.configure(vault: "unlocked", readOnly: false)
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        XCTAssertEqual(session.items.rows.count, 1)
    }

    @MainActor func testReadOnlyHonorsDaemonRefusalAndLockedWins() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await client.configure(integrity: "tampered")
        await session.poll()
        XCTAssertFalse(session.state.canReadMetadata)
        XCTAssertTrue(session.state.canLock)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        let lists = await client.calls("items.list")
        XCTAssertEqual(lists, 0)
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertNil(session.projects.opened)
        await session.revoke(DaemonText("fixture"))
        let revokes = await client.calls("grants.revoke")
        XCTAssertEqual(revokes, 0)
        await client.configure(vault: "locked")
        await session.poll()
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertNil(session.projects.opened)
    }

    @MainActor func testIdleDurationsAndVerificationDetailsAreExact() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        for (seconds, words) in [(UInt64(30), "30 seconds"), (60, "1 minute"), (90, "1 minute 30 seconds"), (3599, "59 minutes 59 seconds"), (3600, "1 hour"), (5400, "1 hour 30 minutes")] {
            await client.idle(seconds); await session.poll()
            XCTAssertEqual(session.lockReason, "Locked after " + words + " idle")
        }
        await client.configure(failure: .daemonUnverified(.peerUID)); await session.poll()
        XCTAssertEqual(session.verificationDetails, "Failed check: peerUID. Socket: /tmp/ec05-fixture\\u{202e}/envcloakd.sock")
    }

    @MainActor func testScopeRestoresPerViewerAndSurvivesFailedRefresh() async throws {
        let root = URL(fileURLWithPath: "/tmp/ec05-scope-" + UUID().uuidString.prefix(8))
        let file = root.appendingPathComponent("viewer-a/projects.json")
        let folders = try ProjectFolders(file: file)
        try folders.saveScope(DaemonText("/tmp/project"))
        let client = ScriptedClient()
        let store = ProjectsStore(client: client, folders: try ProjectFolders(file: file))
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        XCTAssertNil(try ProjectFolders(file: root.appendingPathComponent("viewer-b/projects.json")).scope)
        await client.configure(projectFailure: true); await store.refetch(.projects)
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        store.clear()
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        await client.configure(); await store.refetch(.projects)
        XCTAssertEqual(store.scope, DaemonText("/tmp/project"))
        XCTAssertThrowsError(try folders.saveScope(DaemonText("relative")))
        XCTAssertThrowsError(try folders.saveScope(DaemonText("/tmp/bad\0path")))
        await client.pages("hidden-one-page"); await store.refetch(.projects)
        XCTAssertNil(store.scope)
        XCTAssertNil(try ProjectFolders(file: file).scope)
    }

    @MainActor func testScopeWriteFailurePreservesInventoryAndRetriesLocally() async throws {
        let fixture = try ScopeWriteFixture()
        let client = ScriptedClient()
        let session = VaultSession(client: client, folders: fixture.folders)
        await session.projects.open(DaemonText("/tmp/project"))
        try fixture.block()
        await session.poll()
        XCTAssertNil(session.projects.failure)
        XCTAssertEqual(session.projects.rows.count, 1)
        XCTAssertNotNil(session.projects.opened)
        XCTAssertNil(session.projects.scope)
        XCTAssertNotNil(session.notice)
        let lists = await client.calls("projects.list")
        await session.poll()
        let repeatedLists = await client.calls("projects.list")
        XCTAssertEqual(lists, repeatedLists)
        XCTAssertEqual(session.filteredKeys(query: "provider:example", filter: .all, scope: session.projects.scope).count, 1)
        session.setScope(DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.scope, DaemonText("/tmp/project"))
        session.setScope(nil)
        XCTAssertNil(session.projects.scope)
        XCTAssertNotNil(session.notice)
        try fixture.restore()
        await session.poll()
        XCTAssertNil(session.notice)
        XCTAssertNil(try ProjectFolders(file: fixture.file).scope)
        let recoveredLists = await client.calls("projects.list")
        XCTAssertEqual(recoveredLists, lists)
        session.setScope(DaemonText("/tmp/project"))
        await session.lock()
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertEqual(session.projects.scope, DaemonText("/tmp/project"))
        await client.configure(vault: "unlocked"); await session.poll()
        XCTAssertEqual(session.projects.rows.count, 1)
        XCTAssertEqual(session.projects.scope, DaemonText("/tmp/project"))
    }

    @MainActor func testObsoleteScopeClearsOnlyAfterCompleteInventory() async throws {
        let fixture = try ScopeWriteFixture()
        let client = ScriptedClient(); let session = VaultSession(client: client, folders: fixture.folders)
        await client.pages("fail-second"); await session.poll()
        XCTAssertNotNil(session.projects.failure)
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertEqual(session.projects.scope, DaemonText("/tmp/obsolete"))
        await client.pages("single"); await session.poll()
        XCTAssertNil(session.projects.failure)
        XCTAssertEqual(session.projects.rows.count, 1)
        XCTAssertNil(session.projects.scope)
        XCTAssertNil(try ProjectFolders(file: fixture.file).scope)
        XCTAssertNil(session.notice)
    }

    @MainActor func testCopiedCommandsAreAcceptedByBuiltDispatcher() async throws {
        guard let executable = ProcessInfo.processInfo.environment["ENVCLOAK_TEST_CLI"] else {
            throw XCTSkip("Set ENVCLOAK_TEST_CLI to the built CLI for the dispatcher oracle")
        }
        let client = ScriptedClient(); await client.plainSlugs()
        let session = VaultSession(client: client); await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(InspectorAction.reveal.commandWords(item: item, field: nil))
        XCTAssertNil(InspectorAction.replace.commandWords(item: item, field: nil))
        XCTAssertNil(InspectorAction.replace.commandWords(item: item, field: DaemonText("missing")))
        let replace = try XCTUnwrap(InspectorAction.replace.commandWords(item: item, field: DaemonText("secondary")))
        XCTAssertEqual(replace, ["rotate", "fixture-0#secondary"])
        let remove = try XCTUnwrap(InspectorAction.remove.commandWords(item: item, field: nil))
        var commands = CopiedCommand.allCases.map(\.commandWords)
        commands += [replace, remove, ["daemon", "install", "--daemon", "/tmp/ec05-missing/daemon"]]
        for (index, arguments) in commands.enumerated() {
            let home = URL(fileURLWithPath: "/tmp/ec05-command-" + UUID().uuidString.prefix(8))
            try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let process = Process(); process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments; process.currentDirectoryURL = home
            process.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "TMPDIR": home.path,
                                   "XDG_CONFIG_HOME": home.path, "XDG_DATA_HOME": home.path, "XDG_STATE_HOME": home.path,
                                   "XDG_CACHE_HOME": home.path, "XDG_RUNTIME_DIR": home.path]
            process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run()
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while process.isRunning, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
            if process.isRunning { process.terminate(); XCTFail("command timed out: \(index)") }
            process.waitUntilExit()
            XCTAssertNotEqual(process.terminationStatus, 2, "dispatcher rejected command \(index)")
            XCTAssertNotEqual(process.terminationStatus, 125, "unavailable command \(index)")
            if arguments == CopiedCommand.recoveryHelp.commandWords { XCTAssertEqual(process.terminationStatus, 0) }
        }
    }

    @MainActor func testStartActionRunsStatusInstallerAndReconciles() async throws {
        for succeeds in [true, false] {
            let home = "/tmp/ec05-installer-" + UUID().uuidString.prefix(8)
            try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let executable = home + "/cli"
            try ("#!/bin/sh\ntest \"$#\" -eq 4 && test \"$1\" = daemon && test \"$2\" = install && test \"$3\" = --daemon || exit 2\nprintf 'installed'\nexit " + (succeeds ? "0" : "1") + "\n").write(toFile: executable, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable)
            let runner = CLIRunner(executable: executable, home: String(home), timeout: .seconds(2))
            let client = ScriptedClient(); let session = VaultSession(client: client); session.state = .noDaemon
            await WorkspaceActions.startDaemon(session) { try await WorkspaceActions.installDaemon(using: runner, daemonPath: "/tmp/fixture-daemon") }
            let polls = await client.calls("status")
            XCTAssertEqual(polls, succeeds ? 1 : 0)
            XCTAssertEqual(session.state, succeeds ? .ready : .noDaemon)
            XCTAssertEqual(session.notice == nil, succeeds)
            XCTAssertFalse(session.actionInProgress)
        }
    }

    func testRepeatedDisplayTextNeverDefinesRowIdentity() {
        let hidden = DaemonText("[not shown: looks like a key or token]")
        let rows = DisplayRow.of([hidden, hidden, DaemonText("same"), DaemonText("same")])
        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(Set(rows.map(\.id)).count, 4)
        XCTAssertEqual(rows.map(\.value), [hidden, hidden, DaemonText("same"), DaemonText("same")])
    }

    @MainActor func testOnlyChangedStoresRefetch() async {
        let client = ScriptedClient()
        let session = VaultSession(client: client)
        await session.poll()
        await session.poll()
        let initial = await client.calls("items.list")
        XCTAssertEqual(initial, 1)
        await client.configure(pending: 1)
        await session.poll()
        let pending = await client.calls("items.list")
        XCTAssertEqual(pending, 1)
        await client.configure(grants: 1)
        await session.poll()
        let grantCalls = await client.calls("grants.list")
        let itemCalls = await client.calls("items.list")
        XCTAssertEqual(grantCalls, 2)
        XCTAssertEqual(itemCalls, 1)
        await client.configure(head: 2)
        await session.poll()
        let changed = await client.calls("items.list")
        let projects = await client.calls("projects.list")
        XCTAssertEqual(changed, 2)
        XCTAssertEqual(projects, 2)
    }

    @MainActor func testFailureClearsDerivedStateAndReconnectRefetches() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 1)
        await client.configure(failure: .daemonUnavailable)
        await session.poll()
        XCTAssertEqual(session.state, .noDaemon)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        await client.configure()
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 1)
        let calls = await client.calls("items.list")
        XCTAssertEqual(calls, 2)
    }

    @MainActor func testFailedRefreshIsRetriedWithoutAdvancingSignal() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await client.configure(head: 2, projectFailure: true)
        await session.poll()
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertNotNil(session.projects.failure)
        await client.configure(head: 2)
        await session.poll()
        XCTAssertEqual(session.projects.rows.count, 1)
    }

    @MainActor func testStatesAndLockedReason() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        XCTAssertEqual(session.state, .connecting)
        for (wire, expected) in [("absent", ConnectionState.noVault), ("locked", .locked), ("unlocked", .ready), ("unavailable", .unavailable)] {
            await client.configure(vault: wire)
            await session.poll()
            XCTAssertEqual(session.state, expected)
        }
        await client.configure(vault: "unlocked", integrity: "tampered")
        await session.poll()
        XCTAssertEqual(session.state, .readOnly)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertEqual(session.lockReason, "Locked when this Mac slept")
        await client.configure(failure: .daemonUnverified(.peerUID))
        await session.poll()
        XCTAssertEqual(session.state, .unverified(.peerUID))
    }

    @MainActor func testTwoThousandKeysAndTokenSearch() async {
        let client = ScriptedClient(); await client.configure(itemCount: 2000)
        let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.items.rows.count, 2000)
        XCTAssertEqual(session.filteredKeys(query: "provider:example account:fixture@example.invalid class:test", filter: .all, scope: nil).count, 2000)
        XCTAssertEqual(session.filteredKeys(query: "Fixture 1999", filter: .all, scope: nil).count, 1)
        XCTAssertEqual(session.filteredKeys(query: "class:live", filter: .all, scope: nil).count, 0)
    }

    @MainActor func testGate31ProjectNameAndSlugEscaped() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await session.openProject(DaemonText("/tmp/project"))
        XCTAssertEqual(session.projects.opened?.title, "project\\u{202e}\\u{1b}[31m")
        XCTAssertEqual(session.items.rows.first?.slug.escaped, "fixture-0\\u{202e}\\u{1b}[31m")
        XCTAssertEqual(session.projects.opened?.bindings(profile: "test").first?.status, .unknownItem)
    }

    @MainActor func testPagesAreCompleteOrExplicitlyFailed() async {
        for mode in ["two", "repeat", "fail-second"] {
            let client = ScriptedClient(); await client.pages(mode)
            let store = ProjectsStore(client: client, folders: nil)
            await store.refetch(.projects)
            if mode == "two" {
                XCTAssertEqual(store.rows.map(\.dir.escaped), ["/tmp/project", "/tmp/second"])
                XCTAssertNil(store.failure)
            } else {
                XCTAssertTrue(store.rows.isEmpty)
                XCTAssertEqual(store.failure, .protocolError)
            }
        }
    }

    @MainActor func testLockDiscardsAnInFlightRefresh() async {
        let barrier = ItemBarrierClient()
        let session = VaultSession(client: barrier)
        let polling = Task { await session.poll() }
        await barrier.arrived()
        await session.lock()
        await barrier.release()
        await polling.value
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
        XCTAssertTrue(session.projects.rows.isEmpty)
        XCTAssertTrue(session.grants.rows.isEmpty)
    }

    @MainActor func testPollDuringLockNeverReadsOrRestoresMetadata() async throws {
        for lockFinishesFirst in [false, true] {
            let barrier = LockRaceClient()
            await barrier.client.configure(grants: 1, pending: 2)
            let session = VaultSession(client: barrier); await session.poll()
            await session.selectKey(try XCTUnwrap(session.items.rows.first?.slug))
            await session.openProject(DaemonText("/tmp/project"))
            XCTAssertNotNil(session.items.selectedItem)
            XCTAssertNotNil(session.projects.opened)
            await barrier.arm(holdStatus: lockFinishesFirst)
            let locking = Task { await session.lock() }
            await barrier.lockGate.arrived()
            let started = expectation(description: "poll started during Lock")
            let polling = Task { started.fulfill(); await session.poll() }
            await fulfillment(of: [started], timeout: 2)
            if lockFinishesFirst {
                await barrier.lockGate.release(); await locking.value
                await barrier.statusGate.release(); await polling.value
            } else {
                await polling.value
                XCTAssertEqual(session.state, .connecting)
                XCTAssertTrue(session.items.rows.isEmpty)
                XCTAssertTrue(session.projects.rows.isEmpty)
                XCTAssertTrue(session.grants.rows.isEmpty)
                await barrier.lockGate.release(); await locking.value
            }
            let calls = await barrier.client.calls("status")
            XCTAssertEqual(calls, 1, "Lock must suspend status polling in either completion order")
            XCTAssertEqual(session.state, .locked)
            XCTAssertEqual(session.pendingCount, 0)
            XCTAssertTrue(session.items.rows.isEmpty)
            XCTAssertTrue(session.projects.rows.isEmpty)
            XCTAssertTrue(session.grants.rows.isEmpty)
            XCTAssertNil(session.items.selectedItem)
            XCTAssertNil(session.projects.opened)
        }
    }

    @MainActor func testLockInvalidatesEarlierStatusInBothCompletionOrders() async {
        for lockFinishesFirst in [false, true] {
            let barrier = LockRaceClient()
            let session = VaultSession(client: barrier); await session.poll()
            await barrier.arm(holdStatus: true)
            let polling = Task { await session.poll() }
            await barrier.statusGate.arrived()
            let locking = Task { await session.lock() }
            await barrier.lockGate.arrived()
            if lockFinishesFirst {
                await barrier.lockGate.release(); await locking.value
                await barrier.statusGate.release(); await polling.value
            } else {
                await barrier.statusGate.release(); await polling.value
                XCTAssertEqual(session.state, .connecting)
                await barrier.lockGate.release(); await locking.value
            }
            XCTAssertEqual(session.state, .locked)
            XCTAssertTrue(session.items.rows.isEmpty)
            XCTAssertTrue(session.projects.rows.isEmpty)
            XCTAssertTrue(session.grants.rows.isEmpty)
        }
    }

    @MainActor func testBusyStatusPreservesWorkspaceAndRecoversWithBackoff() async {
        let client = ScriptedClient(); await client.configure(grants: 1, pending: 2)
        let session = VaultSession(client: client); await session.poll()
        await client.busy(100)
        let start = ContinuousClock.now
        await session.poll()
        XCTAssertGreaterThanOrEqual(start.duration(to: .now), .seconds(2))
        XCTAssertLessThan(start.duration(to: .now), .seconds(4))
        XCTAssertEqual(session.state, .ready)
        XCTAssertEqual(session.pendingCount, 2)
        XCTAssertEqual(session.items.rows.count, 1)
        XCTAssertEqual(session.projects.rows.count, 1)
        XCTAssertEqual(session.grants.rows.count, 1)
        XCTAssertEqual(session.notice, "EnvCloak is busy finishing an unlock or approval. Try again in a moment.")
        let calls = await client.calls("status")
        XCTAssertGreaterThan(calls, 2)
        XCTAssertLessThan(calls, 25, "Busy retries must back off")
        await client.busy(2)
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        XCTAssertNil(session.notice, "A recovered status must clear the stale Busy notice")
        let lists = await client.calls("items.list")
        XCTAssertEqual(lists, 1, "Busy must not reset the change detector")
        await client.busy(2); await client.configure(vault: "locked")
        await session.poll()
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.items.rows.isEmpty)
    }

    @MainActor func testBusyAtLaunchNeverAdvertisesUnlockAndCancellationStopsRetries() async {
        let client = ScriptedClient(); await client.busy(100)
        let session = VaultSession(client: client)
        let polling = Task { await session.poll() }
        while await client.calls("status") == 0 { await Task.yield() }
        polling.cancel(); await polling.value
        XCTAssertEqual(session.state, .connecting)
        XCTAssertNil(session.notice)
        await client.busy(2)
        await session.poll()
        XCTAssertEqual(session.state, .ready)
    }

    @MainActor func testGroupingAndUnsafeLinks() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .provider).map(\.title), ["example"])
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .account).map(\.title), ["fixture@example.invalid"])
        XCTAssertEqual(session.keySections(query: "", filter: .all, scope: nil, grouping: .project).map(\.title), ["No adopted project"])
        XCTAssertEqual(MetadataRequest.slug(DaemonText("fixture#field")), DaemonText("fixture"))
        XCTAssertNotNil(MetadataRequest.safeLink(DaemonText("https://example.invalid/docs")))
        for bad in ["file:///tmp/example", "javascript:alert(1)", "https://user:password@example.invalid", "https://example.invalid/\n"] {
            XCTAssertNil(MetadataRequest.safeLink(DaemonText(bad)))
        }
    }

    @MainActor func testLostRevokeResponseIsUnknownAndReconciled() async {
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll()
        await client.loseRevokeResponse()
        await session.revoke(DaemonText("fixture-grant"))
        XCTAssertEqual(session.notice, "The revoke outcome could not be confirmed. Grants have been refreshed.")
        let calls = await client.calls("grants.list")
        XCTAssertEqual(calls, 2)
        XCTAssertFalse(session.actionInProgress)
    }

    @MainActor func testManifestEditsHaveTheirOwnRefreshSignal() async throws {
        let directory = URL(fileURLWithPath: "/tmp/ec05-manifest-" + UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let manifest = directory.appendingPathComponent("envcloak.toml")
        try Data("first".utf8).write(to: manifest)
        let client = ScriptedClient(); let session = VaultSession(client: client)
        await session.poll(); await session.openProject(DaemonText(directory.path))
        await session.poll()
        let before = await client.calls("items.check")
        XCTAssertEqual(before, 1)
        try Data("other".utf8).write(to: manifest, options: .atomic)
        await session.poll()
        let after = await client.calls("items.check")
        XCTAssertEqual(after, 2)
        let items = await client.calls("items.list")
        XCTAssertEqual(items, 1)
    }

    @MainActor func testAddedFoldersPersistOnlyPathsAndRefuseUnavailableStorage() throws {
        let directory = URL(fileURLWithPath: "/tmp/ec05-folders-" + UUID().uuidString.prefix(8))
        let file = directory.appendingPathComponent("project-folders.json")
        let folders = try ProjectFolders(file: file)
        let store = ProjectsStore(client: nil, folders: folders)
        let project = directory.appendingPathComponent("project")
        try store.add(project)
        try store.add(project)
        XCTAssertEqual(try JSONDecoder().decode([String].self, from: Data(contentsOf: file)), [project.path])
        XCTAssertEqual(try ProjectFolders(file: file).paths, [DaemonText(project.path)])
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let unavailable = ProjectsStore(client: nil, folders: nil)
        XCTAssertThrowsError(try unavailable.add(project))
        XCTAssertTrue(unavailable.added.isEmpty)
    }

    func testUnavailableRoutesNeverAdvertiseShippedFeatures() {
        for route in [Route.approvals, .activity, .agents, .keys(.exposed)] {
            XCTAssertNil(route.unavailableMessage)
        }
        XCTAssertEqual(Route.later(.spend).unavailableMessage, "Spend arrives in M4")
        XCTAssertEqual(Route.later(.devices).unavailableMessage, "Devices arrive in M5")
    }

    @MainActor func testExposedKeysFilterOnlyReturnsItemsWithExposedMetadata() async {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(itemCount: 3)
        await client.expose([1])
        let session = VaultSession(client: client)
        await session.poll()
        XCTAssertEqual(session.filteredKeys(query: "", filter: .all, scope: nil).map(\.slug.escaped), ["fixture-0", "fixture-1", "fixture-2"])
        XCTAssertEqual(session.filteredKeys(query: "", filter: .exposed, scope: nil).map(\.slug.escaped), ["fixture-1"])
    }

    @MainActor func testSoftwareKeyTouchIDUnlockEnrolmentAndSSHRefusal() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(vault: "locked")
        let unlockKey = SoftwareUnlockKey()
        let approveKey = SoftwareApprovalSigner()
        let overrideKeys = EnrolledPublicKeys(
            unlockPublicKeyHex: unlockKey.publicKeyHex,
            approvePublicKeyHex: approveKey.publicKeyHex
        )
        let session = VaultSession(
            client: client,
            unlockKey: unlockKey,
            approvalSigner: approveKey,
            enrolledPublicKeysOverride: overrideKeys
        )
        session.sshSession = true
        await session.poll()
        XCTAssertEqual(session.state, .locked)

        let sshUnlocked = await session.unlockWithTouchID()
        XCTAssertFalse(sshUnlocked)
        XCTAssertEqual(
            session.notice,
            "Touch ID cannot be used over SSH. Use envcloak unlock and envcloak approve in Terminal."
        )
        let sshBeginCalls = await client.calls("app.unlock.begin")
        XCTAssertEqual(sshBeginCalls, 0)

        session.sshSession = false
        let started = await session.beginEnrolment()
        XCTAssertTrue(started)
        XCTAssertEqual(session.enrolmentPendingId?.escaped, "ENROL123")
        XCTAssertFalse(session.enrolmentCompleted)
        let enrollState = await session.pollEnrolment()
        XCTAssertEqual(enrollState, .enrolled)
        XCTAssertTrue(session.enrolmentCompleted)
        XCTAssertNil(session.enrolmentPendingId)

        let vmk = Data((0..<32).map { UInt8($0 + 1) })
        let vaultIDHex = "00112233445566778899aabbccddeeff"
        let unlockerIDHex = "ffeeddccbbaa99887766554433221100"
        let sealedEnvelope = try SoftwareUnlockKey.sealEnvelope(
            vmk: vmk,
            recipientPublicKey: unlockKey.privateKey.publicKey,
            vaultIDHex: vaultIDHex,
            unlockerIDHex: unlockerIDHex,
            epoch: 1
        )
        let daemonEphKey = Curve25519.KeyAgreement.PrivateKey()
        let challengeHex = String(repeating: "ab", count: 32)
        await client.setUnlockBegin([
            "request_id": "UNLK0001",
            "unlocker_id": unlockerIDHex,
            "vault_id": vaultIDHex,
            "epoch": 1,
            "challenge": challengeHex,
            "envelope": [
                "enc": sealedEnvelope.enc.escaped,
                "ciphertext": sealedEnvelope.ciphertext.escaped,
            ],
            "daemon_eph_pub": HexCoding.encode(daemonEphKey.publicKey.rawRepresentation),
        ])

        let unlocked = await session.unlockWithTouchID()
        XCTAssertTrue(unlocked)
        XCTAssertNil(session.notice)
        XCTAssertEqual(session.state, .ready)
        XCTAssertEqual(unlockKey.lastReason, "unlock your vault")
        let unlockCalls = await client.calls("app.unlock")
        XCTAssertEqual(unlockCalls, 1)
    }

    @MainActor func testStandingApprovalsScopeLabelAndRevoke() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.setStandingCount(1)
        let session = VaultSession(client: client)
        await session.poll()

        XCTAssertEqual(session.grants.standing.count, 1)
        let standing = try XCTUnwrap(session.grants.standing.first)
        XCTAssertEqual(
            standing.scopeLabel,
            "any claude_code session in this project, including one started by another program, gets these keys without asking"
        )

        await session.revokeStanding(standing.id)
        let revokeCalls = await client.calls("standing.revoke")
        XCTAssertEqual(revokeCalls, 1)
        XCTAssertTrue(session.grants.standing.isEmpty)
    }

    @MainActor func testApprovalWindowModelV2StatementGuardProposalsAndOutcomes() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(pending: 1)
        let signer = SoftwareApprovalSigner()
        let session = VaultSession(client: client, approvalSigner: signer)
        await session.poll()

        let model = ApprovalWindowModel(session: session)
        await model.load(requestId: DaemonText("REQ0ABCD"))
        let descriptor = try XCTUnwrap(model.descriptor)
        XCTAssertEqual(descriptor.request.escaped, "REQ0ABCD")

        // Immediately after open, the 0.5 s focus/change guard disables Approve.
        XCTAssertTrue(model.isWithinGuardWindow)
        XCTAssertFalse(model.canApprove)

        // Even after the 0.5 s guard finishes, an unticked live key keeps Approve disabled (M3-J1).
        model.completeGuardPeriodForTesting()
        XCTAssertFalse(model.isWithinGuardWindow)
        XCTAssertFalse(model.allLiveKeysTicked)
        XCTAssertFalse(model.canApprove)
        await model.approve()
        let prematureApproveCalls = await client.calls("app.approve")
        XCTAssertEqual(prematureApproveCalls, 0)

        // Ticking the live key restarts the 0.5 s content-change guard.
        model.toggleLiveKey("STRIPE_SECRET_KEY")
        XCTAssertTrue(model.allLiveKeysTicked)
        XCTAssertTrue(model.isWithinGuardWindow)
        XCTAssertFalse(model.canApprove)

        model.completeGuardPeriodForTesting()
        XCTAssertTrue(model.canApprove)

        let statementBytes = try XCTUnwrap(model.currentStatementData())
        XCTAssertTrue(statementBytes.starts(with: Data("envcloak-statement/2\n".utf8)))
        let expectedDigest = CanonicalStatement.digestHex(
            descriptor,
            options: model.currentApproveOptions()
        )

        await model.approve()
        XCTAssertEqual(
            model.outcome,
            .approved(grantId: DaemonText("grant-approved-1"), expiresInSecs: 28800)
        )
        XCTAssertEqual(signer.lastReason, "approve npm test in project with 2 keys")
        let receipt = await client.approvedReceipt()
        XCTAssertEqual(receipt.digest, expectedDigest)
        let sigHex = try XCTUnwrap(receipt.signature)
        let sigData = try XCTUnwrap(HexCoding.decode(sigHex, expectedByteCount: 64))
        let rawSig = try P256.Signing.ECDSASignature(rawRepresentation: sigData)
        XCTAssertTrue(
            signer.privateKey.publicKey.isValidSignature(
                rawSig,
                for: SHA256.hash(data: statementBytes)
            )
        )

        // Proposal swap ("Use test key instead") denies the live request and records the swapped outcome.
        var appliedEdit: BindingEdit?
        session.bindings.applyOverride = { edit in
            appliedEdit = edit
            return true
        }
        await model.load(requestId: DaemonText("REQ0ABCD"))
        let proposal = try XCTUnwrap(model.descriptor?.proposals.first)
        await model.useTestKeyInstead(proposal)
        XCTAssertEqual(
            model.outcome,
            .proposalApplied(envName: "STRIPE_SECRET_KEY", slug: "stripe/acme-test")
        )
        XCTAssertEqual(appliedEdit?.envName, "STRIPE_SECRET_KEY")
        XCTAssertEqual(appliedEdit?.reference, "stripe/acme-test")
        XCTAssertNil(appliedEdit?.profile)
        let denyCalls = await client.calls("deny")
        XCTAssertEqual(denyCalls, 1)

        // Daemon refusal outcomes and expiry context invalidation.
        for (error, expectedOutcome) in [
            (EnvCloakError.rpc(.statementMismatch, nil), ApprovalOutcome.statementChanged),
            (EnvCloakError.rpc(.vaultLocked, nil), .vaultLocked),
            (EnvCloakError.rpc(.liveNotTicked, nil), .liveNotTicked),
            (EnvCloakError.rpc(.noSuchRequest, nil), .expired),
        ] {
            await client.setApproveError(error)
            await model.load(requestId: DaemonText("REQ0ABCD"))
            model.toggleLiveKey("STRIPE_SECRET_KEY")
            model.completeGuardPeriodForTesting()
            await model.approve()
            XCTAssertEqual(model.outcome, expectedOutcome)
        }
        await client.setApproveError(nil)

        await model.load(requestId: DaemonText("REQ0ABCD"))
        let invalidatedBefore = signer.invalidatedCount
        model.triggerExpiry()
        XCTAssertEqual(model.outcome, .expired)
        XCTAssertEqual(signer.invalidatedCount, invalidatedBefore + 1)
    }

    @MainActor func testStandingCapCoveredLiveGuardAndProposalEditSemantics() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        let session = VaultSession(client: client)
        await session.poll()

        // F-1: Standing choices are capped at 30 days and only offered when descriptor.standing != nil and all bindings are test.
        XCTAssertEqual(
            ApprovalDurationChoice.allCases.filter(\.isStanding).map(\.durationSecs),
            [604_800, 2_592_000]
        )

        let model = ApprovalWindowModel(session: session)
        await model.load(requestId: DaemonText("REQ0ABCD"))
        XCTAssertFalse(model.isStandingCapable)
        XCTAssertFalse(model.availableDurationChoices.contains(where: \.isStanding))

        func decodeDescriptor(_ bodyJSON: String) throws -> PendingDescriptor {
            let envelope = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\(bodyJSON)}"
            return try Frame(text: envelope).response(id: 1)
        }

        let standingEligibleJSON = """
        {
          "request": "REQSTAND",
          "nonce": "\(String(repeating: "ab", count: 32))",
          "created_secs": 1000,
          "expires_in_secs": 540,
          "subject": {
            "kind": "agent",
            "label": "claude_code",
            "caller_pid": 100,
            "root": { "pid": 90, "start_time": 123456, "exe": "/usr/local/bin/claude" }
          },
          "project": {
            "dir": "/tmp/project",
            "manifest": "/tmp/project/envcloak.toml",
            "manifest_sha256": "\(String(repeating: "c", count: 64))",
            "new_project": false
          },
          "bindings": [
            {
              "env_name": "OPENAI_API_KEY",
              "slug": "openai/acme-test",
              "item": "item-test-1",
              "field": "field-test-1",
              "field_name": "value",
              "classification": "test",
              "first_use": false,
              "granted": false
            }
          ],
          "proposals": [],
          "standing": {
            "exe": "/usr/local/bin/claude"
          },
          "mode": "inject",
          "argv": ["npm", "test"]
        }
        """
        let standingDescriptor = try decodeDescriptor(standingEligibleJSON)
        model.applyDescriptor(standingDescriptor)
        XCTAssertTrue(model.isStandingCapable)
        XCTAssertTrue(model.availableDurationChoices.contains(.standingDays7))
        XCTAssertTrue(model.availableDurationChoices.contains(.standingDays30))

        // F-2: Covered live binding must still be ticked for agent/unknown subjects; terminal subjects have no live guard.
        let coveredLiveJSON = """
        {
          "request": "REQCOVLIVE",
          "nonce": "\(String(repeating: "ab", count: 32))",
          "created_secs": 1000,
          "expires_in_secs": 540,
          "subject": {
            "kind": "agent",
            "label": "claude_code",
            "caller_pid": 100,
            "root": { "pid": 90, "start_time": 123456, "exe": "/usr/local/bin/claude" }
          },
          "project": {
            "dir": "/tmp/project",
            "manifest": "/tmp/project/envcloak.toml",
            "manifest_sha256": "\(String(repeating: "c", count: 64))",
            "new_project": false
          },
          "bindings": [
            {
              "env_name": "OPENAI_API_KEY",
              "slug": "openai/acme-test",
              "item": "item-test-1",
              "field": "field-test-1",
              "field_name": "value",
              "classification": "test",
              "first_use": false,
              "granted": false
            },
            {
              "env_name": "COVERED_LIVE_KEY",
              "slug": "stripe/acme-live",
              "item": "item-live-1",
              "field": "field-live-1",
              "field_name": "value",
              "classification": "live",
              "first_use": false,
              "granted": true
            }
          ],
          "proposals": [
            {
              "env_name": "STRIPE_SECRET_KEY",
              "live_slug": "stripe/acme-live",
              "test_slug": "stripe/acme-test",
              "test_field": "secret",
              "source": { "layer": "profile", "profile": "dev" }
            },
            {
              "env_name": "LOCAL_LIVE_KEY",
              "live_slug": "stripe/acme-live",
              "test_slug": "stripe/acme-test",
              "source": { "layer": "ref" }
            }
          ],
          "mode": "inject",
          "argv": ["npm", "test"]
        }
        """
        let coveredLiveDescriptor = try decodeDescriptor(coveredLiveJSON)
        model.applyDescriptor(coveredLiveDescriptor)
        XCTAssertTrue(model.isLiveGuarded)
        XCTAssertEqual(model.liveBindings.map(\.env_name.escaped), ["COVERED_LIVE_KEY"])
        XCTAssertFalse(model.allLiveKeysTicked)
        model.toggleLiveKey("COVERED_LIVE_KEY")
        XCTAssertTrue(model.allLiveKeysTicked)
        XCTAssertEqual(model.currentApproveOptions().live, ["COVERED_LIVE_KEY"])

        let terminalLiveJSON = coveredLiveJSON.replacingOccurrences(of: "\"kind\": \"agent\"", with: "\"kind\": \"terminal\"")
        let terminalDescriptor = try decodeDescriptor(terminalLiveJSON)
        model.applyDescriptor(terminalDescriptor)
        XCTAssertFalse(model.isLiveGuarded)
        XCTAssertTrue(model.liveBindings.isEmpty)
        XCTAssertTrue(model.allLiveKeysTicked)
        XCTAssertTrue(model.currentApproveOptions().live.isEmpty)

        // F-3: Profile and test_field preservation, non-automatic refusal, and apply failure checks.
        let profileProposal = try XCTUnwrap(coveredLiveDescriptor.proposals.first)
        let localProposal = try XCTUnwrap(coveredLiveDescriptor.proposals.last)

        var recordedEdits: [BindingEdit] = []
        session.bindings.applyOverride = { edit in
            recordedEdits.append(edit)
            return false
        }
        let denyCallsBefore = await client.calls("deny")

        // Local override proposal cannot be applied automatically.
        await model.useTestKeyInstead(localProposal)
        if case .failed = model.outcome {} else {
            XCTFail("Expected .failed for non-automatic proposal, got \(model.outcome)")
        }
        XCTAssertTrue(recordedEdits.isEmpty)
        let denyAfterLocal = await client.calls("deny")
        XCTAssertEqual(denyAfterLocal, denyCallsBefore)

        // When apply fails, outcome is .failed and pending request is not denied.
        await model.useTestKeyInstead(profileProposal)
        if case .failed = model.outcome {} else {
            XCTFail("Expected .failed when apply returns false, got \(model.outcome)")
        }
        XCTAssertEqual(recordedEdits.count, 1)
        XCTAssertEqual(recordedEdits.first?.profile, "dev")
        XCTAssertEqual(recordedEdits.first?.reference, "stripe/acme-test#secret")
        XCTAssertEqual(
            recordedEdits.first?.cliArguments,
            ["ref", "STRIPE_SECRET_KEY=stripe/acme-test#secret", "--profile", "dev", "--json"]
        )
        let denyAfterFailedApply = await client.calls("deny")
        XCTAssertEqual(denyAfterFailedApply, denyCallsBefore)

        // When apply succeeds, request is denied and outcome is .proposalApplied with slug#field.
        session.bindings.applyOverride = { edit in
            recordedEdits.append(edit)
            return true
        }
        await model.useTestKeyInstead(profileProposal)
        XCTAssertEqual(
            model.outcome,
            .proposalApplied(envName: "STRIPE_SECRET_KEY", slug: "stripe/acme-test#secret")
        )
        let denyAfterSuccess = await client.calls("deny")
        XCTAssertEqual(denyAfterSuccess, denyCallsBefore + 1)
    }

    @MainActor func testNotificationManagerNeverIncludesArgvAndHandlesActions() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(pending: 1)
        let session = VaultSession(client: client)
        session.isFrontmostOverride = true
        await session.poll()

        let summary = try XCTUnwrap(session.grants.pending.first)
        let body = NotificationManager.bodyText(for: summary)
        XCTAssertEqual(body, "claude_code asked for 2 keys in project.")
        XCTAssertFalse(body.contains("npm"))
        XCTAssertFalse(body.contains("test"))

        let mgr = session.notifications
        await mgr.reconcile(pending: [summary], isFrontmost: true)
        XCTAssertEqual(mgr.notifiedRequestIds, ["REQ0ABCD"])
        XCTAssertEqual(
            mgr.lastAnnouncement,
            "Secret approval requested. claude_code asked for 2 keys in project."
        )
        XCTAssertNil(session.activeApprovalRequestId, "Notifications must never open the approval window by themselves")

        await mgr.handleNotificationAction(
            actionIdentifier: "com.apple.UNNotificationDefaultActionIdentifier",
            requestId: DaemonText("REQ0ABCD")
        )
        XCTAssertEqual(session.activeApprovalRequestId?.escaped, "REQ0ABCD")

        await mgr.handleNotificationAction(
            actionIdentifier: NotificationManager.denyActionId,
            requestId: DaemonText("REQ0ABCD")
        )
        let denyCalls = await client.calls("deny")
        XCTAssertEqual(denyCalls, 1)
    }

    @MainActor func testPaletteAndMenuBarActionsEmitOnlyPaletteEffectsAndSearchCopiesPlainReference() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(grants: 1, pending: 2)
        await client.expose([0])
        let session = VaultSession(client: client)
        await session.poll()

        let key = try XCTUnwrap(session.items.rows.first)
        let titles: [DaemonText: String] = [DaemonText("/tmp/project"): "Project"]
        for query in ["", "p ", "k ", "a ", ">", "fixture"] {
            let items = PaletteBuilder.items(
                query: query,
                selectedKey: key,
                projects: session.projects.directories,
                projectTitles: titles,
                keys: session.items.rows,
                grants: session.grants.rows,
                pendingCount: Int(session.pendingCount)
            )
            XCTAssertFalse(items.isEmpty, "Expected items for query '\(query)'")
            for item in items {
                XCTAssertFalse(item.isDirectPrivilegeAction, "Direct privilege action found in palette: \(item.title)")
                XCTAssertFalse(item.primaryEffect.isDirectPrivilegeAction)
                if let sec = item.secondaryEffect {
                    XCTAssertFalse(sec.isDirectPrivilegeAction)
                }
                if let opt = item.optionEffect {
                    XCTAssertFalse(opt.isDirectPrivilegeAction)
                }
            }
        }

        let menuItems = MenuBarCatalog.allActionItems(
            keys: session.items.rows,
            projects: session.projects.directories,
            projectTitles: titles,
            grants: session.grants.rows,
            pendingCount: Int(session.pendingCount),
            exposedCount: 1
        )
        XCTAssertFalse(menuItems.isEmpty)
        for item in menuItems {
            XCTAssertFalse(item.isDirectPrivilegeAction, "Direct privilege action found in menu bar: \(item.title)")
            XCTAssertFalse(item.primaryEffect.isDirectPrivilegeAction)
        }

        // Menu bar search copies reference on Return and env line on Option-Return as plain text only.
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let writer = ClipboardWriter(pasteboard: board)
        let popover = MenuBarPopover(session: session, clipboardWriter: writer)
        let search = MenuBarCatalog.searchItems(
            query: "fixture-0",
            keys: session.items.rows,
            projects: session.projects.directories,
            projectTitles: titles
        )
        let keyItem = try XCTUnwrap(search.shown.first)
        popover.runEffect(keyItem.primaryEffect)
        XCTAssertEqual(board.string(forType: .string), "envcloak://fixture-0")
        XCTAssertNil(board.data(forType: ClipboardWriter.concealedType))
        XCTAssertNil(board.data(forType: ClipboardWriter.transientType))

        let optEffect = try XCTUnwrap(keyItem.optionEffect)
        popover.runEffect(optEffect)
        XCTAssertEqual(board.string(forType: .string), "VARIABLE=\"envcloak://fixture-0\"")
        XCTAssertNil(board.data(forType: ClipboardWriter.concealedType))

        // Blink stops under Reduce Motion.
        for t in stride(from: 0.0, through: 2.0, by: 0.15) {
            XCTAssertTrue(MenuBarCatalog.isBlinkVisible(waitingCount: 2, reduceMotion: true, elapsed: t))
        }
        XCTAssertFalse(MenuBarCatalog.isBlinkVisible(waitingCount: 2, reduceMotion: false, elapsed: 0.7))

        // Dock menu items have empty keyEquivalent and match design §5.8.
        let delegate = EnvCloakAppDelegate()
        delegate.session = session
        let dockMenu = try XCTUnwrap(delegate.applicationDockMenu(NSApplication.shared))
        XCTAssertEqual(dockMenu.items.map(\.title), ["Review requests", "Add key", "Lock"])
        for menuItem in dockMenu.items {
            XCTAssertEqual(menuItem.keyEquivalent, "")
        }
    }

    @MainActor func testSignedRotateRemoveAndUnlockerWritesVerifyCanonicalStatementAndSealValue() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        let signer = SoftwareApprovalSigner()
        let session = VaultSession(
            client: client,
            approvalSigner: signer,
            enrolledTouchID: true
        )
        await session.poll()

        let writeModel = KeyWriteModel(slug: DaemonText("fixture-0"), field: DaemonText("value"))
        await writeModel.loadTarget(session)
        let target = try XCTUnwrap(writeModel.target)
        XCTAssertEqual(target.grants, 1)

        var newSecret = "sk_test_rotated_canary_998877"
        var draftInput = newSecret
        writeModel.receive(&draftInput)
        XCTAssertEqual(writeModel.count, newSecret.count)
        await writeModel.submitRotation(session)
        XCTAssertTrue(writeModel.completed)

        let rotateReceipt = await client.writeReceipt()
        let sealedHex = try XCTUnwrap(rotateReceipt.sealed)
        XCTAssertFalse(sealedHex.contains(newSecret))
        let rotateAAD = try SEHPKE.resealAAD(
            requestID: target.target.raw,
            challengeHex: target.nonce.raw
        )
        let openedRotated = try SEHPKE.openSecretFromX25519(
            sealedHex: sealedHex,
            privateKey: client.daemonEphKey,
            aad: rotateAAD
        )
        XCTAssertEqual(ClipboardWriter.utf8String(openedRotated), newSecret)

        var newSecBuf = try SecretBuffer(capacity: newSecret.utf8.count)
        try newSecret.withUTF8 { try newSecBuf.append(contentsOf: UnsafeRawBufferPointer($0)) }
        let expectedRotateStmt = WriteStatement(
            target: target.target.raw,
            nonce: target.nonce.raw,
            vault_id: target.vault_id.raw,
            action: .rotate(
                item: target.item.raw,
                slug: target.slug.raw,
                field: target.field!.raw,
                field_name: target.field_name!.raw,
                classification: target.classification.rawValue,
                prior_count: target.prior_count,
                grants: target.grants,
                new_value_sha256: SEHPKE.secretSHA256Hex(newSecBuf)
            )
        )
        XCTAssertEqual(rotateReceipt.digest, CanonicalStatement.writeDigestHex(expectedRotateStmt))

        // Signed remove
        let removeModel = KeyWriteModel(slug: DaemonText("fixture-0"), field: nil)
        await removeModel.loadTarget(session)
        await removeModel.submitRemoval(session)
        XCTAssertTrue(removeModel.completed)
        let removeReceipt = await client.writeReceipt()
        let expectedRemoveStmt = WriteStatement(
            target: target.target.raw,
            nonce: target.nonce.raw,
            vault_id: target.vault_id.raw,
            action: .remove(
                item: target.item.raw,
                slug: target.slug.raw,
                grants: target.grants
            )
        )
        XCTAssertEqual(removeReceipt.digest, CanonicalStatement.writeDigestHex(expectedRemoveStmt))

        // Signed passphrase unlocker removal
        let removedUnlocker = await session.removePassphraseUnlockerWithTouchID()
        XCTAssertTrue(removedUnlocker)
        XCTAssertTrue(session.passphraseUnlockerRemoved)
    }

    @MainActor func testRevealOpensSealedSecretHidesOnResignKeyAndWipesBuffer() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        let canary = "sk_live_reveal_canary_" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        await client.setRevealPlaintext(canary)
        let signer = SoftwareApprovalSigner()
        let session = VaultSession(
            client: client,
            approvalSigner: signer,
            enrolledTouchID: true
        )
        await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)

        final class WipeTracker: @unchecked Sendable {
            var wipedAllZero = false
            var wipeCallbacks = 0
        }
        let tracker = WipeTracker()
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let writer = ClipboardWriter(pasteboard: board)

        try await BufferProbe.$observer.withValue(BufferObserver { buf in
            tracker.wipeCallbacks += 1
            if !buf.isEmpty && buf.allSatisfy({ $0 == 0 }) {
                tracker.wipedAllZero = true
            }
        }) {
            let sightModel = KeySightModel(slug: item.slug, field: DaemonText("value"))
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 480, height: 360),
                styleMask: [.titled],
                backing: .buffered,
                defer: false
            )
            let sheet = RevealSheet(
                session: session,
                item: item,
                field: DaemonText("value"),
                clipboardWriter: writer,
                model: sightModel
            )
            let host = NSHostingView(rootView: sheet)
            window.contentView = host
            window.makeKeyAndOrderFront(nil)
            defer { window.orderOut(nil); window.contentView = nil }
            host.layoutSubtreeIfNeeded()

            await sightModel.performSight(session)
            XCTAssertTrue(sightModel.isShown)
            XCTAssertTrue(sightModel.hasSecretBuffer)
            XCTAssertEqual(sightModel.renderedSecret, canary)
            XCTAssertFalse(RevealSheet.allowsValueSelection)

            var desc = try XCTUnwrap(sightModel.descriptor)
            let receipt = await client.revealReceipt()
            desc.app_eph_pub = DaemonText(try XCTUnwrap(receipt.appEphPub))
            XCTAssertEqual(receipt.digest, CanonicalStatement.revealDigestHex(desc))

            // Copy writes both ConcealedType and TransientType.
            sightModel.copySecret(using: writer)
            XCTAssertEqual(sightModel.copiedNotice, "Copied. Cleared in 30 s.")
            XCTAssertEqual(board.string(forType: .string), canary)
            XCTAssertNotNil(board.data(forType: ClipboardWriter.concealedType))
            XCTAssertNotNil(board.data(forType: ClipboardWriter.transientType))

            // Simulated resign key hides at once and wipes the SecretBuffer.
            NotificationCenter.default.post(name: NSWindow.didResignKeyNotification, object: window)
            try await Task.sleep(for: .milliseconds(30))
            XCTAssertFalse(sightModel.isShown)
            XCTAssertFalse(sightModel.hasSecretBuffer)
            XCTAssertNil(sightModel.renderedSecret)
            XCTAssertTrue(tracker.wipedAllZero)
        }
    }

    @MainActor func testSealedPasteInspectCommitAndAskDecline() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.setAsksCount(1)
        await client.configure(pending: 1)
        let session = VaultSession(client: client)
        await session.poll()

        XCTAssertEqual(session.grants.asks.count, 1)
        let ask = try XCTUnwrap(session.grants.asks.first)
        XCTAssertEqual(ask.ask.escaped, "ASK0ABCD")

        let model = PasteModel(ask: ask)
        XCTAssertEqual(model.account, "dev@example.com")
        var secret = ["sk", "proj", UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")].joined(separator: "-")
        model.receive(&secret)

        XCTAssertTrue(secret.isEmpty)
        await model.inspect(session)
        XCTAssertEqual(model.stagedId?.escaped, "STAGE123")
        XCTAssertEqual(model.inspection?.provider?.escaped, "openai")
        XCTAssertEqual(model.inspection?.suggested_slug?.escaped, "openai-work")

        await model.save(session)
        let saved = try XCTUnwrap(model.saved)
        XCTAssertEqual(saved.item.slug.escaped, "openai-work")
        let pasteCommitCalls = await client.calls("app.paste")
        XCTAssertEqual(pasteCommitCalls, 1)

        // Decline ask
        let declineModel = PasteModel(ask: ask)
        let declined = await declineModel.decline(session)
        XCTAssertTrue(declined)
        let declineCalls = await client.calls("app.asks.decline")
        XCTAssertEqual(declineCalls, 1)
    }

    @MainActor func testReviewRemediationF01ThroughF05() async throws {
        // F-01: Target sentinel colons ("unlocker:add" / "unlocker:remove"), signing identity,
        // and Touch ID-only transition removing the earlier SE unlocker and updating unlocker_id.
        XCTAssertEqual(MetadataRequest.itemsTargetUnlockerAdd().slug, "unlocker:add")
        XCTAssertEqual(MetadataRequest.itemsTargetUnlockerRemove().slug, "unlocker:remove")

        let client = ScriptedClient()
        await client.plainSlugs()
        do {
            _ = try await client.call(AppItemsTarget(slug: "unlocker_add"))
            XCTFail("Expected ScriptedClient to reject underscore sentinel unlocker_add")
        } catch let error as EnvCloakError {
            XCTAssertEqual(error, .rpc(.noSuchItem, nil))
        }

        let unlockPub = P256.KeyAgreement.PrivateKey().publicKey
        let approveKey = P256.Signing.PrivateKey()
        let enrolledKeys = EnrolledPublicKeys(
            unlockPublicKeyHex: HexCoding.encode(unlockPub.x963Representation),
            approvePublicKeyHex: HexCoding.encode(approveKey.publicKey.x963Representation)
        )
        let signer = SoftwareApprovalSigner(privateKey: approveKey)
        let unlockKey = SoftwareUnlockKey()
        let session = VaultSession(
            client: client,
            unlockKey: unlockKey,
            approvalSigner: signer,
            enrolledPublicKeysOverride: enrolledKeys,
            enrolledTouchID: true
        )
        let ownIdentity = VaultSession.readOwnSigningIdentity()
        XCTAssertFalse(ownIdentity.teamID.isEmpty)
        XCTAssertFalse(ownIdentity.signingID.isEmpty)
        session.enrolledTeamID = "TEAM998877"
        session.enrolledSigningID = "ai.envcloak.custom"
        await session.poll()

        // Enrol initial SE unlocker and poll to record enrolledUnlockerID ("unlocker-1")
        let began = await session.beginEnrolment()
        XCTAssertTrue(began)
        let enrollState = await session.pollEnrolment()
        XCTAssertEqual(enrollState, .enrolled)
        XCTAssertEqual(session.enrolledUnlockerID?.raw, "unlocker-1")

        // Transition to Touch ID-only unlocker: adds new unlocker AND removes prior SE unlocker ("unlocker-1")
        let upgraded = await session.enrollTouchIDOnlyUnlocker(label: "Mac Studio Touch ID Only")
        XCTAssertTrue(upgraded)
        XCTAssertTrue(session.touchIDOnlyEnabled)
        let upgradedUnlockerHex = "ffeeddccbbaa99887766554433221100"
        XCTAssertEqual(session.enrolledUnlockerID?.raw, upgradedUnlockerHex)
        let removedUnlockers = await client.removedUnlockerIDs()
        XCTAssertEqual(removedUnlockers, ["unlocker-1"])

        // Subsequent Touch ID unlock passes the active enrolledUnlockerID to app.unlock.begin
        let vmk = Data((0..<32).map { UInt8($0 + 1) })
        let vaultIDHex = "00112233445566778899aabbccddeeff"
        let daemonEph = Curve25519.KeyAgreement.PrivateKey()
        let env = try SoftwareUnlockKey.sealEnvelope(
            vmk: vmk,
            recipientPublicKey: unlockKey.privateKey.publicKey,
            vaultIDHex: vaultIDHex,
            unlockerIDHex: upgradedUnlockerHex,
            epoch: 1
        )
        await client.configure(vault: "locked")
        await client.setUnlockBegin([
            "request_id": "REQUNLOCK2",
            "unlocker_id": upgradedUnlockerHex,
            "vault_id": vaultIDHex,
            "epoch": 1,
            "challenge": String(repeating: "11", count: 32),
            "envelope": ["enc": env.enc.raw, "ciphertext": env.ciphertext.raw],
            "daemon_eph_pub": HexCoding.encode(daemonEph.publicKey.rawRepresentation),
        ])
        await session.poll()
        let unlocked = await session.unlockWithTouchID()
        XCTAssertTrue(unlocked)
        let beginUnlockerID = await client.unlockBeginUnlockerID()
        XCTAssertEqual(beginUnlockerID, upgradedUnlockerHex)

        // F-02: PasteModel preserves draft across inspect failure and stage expiry, and sends raw provider/account.
        await client.hostileMetadata()
        await client.setHostileAskAccount(true)
        await client.setAsksCount(1)
        await session.poll()
        let ask = try XCTUnwrap(session.grants.asks.first)
        let pasteModel = PasteModel(ask: ask)
        XCTAssertEqual(pasteModel.account, "dev\\acct@example.com")

        // Fail first beginPasteStage during inspect, then fail first commitPasteStage with .noSuchRequest
        await client.queuePasteBeginErrors([.rpc(.busy, nil)])
        var rawSecret = "sk_test_f02_preserve_draft_123456"
        pasteModel.receive(&rawSecret)
        await pasteModel.inspect(session)
        XCTAssertNil(pasteModel.stagedId, "inspect failed so stagedId is nil, but draft must remain intact")
        await pasteModel.save(session)
        XCTAssertNotNil(pasteModel.saved, "save must succeed using preserved draft after inspect failure")
        let receipt = await client.pasteReceipt()
        XCTAssertEqual(receipt.account, "dev\\acct@example.com")
        XCTAssertEqual(receipt.provider, "openai\u{202e}\u{1b}[31m")

        // Stage expiry (.noSuchRequest) re-stages from preserved draft
        let expiryModel = PasteModel(ask: nil)
        var secondSecret = "sk_test_f02_expiry_restage_654321"
        expiryModel.receive(&secondSecret)
        await expiryModel.inspect(session)
        XCTAssertNotNil(expiryModel.stagedId)
        await client.queuePasteCommitErrors([.rpc(.noSuchRequest, nil)])
        await expiryModel.save(session)
        XCTAssertNotNil(expiryModel.saved, "save must re-stage and succeed when initial stage expired")

        // F-03: KeyWriteModel preserves draft on Touch ID cancellation, ignores stale session.notice,
        // and reloads a fresh target after RPC failure.
        await client.plainSlugs()
        await client.setIncrementTargetId(true)
        session.notice = "Stale unrelated workspace notice"
        let rotModel = KeyWriteModel(slug: DaemonText("fixture-0"), field: DaemonText("value"))
        await rotModel.loadTarget(session)
        XCTAssertEqual(rotModel.target?.target.raw, "target-3")

        var rotSecret = "sk_test_f03_rotate_draft_777"
        rotModel.receive(&rotSecret)
        signer.simulatedFailure = SignerError.userCancelled
        await rotModel.submitRotation(session)
        XCTAssertFalse(rotModel.completed)
        XCTAssertEqual(rotModel.count, "sk_test_f03_rotate_draft_777".count)
        XCTAssertEqual(rotModel.notice, "Touch ID was cancelled. The key value was not replaced.")
        XCTAssertNil(session.notice, "Stale session.notice must be cleared on entry to rotateItemWithTouchID")

        // Now let signer succeed, but fail first rotate RPC with .noSuchRequest -> target reloads to target-4
        signer.simulatedFailure = nil
        await client.queueRotateErrors([.rpc(.noSuchRequest, nil)])
        await rotModel.submitRotation(session)
        XCTAssertFalse(rotModel.completed)
        XCTAssertEqual(rotModel.count, "sk_test_f03_rotate_draft_777".count)
        XCTAssertEqual(rotModel.target?.target.raw, "target-4")
        XCTAssertEqual(rotModel.notice, "The key value could not be replaced.")

        // Retry with refreshed target-4 succeeds without re-pasting
        await rotModel.submitRotation(session)
        XCTAssertTrue(rotModel.completed)
        XCTAssertEqual(rotModel.count, 0)

        // F-04: Dock badge includes asksCount and AppDelegate.reviewRequests does not double-invoke or open empty window
        await client.configure(pending: 0)
        await client.setAsksCount(2)
        await session.poll()
        XCTAssertEqual(session.notifications.lastBadge, "2")

        var approvalOpenCount = 0
        var mainOpenCount = 0
        var focusedApprovals = 0
        session.onOpenApprovalWindow = { approvalOpenCount += 1 }
        session.onOpenMainWindow = { mainOpenCount += 1 }
        session.onFocusApprovals = { focusedApprovals += 1 }

        let delegate = EnvCloakAppDelegate()
        delegate.session = session
        delegate.reviewRequests(nil)
        XCTAssertEqual(approvalOpenCount, 0, "Should not open empty approval window when only asks are waiting")
        XCTAssertEqual(focusedApprovals, 1)
        XCTAssertEqual(mainOpenCount, 1)

        await client.configure(pending: 1)
        await session.poll()
        XCTAssertEqual(session.notifications.lastBadge, "3")
        delegate.reviewRequests(nil)
        XCTAssertEqual(approvalOpenCount, 1, "Must invoke onOpenApprovalWindow exactly once")

        // F-05: session.canSignInApp and selectedField reset on key change
        XCTAssertTrue(session.canSignInApp)
        session.sshSession = true
        XCTAssertFalse(session.canSignInApp)
        session.sshSession = false
        session.selectedField = DaemonText("secondary")
        await session.selectKey(DaemonText("fixture-0"))
        XCTAssertNil(session.selectedField)
    }

    @MainActor func testScreenLockMonitorSendsAppLockDropsGrantsAndHidesRevealedSecret() async throws {
        let client = ScriptedClient()
        await client.plainSlugs()
        await client.configure(grants: 2, vault: "unlocked")
        let signer = SoftwareApprovalSigner()
        let source = FakeLockSignalSource()
        let session = VaultSession(
            client: client,
            approvalSigner: signer,
            enrolledTouchID: true,
            lockSignalSource: source
        )
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        XCTAssertEqual(session.grants.rows.count, 2)

        let item = try XCTUnwrap(session.items.rows.first)
        let sightModel = KeySightModel(slug: item.slug, field: DaemonText("value"))
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 360),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        let sheet = RevealSheet(
            session: session,
            item: item,
            field: DaemonText("value"),
            model: sightModel
        )
        let host = NSHostingView(rootView: sheet)
        window.contentView = host
        window.makeKeyAndOrderFront(nil)
        defer { window.orderOut(nil); window.contentView = nil }
        host.layoutSubtreeIfNeeded()

        await sightModel.performSight(session)
        XCTAssertTrue(sightModel.isShown)
        XCTAssertTrue(sightModel.hasSecretBuffer)

        source.emit(.screenLocked)
        for _ in 0..<40 where session.state != .locked {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(session.state, .locked)
        XCTAssertTrue(session.grants.rows.isEmpty)
        XCTAssertFalse(sightModel.isShown)
        XCTAssertFalse(sightModel.hasSecretBuffer)
        let reasonsAfterLock = await client.recordedAppLockReasons()
        XCTAssertEqual(reasonsAfterLock, [.screenLock])

        await client.configure(grants: 1, vault: "unlocked")
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        source.emit(.screensDidSleep)
        for _ in 0..<40 where session.state != .locked {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(session.state, .locked)
        let reasonsAfterSleep = await client.recordedAppLockReasons()
        XCTAssertEqual(reasonsAfterSleep, [.screenLock, .screenLock])

        await client.configure(grants: 1, vault: "unlocked")
        await session.poll()
        XCTAssertEqual(session.state, .ready)
        source.emit(.sessionDidResign)
        for _ in 0..<40 where session.state != .locked {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(session.state, .locked)
        let reasonsAfterSwitch = await client.recordedAppLockReasons()
        XCTAssertEqual(reasonsAfterSwitch, [.screenLock, .screenLock, .sessionResign])
    }

    func testGuaranteesTableEqualsSpecSection1_1() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repoRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let repoSpecURL = repoRoot.appendingPathComponent("docs/SPEC.md")
        let tmpCopyURL = URL(fileURLWithPath: "/tmp/ec-spec-copy.md")
        let specURL = (repoSpecURL.path.hasPrefix("/Volumes/") && FileManager.default.fileExists(atPath: tmpCopyURL.path))
            ? tmpCopyURL
            : repoSpecURL
        let specMarkdown = try String(contentsOf: specURL, encoding: .utf8)
        let parsedRows = GuaranteesTable.parse(specMarkdown: specMarkdown)
        XCTAssertEqual(parsedRows.count, 6)
        XCTAssertEqual(GuaranteesTable.rows, parsedRows)
        let unshippedModes = GuaranteesTable.rows.filter { !$0.isAvailableInThisRelease }.map(\.mode)
        XCTAssertEqual(
            unshippedModes,
            [
                "Proxy (HTTPS APIs; M6)",
                "Native credential helpers (AWS, git, Docker, kube; M9)",
                "Dev sign-in (own apps and test accounts; M2b)",
            ]
        )
    }

    @MainActor func testActivityStorePagingVerifyAndFilterTokens() async throws {
        let client = ScriptedClient()
        await client.hostileMetadata()
        await client.setAuditHasMorePages(true)
        let store = ActivityStore(client: client)

        await store.refetch(.all)
        XCTAssertEqual(store.entries.count, 1)
        let first = try XCTUnwrap(store.entries.first)
        XCTAssertEqual(first.seq, 2)
        XCTAssertEqual(store.nextBeforeSeq, 2)
        XCTAssertTrue(store.hasMore)
        XCTAssertEqual(
            ActivityEventPresentation.escapedCommandLine(first),
            "npm test\\u{202e}\\u{1b}[31m --token=[REDACTED]"
        )

        await store.loadMore()
        XCTAssertEqual(store.entries.map(\.seq), [2, 1])
        XCTAssertFalse(store.hasMore)

        await store.verifyLog()
        XCTAssertEqual(
            store.verifySummary,
            "All 2 entries check out. The last one is anchored in the vault."
        )
        XCTAssertEqual(store.verifyIsOK, true)
    }

    @MainActor func testLoginItemMigrationUninstallsCLIBeforeRegisteringAndNeverRunsBoth() async {
        var operations: [String] = []
        var cliPresent = true
        let fakeService = FakeLoginItemService(
            onRegisterAgent: {
                XCTAssertFalse(cliPresent, "SMAppService.agent must never be registered while CLI LaunchAgent is still installed")
                operations.append("register_agent")
            }
        )
        let controller = LoginItemController(
            service: fakeService,
            cliAgentDetector: { cliPresent },
            cliDaemonUninstaller: {
                operations.append("uninstall_cli")
                cliPresent = false
            },
            bundlePathProvider: { "/Applications/EnvCloak.app" }
        )

        let ok = await controller.registerBackgroundAgent()
        XCTAssertTrue(ok)
        XCTAssertEqual(operations, ["uninstall_cli", "register_agent"])
        XCTAssertEqual(controller.agentStatus, .enabled)

        // When CLI daemon uninstall fails, SMAppService.agent must NEVER be registered.
        operations.removeAll()
        cliPresent = true
        fakeService.currentAgentStatus = .notRegistered
        let failingController = LoginItemController(
            service: fakeService,
            cliAgentDetector: { cliPresent },
            cliDaemonUninstaller: {
                operations.append("uninstall_cli_failed")
                throw CLIError.failed(1)
            },
            bundlePathProvider: { "/Applications/EnvCloak.app" }
        )
        let failedResult = await failingController.registerBackgroundAgent()
        XCTAssertFalse(failedResult)
        XCTAssertEqual(operations, ["uninstall_cli_failed"])
        XCTAssertEqual(failingController.agentStatus, .notRegistered)
    }

    @MainActor func testLoginItemCheckAtLaunchShowsRequiresApprovalBannerAndReRegistersOnMove() {
        var operations: [String] = []
        let fakeService = FakeLoginItemService(
            initialAgentStatus: .requiresApproval,
            onRegisterAgent: { operations.append("register_agent") },
            onUnregisterAgent: { operations.append("unregister_agent") }
        )
        let controller = LoginItemController(
            service: fakeService,
            cliAgentDetector: { false },
            cliDaemonUninstaller: {},
            bundlePathProvider: { fakeService.currentBundlePath }
        )
        controller.lastRegisteredBundlePath = "/Applications/EnvCloak.app"

        controller.checkStatusOnLaunch()
        XCTAssertEqual(controller.agentStatus, .requiresApproval)
        XCTAssertEqual(controller.banner, "Background item disabled in Login Items")
        XCTAssertTrue(controller.showsApprovalBanner)
        XCTAssertTrue(operations.isEmpty)

        // Moving the app bundle triggers unregister + re-register on launch check.
        fakeService.currentBundlePath = "/Users/Shared/EnvCloak.app"
        controller.checkStatusOnLaunch()
        XCTAssertEqual(operations, ["unregister_agent", "register_agent"])
        XCTAssertEqual(controller.lastRegisteredBundlePath, "/Users/Shared/EnvCloak.app")
    }

    func testCLIInstallerLinksFirstWritableCandidateWarnsOnShadowAndFallsBackToManualLn() throws {
        let root = URL(fileURLWithPath: "/tmp/ec-cli-install-" + UUID().uuidString.prefix(8))
        let shadowDir = root.appendingPathComponent("shadow-bin")
        let writableDir = root.appendingPathComponent("writable-bin")
        let bundledBinary = root.appendingPathComponent("EnvCloak.app/Contents/MacOS/envcloak")
        try FileManager.default.createDirectory(at: shadowDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: writableDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: bundledBinary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("#!/bin/sh\n".utf8).write(to: bundledBinary)
        let shadowBinary = shadowDir.appendingPathComponent("envcloak")
        try Data("#!/bin/sh\n".utf8).write(to: shadowBinary)
        defer { try? FileManager.default.removeItem(at: root) }

        let installer = CLIInstaller(
            bundledCLIPath: bundledBinary.path,
            candidateDirectories: ["/nonexistent/unwritable/bin", writableDir.path],
            searchDirectories: [shadowDir.path, writableDir.path]
        )
        let outcome = installer.install()
        let expectedLink = writableDir.appendingPathComponent("envcloak").path
        XCTAssertEqual(
            outcome,
            .installed(
                linkPath: expectedLink,
                targetPath: bundledBinary.path,
                shadowedBy: shadowBinary.path
            )
        )
        let status = installer.status()
        XCTAssertTrue(status.isInstalled)
        XCTAssertEqual(status.installedLinkPath, expectedLink)
        XCTAssertEqual(status.shadowedBy, shadowBinary.path)

        let unwritableInstaller = CLIInstaller(
            bundledCLIPath: "/Applications/EnvCloak.app/Contents/MacOS/envcloak",
            candidateDirectories: ["/nonexistent/unwritable/bin"]
        )
        let fallback = unwritableInstaller.install()
        if case .manualCommand(let command, _) = fallback {
            XCTAssertEqual(
                command,
                "ln -sf '/Applications/EnvCloak.app/Contents/MacOS/envcloak' '/nonexistent/unwritable/bin/envcloak'"
            )
        } else {
            XCTFail("Expected manualCommand fallback, got \(fallback)")
        }
    }

    @MainActor func testAgentsCoverageNeverShowsActiveWhenDegradedAndSortsFailedProbesFirst() async throws {
        let statusJSON = """
        {
          "agents": [
            {
              "agent": "claude_code",
              "name": "Claude Code",
              "tier": 1,
              "version": "1.2.3",
              "exe": "/usr/local/bin/claude",
              "surfaces": [
                {
                  "surface": "prompt_to_model",
                  "state": "active",
                  "reasons": [],
                  "probe": "passed",
                  "skipped": []
                },
                {
                  "surface": "shell",
                  "state": "degraded",
                  "reasons": ["hook_missing"],
                  "probe": "failed",
                  "skipped": []
                }
              ],
              "envcloak_server": {
                "availability": "active",
                "reasons": [],
                "probe": "passed",
                "sentinel": "not_run"
              }
            }
          ]
        }
        """
        let installPreviewJSON = """
        {
          "hosts": [
            {
              "host": "claude_code",
              "version": "1.2.3",
              "found": "/usr/local/bin/claude",
              "changes": [
                {
                  "path": "/tmp/.claude/settings.json",
                  "what": "install PreToolUse hook"
                }
              ]
            }
          ],
          "project": null,
          "applied": false,
          "complete": true
        }
        """
        let installAppliedJSON = installPreviewJSON.replacingOccurrences(of: "\"applied\": false", with: "\"applied\": true")

        let decoded = try JSONDecoder().decode(AgentStatusReport.self, from: Data(statusJSON.utf8))
        let row = try XCTUnwrap(decoded.agents.first)
        XCTAssertEqual(row.sortedSurfaces.map(\.surface), [.shell, .promptToModel])

        let shellSurface = try XCTUnwrap(row.surfaces.first { $0.surface == .shell })
        XCTAssertEqual(shellSurface.state, .degraded)
        XCTAssertEqual(shellSurface.displayedState, .degraded)
        XCTAssertNotEqual(shellSurface.displayedState, .active)
        XCTAssertEqual(shellSurface.formattedLine, "degraded (hook_missing; probe=failed)")
        XCTAssertEqual(
            shellSurface.humanReasonSummary,
            "EnvCloak hook is missing from the host configuration"
        )

        final class CLIRecorder: @unchecked Sendable {
            var invocations: [[String]] = []
        }
        let recorder = CLIRecorder()
        let store = AgentsStore { args in
            recorder.invocations.append(args)
            if args.contains("status") {
                return CLIOutput(exitCode: 0, json: statusJSON, errorText: "")
            }
            if args.contains("--yes") {
                return CLIOutput(exitCode: 0, json: installAppliedJSON, errorText: "")
            }
            return CLIOutput(exitCode: 0, json: installPreviewJSON, errorText: "")
        }

        await store.refresh()
        XCTAssertEqual(store.agents.first?.surfaces.map(\.surface), [.shell, .promptToModel])

        await store.prepareInstall(for: "claude_code")
        XCTAssertEqual(
            recorder.invocations.last,
            ["agents", "install", "--json", "--agent", "claude_code"]
        )
        XCTAssertEqual(store.pendingInstallPlan?.plannedFilePaths, ["/tmp/.claude/settings.json"])

        await store.confirmInstall()
        XCTAssertTrue(
            recorder.invocations.contains(["agents", "install", "--yes", "--json", "--agent", "claude_code"])
        )
        XCTAssertNil(store.pendingInstallPlan)
        XCTAssertEqual(store.notice, "Updated integration files: /tmp/.claude/settings.json.")
    }

    @MainActor func testM317ReviewRemediationF01ThroughF06() async throws {
        // F-01: VaultSession.run() activates screenLockMonitor when not already started.
        let client = ScriptedClient()
        await client.plainSlugs()
        let sessionForRun = VaultSession(client: client)
        XCTAssertFalse(sessionForRun.isScreenLockMonitoringActive)
        let runTask = Task { await sessionForRun.run() }
        for _ in 0..<40 where !sessionForRun.isScreenLockMonitoringActive {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(sessionForRun.isScreenLockMonitoringActive)
        runTask.cancel()
        await runTask.value
        sessionForRun.screenLockMonitor?.stop()

        // F-02: AgentsStore.confirmInstall() surfaces partial/refused changes from non-zero JSON exit.
        let incompleteJSON = """
        {
          "hosts": [
            {
              "host": "claude_code",
              "version": "1.2.3",
              "found": "/usr/local/bin/claude",
              "changes": [
                {
                  "path": "/tmp/.claude/settings.json",
                  "outcome": "refused",
                  "message": "malformed settings.json"
                }
              ]
            }
          ],
          "project": null,
          "applied": true,
          "complete": false
        }
        """
        let incompleteStore = AgentsStore { args in
            if args.contains("--yes") {
                return CLIOutput(exitCode: 1, json: incompleteJSON, errorText: "")
            }
            return CLIOutput(exitCode: 0, json: "{\"agents\":[]}", errorText: "")
        }
        await incompleteStore.confirmInstall()
        XCTAssertEqual(
            incompleteStore.notice,
            "Integration install incomplete: /tmp/.claude/settings.json (refused: malformed settings.json)."
        )

        // F-03: Toggling Touch ID only off performs a signed unlocker replacement, preserves true on cancel,
        // and ProjectFolders persists touchIDOnlyEnabled, recoveryConfirmed, and passphraseUnlockerRemoved across launches.
        let secRoot = URL(fileURLWithPath: "/tmp/ec-sec-state-" + UUID().uuidString.prefix(8))
        defer { try? FileManager.default.removeItem(at: secRoot) }
        let secFile = secRoot.appendingPathComponent("project-folders.json")
        let folders1 = try ProjectFolders(file: secFile)
        let unlockPub = P256.KeyAgreement.PrivateKey().publicKey
        let approveKey = P256.Signing.PrivateKey()
        let enrolledKeys = EnrolledPublicKeys(
            unlockPublicKeyHex: HexCoding.encode(unlockPub.x963Representation),
            approvePublicKeyHex: HexCoding.encode(approveKey.publicKey.x963Representation)
        )
        let signer = SoftwareApprovalSigner(privateKey: approveKey)
        let unlockKey = SoftwareUnlockKey()
        let session1 = VaultSession(
            client: client,
            folders: folders1,
            unlockKey: unlockKey,
            approvalSigner: signer,
            enrolledPublicKeysOverride: enrolledKeys,
            enrolledTouchID: true
        )
        await session1.poll()
        _ = await session1.beginEnrolment()
        _ = await session1.pollEnrolment()
        await session1.setTouchIDOnly(true)
        XCTAssertTrue(session1.touchIDOnlyEnabled)

        // Cancel downgrade -> touchIDOnlyEnabled must remain true!
        signer.simulatedFailure = SignerError.userCancelled
        await session1.setTouchIDOnly(false)
        XCTAssertTrue(session1.touchIDOnlyEnabled, "Cancelled downgrade must leave touchIDOnlyEnabled true")
        signer.simulatedFailure = nil

        // Succeed downgrade -> replaces unlocker and sets touchIDOnlyEnabled false
        let addCallsBeforeDowngrade = await client.calls("app.unlocker.add")
        let removeCallsBeforeDowngrade = await client.calls("app.unlocker.remove")
        await session1.setTouchIDOnly(false)
        XCTAssertFalse(session1.touchIDOnlyEnabled)
        let addCallsAfterDowngrade = await client.calls("app.unlocker.add")
        let removeCallsAfterDowngrade = await client.calls("app.unlocker.remove")
        XCTAssertEqual(addCallsAfterDowngrade, addCallsBeforeDowngrade + 1)
        XCTAssertEqual(removeCallsAfterDowngrade, removeCallsBeforeDowngrade + 1)

        // Re-enable Touch ID only, confirm recovery kit, and remove passphrase unlocker -> verify persistence across launch
        await session1.setTouchIDOnly(true)
        session1.markRecoveryConfirmed()
        let removedPass = await session1.removePassphraseUnlockerWithTouchID()
        XCTAssertTrue(removedPass)

        let folders2 = try ProjectFolders(file: secFile)
        let session2 = VaultSession(client: client, folders: folders2, enrolledTouchID: true)
        XCTAssertTrue(session2.touchIDOnlyEnabled)
        XCTAssertTrue(session2.recoveryConfirmed)
        XCTAssertTrue(session2.passphraseUnlockerRemoved)
        XCTAssertFalse(session2.passphrasePresent)

        // F-04: LoginItemController checks status on init, persists lastRegisteredBundlePath across launches,
        // and refuses registration outside /Applications before touching CLI LaunchAgent.
        let stateFile = secRoot.appendingPathComponent("login-item-state.json")
        var cliPresent = true
        var cliUninstallCount = 0
        var registerCount = 0
        var unregisterCount = 0
        let fakeLoginService = FakeLoginItemService(
            initialAgentStatus: .notRegistered,
            onRegisterAgent: { registerCount += 1 },
            onUnregisterAgent: { unregisterCount += 1 }
        )
        fakeLoginService.currentBundlePath = "/Users/Shared/EnvCloak.app"
        let outsideController = LoginItemController(
            service: fakeLoginService,
            cliAgentDetector: { cliPresent },
            cliDaemonUninstaller: {
                cliUninstallCount += 1
                cliPresent = false
            },
            bundlePathProvider: { fakeLoginService.currentBundlePath },
            stateFileURL: stateFile
        )
        XCTAssertFalse(outsideController.isInApplicationsFolder)
        let outsideRegistered = await outsideController.registerBackgroundAgent()
        XCTAssertFalse(outsideRegistered)
        XCTAssertEqual(cliUninstallCount, 0, "Must never uninstall CLI LaunchAgent when app is outside /Applications")
        XCTAssertEqual(registerCount, 0)

        // Now move to /Applications/EnvCloak.app and register -> persists bundle path to stateFile
        fakeLoginService.currentBundlePath = "/Applications/EnvCloak.app"
        XCTAssertTrue(outsideController.isInApplicationsFolder)
        let insideRegistered = await outsideController.registerBackgroundAgent()
        XCTAssertTrue(insideRegistered)
        XCTAssertEqual(cliUninstallCount, 1)
        XCTAssertEqual(registerCount, 1)
        XCTAssertEqual(outsideController.lastRegisteredBundlePath, "/Applications/EnvCloak.app")

        // Simulate next app launch after moving bundle to /Applications/Utilities/EnvCloak.app:
        // init loads stateFile and immediately re-registers on launch.
        fakeLoginService.currentBundlePath = "/Applications/Utilities/EnvCloak.app"
        fakeLoginService.currentAgentStatus = .requiresApproval
        let relaunchedController = LoginItemController(
            service: fakeLoginService,
            cliAgentDetector: { false },
            cliDaemonUninstaller: {},
            bundlePathProvider: { fakeLoginService.currentBundlePath },
            stateFileURL: stateFile
        )
        XCTAssertEqual(unregisterCount, 1)
        XCTAssertEqual(registerCount, 2)
        XCTAssertEqual(relaunchedController.lastRegisteredBundlePath, "/Applications/Utilities/EnvCloak.app")

        // F-05: CLIInstaller refuses to delete an existing regular file binary and status() reports shadowedBy when not installed.
        let cliRoot = secRoot.appendingPathComponent("cli-f05")
        let candidateDir = cliRoot.appendingPathComponent("bin")
        let bundledCLI = cliRoot.appendingPathComponent("EnvCloak.app/Contents/MacOS/envcloak")
        try FileManager.default.createDirectory(at: candidateDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: bundledCLI.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: bundledCLI)
        let existingBinary = candidateDir.appendingPathComponent("envcloak")
        let standaloneContent = Data("#!/bin/sh\necho standalone\n".utf8)
        try standaloneContent.write(to: existingBinary)

        let f05Installer = CLIInstaller(
            bundledCLIPath: bundledCLI.path,
            candidateDirectories: [candidateDir.path],
            searchDirectories: [candidateDir.path]
        )
        let preInstallStatus = f05Installer.status()
        XCTAssertFalse(preInstallStatus.isInstalled)
        XCTAssertEqual(preInstallStatus.shadowedBy, existingBinary.path, "status() must report shadowedBy even when not installed")

        let f05Outcome = f05Installer.install()
        if case .manualCommand(_, let reason) = f05Outcome {
            XCTAssertTrue(reason.contains(existingBinary.path))
        } else {
            XCTFail("Expected manualCommand when regular file binary exists at candidate, got \(f05Outcome)")
        }
        XCTAssertEqual(try Data(contentsOf: existingBinary), standaloneContent, "Existing standalone binary must never be deleted")

        // F-06: AgentSurfaceReport.formattedLine and AgentServerReport.formattedLine escape hostile strings.
        let hostileSurface = AgentSurfaceReport(
            surface: .shell,
            state: .degraded,
            reasons: ["bad\u{202e}\u{1b}[31mreason"],
            probe: .failed,
            skipped: ["skip\u{202e}item"]
        )
        XCTAssertEqual(
            hostileSurface.formattedLine,
            "degraded (bad\\u{202e}\\u{1b}[31mreason; probe=failed, skip\\u{202e}item skipped)"
        )
        let hostileServer = AgentServerReport(
            availability: "avail\u{202e}",
            reasons: ["srv\u{1b}[31mreason"],
            probe: .passed,
            sentinel: "sent\u{202e}_ok"
        )
        XCTAssertEqual(
            hostileServer.formattedLine,
            "avail\\u{202e}; srv\\u{1b}[31mreason (probe=passed, sentinel sent\\u{202e} ok)"
        )
    }
}

@MainActor final class FakeLockSignalSource: LockSignalSource {
    private var handler: (@MainActor (LockSignal) -> Void)?

    func start(handler: @escaping @MainActor (LockSignal) -> Void) {
        self.handler = handler
    }

    func stop() {
        handler = nil
    }

    func emit(_ signal: LockSignal) {
        handler?(signal)
    }
}

final class FakeLoginItemService: LoginItemService, @unchecked Sendable {
    var currentAgentStatus: LoginItemStatus
    var currentMainAppStatus: LoginItemStatus
    var currentBundlePath = "/Applications/EnvCloak.app"
    var onRegisterAgent: (() -> Void)?
    var onUnregisterAgent: (() -> Void)?
    var openedSettingsCount = 0

    init(
        initialAgentStatus: LoginItemStatus = .notRegistered,
        initialMainAppStatus: LoginItemStatus = .notRegistered,
        onRegisterAgent: (() -> Void)? = nil,
        onUnregisterAgent: (() -> Void)? = nil
    ) {
        self.currentAgentStatus = initialAgentStatus
        self.currentMainAppStatus = initialMainAppStatus
        self.onRegisterAgent = onRegisterAgent
        self.onUnregisterAgent = onUnregisterAgent
    }

    func agentStatus() -> LoginItemStatus {
        currentAgentStatus
    }

    func registerAgent() throws {
        onRegisterAgent?()
        currentAgentStatus = .enabled
    }

    func unregisterAgent() throws {
        onUnregisterAgent?()
        currentAgentStatus = .notRegistered
    }

    func mainAppStatus() -> LoginItemStatus {
        currentMainAppStatus
    }

    func setMainAppEnabled(_ enabled: Bool) throws {
        currentMainAppStatus = enabled ? .enabled : .notRegistered
    }

    func openSystemSettingsLoginItems() {
        openedSettingsCount += 1
    }
}


actor ItemBarrierClient: WorkspaceClient {
    let client = ScriptedClient()
    let methodName: String
    init(method: String = "items.list") { methodName = method }
    var entered = false
    var arrival: CheckedContinuation<Void, Never>?
    var waiter: CheckedContinuation<Void, Never>?
    func arrived() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { waiter?.resume(); waiter = nil }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        if M.name == methodName && !entered {
            await withCheckedContinuation {
                waiter = $0; entered = true; arrival?.resume(); arrival = nil
            }
        }
        return try await client.call(method)
    }
}

actor FailingRefreshClient: WorkspaceClient {
    let client = ScriptedClient()
    var lists = 0
    var entered = false
    var arrival: CheckedContinuation<Void, Never>?
    var waiter: CheckedContinuation<Void, Never>?
    func arrived() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { waiter?.resume(); waiter = nil }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        if M.name == "items.list" {
            lists += 1
            if lists > 1 {
                await withCheckedContinuation {
                    waiter = $0; entered = true; arrival?.resume(); arrival = nil
                }
                throw EnvCloakError.protocolError
            }
        }
        return try await client.call(method)
    }
}

/// Fail only the local scope write. Renames keep all fixture artifacts for inspection.
@MainActor struct ScopeWriteFixture {
    let file: URL
    let folders: ProjectFolders
    private var scopeFile: URL { file.appendingPathExtension("scope") }
    private var savedFile: URL { file.appendingPathExtension("saved") }
    init() throws {
        let root = URL(fileURLWithPath: "/tmp/ec05-scope-write-" + UUID().uuidString.prefix(8))
        file = root.appendingPathComponent("projects.json")
        folders = try ProjectFolders(file: file)
        try folders.saveScope(DaemonText("/tmp/obsolete"))
    }
    func block() throws {
        try FileManager.default.moveItem(at: scopeFile, to: savedFile)
        try FileManager.default.createDirectory(at: scopeFile, withIntermediateDirectories: false)
    }
    func restore() throws {
        try FileManager.default.moveItem(at: scopeFile, to: file.appendingPathExtension("blocked"))
        try FileManager.default.moveItem(at: savedFile, to: scopeFile)
    }
}

/// A latched barrier allows either completion order without timing sleeps.
actor ResponseGate {
    private var entered = false
    private var released = false
    private var arrival: CheckedContinuation<Void, Never>?
    private var waiter: CheckedContinuation<Void, Never>?
    func arrived() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func wait() async {
        entered = true; arrival?.resume(); arrival = nil
        if released { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func release() { released = true; waiter?.resume(); waiter = nil }
}

actor LockRaceClient: WorkspaceClient {
    let client = ScriptedClient()
    let lockGate = ResponseGate()
    let statusGate = ResponseGate()
    private var armed = false
    private var holdStatus = false
    func arm(holdStatus: Bool) { armed = true; self.holdStatus = holdStatus }
    func call<M: DaemonMethod>(_ method: M) async throws -> M.Output {
        if armed && M.name == "lock" { await lockGate.wait() }
        // Snapshot before waiting, as an already encoded daemon response can
        // arrive after Lock even though it still describes an unlocked vault.
        let result = try await client.call(method)
        if armed && holdStatus && M.name == "status" { await statusGate.wait() }
        return result
    }
}
