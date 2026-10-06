import Darwin
import Foundation
import XCTest
@testable import EnvCloakKit

final class MethodTests: XCTestCase {
    private func params<M: DaemonMethod & ~Copyable>(_ method: borrowing M) throws -> [String: Any] {
        let frame = try method.request(id: UInt64.max)
        return try frame.body.withUnsafeBytes { bytes in
            let object = try JSONSerialization.jsonObject(with: Data(bytes)) as! [String: Any]
            XCTAssertEqual((object["id"] as! NSNumber).uint64Value, UInt64.max)
            XCTAssertEqual(object["method"] as! String, M.name)
            XCTAssertEqual(object["jsonrpc"] as! String, "2.0")
            XCTAssertEqual(Set(object.keys), ["jsonrpc", "id", "method", "params"])
            return object["params"] as! [String: Any]
        }
    }

    func testEveryEU1RequestAndValueUsesExpectedWireShape() throws {
        XCTAssertTrue(try params(Status()).isEmpty)
        XCTAssertTrue(try params(Lock()).isEmpty)
        XCTAssertTrue(try params(GrantsList()).isEmpty)
        XCTAssertTrue(try params(AuditVerify()).isEmpty)
        XCTAssertTrue(try params(BackupCreate()).isEmpty)
        XCTAssertEqual(try params(ItemsList(long: true))["long"] as? Bool, true)
        let hostile = "quote\" slash\\\n\u{202e}😀"
        XCTAssertEqual(try params(ItemsShow(slug: hostile))["slug"] as? String, hostile)
        XCTAssertEqual(try params(Deny(request: hostile))["request"] as? String, hostile)
        let check = try params(ItemsCheck(manifest: "/" + hostile, refs: [hostile]))
        XCTAssertEqual(check["manifest"] as? String, "/" + hostile)
        XCTAssertEqual(check["refs"] as? [String], [hostile])
        XCTAssertEqual(try params(GrantsRevoke())["all"] as? Bool, true)
        let one = try params(GrantsRevoke(grant: hostile))
        XCTAssertEqual(one["all"] as? Bool, false)
        XCTAssertEqual(one["grant"] as? String, hostile)
        let bytes = (0..<103).map { _ in UInt8.random(in: .min ... .max) }
        var value = try SecretBuffer()
        try value.append(contentsOf: bytes)
        let method = ItemsAdd(value: consume value, slug: hostile, provider: "provider", field: "value", account: "account", envHint: "VARIABLE", allowShort: true)
        let add = try params(method)
        XCTAssertEqual(add["value"] as? String, Data(bytes).base64EncodedString())
        XCTAssertEqual(add["slug"] as? String, hostile)
        XCTAssertEqual(add["provider"] as? String, "provider")
        XCTAssertEqual(add["field"] as? String, "value")
        XCTAssertEqual(add["account"] as? String, "account")
        XCTAssertEqual(add["env_hint"] as? String, "VARIABLE")
        XCTAssertEqual(add["allow_short"] as? Bool, true)
    }

    func testStatusSanitizesBothUntrustedStringsAndRejectsNestedExtras() throws {
        let canary = UUID().uuidString + "\u{202e}"
        let object: [String: Any] = [
            "daemon": ["version": canary, "pid": 1, "hardening": ["core_dumps_off": true, "non_dumpable": false, "hardened_runtime": false], "runtime_dir_fallback": false],
            "vault": ["state": "unavailable", "read_only": true, "unavailable": canary, "busy": false, "failed_unlocks": 0],
            "lock": ["idle_limit_secs": 60],
            "approvals": ["grants": 0, "pending": 0, "proof_failures": 0, "proof_wait_secs": 0],
            "audit": ["open": false, "unanchored": 0, "anchor_failed": false, "queued": 0, "dropped": 0]
        ]
        func frame(_ result: [String: Any]) throws -> Frame {
            let bytes = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": result])
            return try Frame(text: String(decoding: bytes, as: UTF8.self))
        }
        let response: StatusView = try frame(object).response(id: 1)
        XCTAssertEqual(response.daemon.version, "unrecognized")
        XCTAssertEqual(response.vault.unavailable, "unknown")
        XCTAssertFalse(response.description.contains(canary))
        var changed = object
        var daemon = object["daemon"] as! [String: Any]
        daemon["extra"] = canary
        changed["daemon"] = daemon
        XCTAssertThrowsError(try frame(changed).response(id: 1, as: StatusView.self))
    }

    func testGate31DaemonTextRequiresEscapingBeforeDisplay() {
        let raw = "name\u{202e}\u{200d}\u{1b}[31m"
        let text = DaemonText(raw)
        XCTAssertEqual(text.escaped, "name\\u{202e}\\u{200d}\\u{1b}[31m")
        XCTAssertFalse(String(describing: text).contains(raw))
        XCTAssertFalse(String(reflecting: text).contains(raw))
    }

    func testVaultUnavailableUsesOnlyItsDocumentedReasonSubset() throws {
        let allowed: Set<String> = ["damaged", "unsupported_version", "permissions", "disk_full", "storage", "io", "migration", "busy"]
        // The expected subset comes from IPC.md's carrier table, not the
        // implementation's general Reason list or sanitizing helper.
        for reason in Reason.allCases.map(\.rawValue) + [UUID().uuidString, "", "unknown", "damaged\u{202e}"] {
            let object: [String: Any] = ["state": "unavailable", "read_only": true, "unavailable": reason, "busy": false, "failed_unlocks": 0]
            let bytes = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": object])
            let view: VaultView = try Frame(text: String(decoding: bytes, as: UTF8.self)).response(id: 1)
            XCTAssertEqual(view.unavailable, allowed.contains(reason) ? reason : "unknown", reason)
        }
    }

    func testHomeIgnoresLaunchEnvironment() throws {
        // No path is opened. This compares only the uid database's answer.
        let original = try UserPaths.home()
        for key in ["HOME", "CFFIXED_USER_HOME"] {
            let old = getenv(key).map { String(cString: $0) }
            setenv(key, "/tmp/never-use-launch-home", 1)
            defer { if let old { setenv(key, old, 1) } else { unsetenv(key) } }
            XCTAssertEqual(try UserPaths.home(), original)
            XCTAssertEqual(try UserPaths.runtime(), original + "/Library/Application Support/EnvCloak/run")
        }
    }
}
