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

    func testFirstRunReportReaderDecodesAndValidatesPermissionsAndRejectsUnknownFields() throws {
        let dir = URL(fileURLWithPath: "/tmp/ec-j4-reports-" + UUID().uuidString.prefix(8))
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertNil(try FirstRunReportReader.read(inDirectory: dir.path))

        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        XCTAssertNil(try FirstRunReportReader.read(inDirectory: dir.path))

        // Verify cross-language schema parity against crates/envcloak-client/src/doctor_report.rs.
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let rustSource = try String(contentsOf: repoRoot.appendingPathComponent("crates/envcloak-client/src/doctor_report.rs"), encoding: .utf8)
        var rustFields: [String: [String]] = [:]
        var currentStruct: String?
        for line in rustSource.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("pub struct FirstRun") {
                let rest = trimmed.dropFirst("pub struct ".count)
                let name = String(rest.prefix { $0.isLetter || $0.isNumber || $0 == "_" })
                currentStruct = name
                rustFields[name] = []
                continue
            }
            if let name = currentStruct {
                if trimmed == "}" {
                    currentStruct = nil
                    continue
                }
                if trimmed.hasPrefix("pub "), let colon = trimmed.firstIndex(of: ":") {
                    let fieldName = trimmed[trimmed.index(trimmed.startIndex, offsetBy: 4)..<colon]
                        .trimmingCharacters(in: .whitespaces)
                    rustFields[name, default: []].append(fieldName)
                }
            }
        }
        XCTAssertEqual(rustFields["FirstRunReport"], [
            "version", "keys_found", "projects", "already_leaked", "plaintext_files",
            "providers", "accounts", "leaked", "plaintext_projects"
        ])
        XCTAssertEqual(rustFields["FirstRunProvider"], ["provider", "total_count", "live_count"])
        XCTAssertEqual(rustFields["FirstRunAccount"], ["account", "count"])
        XCTAssertEqual(rustFields["FirstRunLeakedPlace"], ["display_path", "count"])
        XCTAssertEqual(rustFields["FirstRunLeakedItem"], ["slug", "provider", "rotate_url", "sources", "places"])
        XCTAssertEqual(rustFields["FirstRunProjectPlaintext"], ["project_dir", "files"])

        let reportObject: [String: Any] = [
            "version": 1,
            "keys_found": 47,
            "projects": 23,
            "already_leaked": 12,
            "plaintext_files": 18,
            "providers": [
                ["provider": "stripe", "total_count": 4, "live_count": 2],
                ["provider": "custom\u{202e}", "total_count": 1, "live_count": 0]
            ],
            "accounts": [
                ["account": "you@acme.com", "count": 4]
            ],
            "leaked": [
                [
                    "slug": "stripe/acme-live\u{202e}",
                    "provider": "stripe",
                    "rotate_url": "https://dashboard.stripe.com/apikeys",
                    "sources": ["transcript"],
                    "places": [
                        ["display_path": "/tmp/claude.jsonl", "count": 19]
                    ]
                ]
            ],
            "plaintext_projects": [
                [
                    "project_dir": "/tmp/acme-web",
                    "files": [".env", ".env.local"]
                ]
            ]
        ]
        let file = dir.appendingPathComponent("first-run.json")
        let data = try JSONSerialization.data(withJSONObject: reportObject)
        try data.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertThrowsError(try FirstRunReportReader.read(inDirectory: dir.path), "0644 report file must be rejected")

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let hardlink = dir.appendingPathComponent("hardlink.json")
        try FileManager.default.linkItem(at: file, to: hardlink)
        XCTAssertThrowsError(try FirstRunReportReader.read(inDirectory: dir.path), "hard-linked report file must be rejected")
        try FileManager.default.removeItem(at: hardlink)

        let report = try XCTUnwrap(try FirstRunReportReader.read(inDirectory: dir.path))
        XCTAssertEqual(report.version, 1)
        XCTAssertEqual(report.keys_found, 47)
        XCTAssertEqual(report.projects, 23)
        XCTAssertEqual(report.already_leaked, 12)
        XCTAssertEqual(report.plaintext_files, 18)
        XCTAssertEqual(report.providers.first?.summaryLabel, "Stripe 4, 2 live")
        XCTAssertEqual(report.providers.last?.summaryLabel, "custom\\u{202e} 1")
        XCTAssertEqual(report.accounts.first?.summaryLabel, "you@acme.com (4)")
        XCTAssertEqual(report.leaked.first?.slug.escaped, "stripe/acme-live\\u{202e}")
        XCTAssertEqual(report.leaked.first?.whereSummary, "agent transcripts, 1 file")
        XCTAssertEqual(report.plaintext_projects.first?.summaryLabel, "/tmp/acme-web: .env, .env.local")

        var withPreview = reportObject
        withPreview["preview"] = "sk-ant-api03-canary"
        let badBytes = try JSONSerialization.data(withJSONObject: withPreview)
        XCTAssertThrowsError(try FirstRunReportReader.decode(json: String(decoding: badBytes, as: UTF8.self)),
                             "unknown or preview fields must be rejected")
    }
}
