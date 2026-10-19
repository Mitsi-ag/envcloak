import CryptoKit
import EnvCloakKitTestSupport
import Foundation
import LocalAuthentication
import XCTest
@testable import EnvCloakKit

extension SoftwareUnlockKey: UnlockKeyAgreement {
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

extension SoftwareApprovalSigner: ApprovalSigner {
    public func sign(_ statementBytes: Data, reason: String) async throws -> P256RawSignature {
        let raw = try await signRaw(statementBytes, reason: reason)
        return try P256RawSignature(rawRepresentation: raw)
    }
}

final class StatementVectorTests: XCTestCase {
    private func repoRoot() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.path != "/" {
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Cargo.toml").path) {
                return url
            }
            url.deleteLastPathComponent()
        }
        fatalError("Could not locate repo root from \(#filePath)")
    }

    func testCanonicalStatementMatchesPythonOracleAcross1000Vectors() throws {
        let oracleScript = repoRoot().appendingPathComponent("crates/envcloak-policy/tests/oracles/statement.py")
        XCTAssertTrue(FileManager.default.fileExists(atPath: oracleScript.path))

        var swiftSignedHex: [String] = []
        var swiftV1Hex: [String] = []
        var cases: [[String: Any]] = []
        swiftSignedHex.reserveCapacity(1000)
        swiftV1Hex.reserveCapacity(1000)
        cases.reserveCapacity(1000)

        let specialStrings = [
            "",
            "simple",
            "control\n\r\t\0\u{1b}[31m\u{7f}\u{85}",
            "bidi\u{202e}override\u{200d}\u{feff}\u{2066}\u{2028}",
            "quote\"backslash\\tick'space ",
            "emoji🧪🔑🚀",
            "/Users/acme/my project/envcloak.toml"
        ]

        for i in 0..<1000 {
            let pick = { (offset: Int) -> String in
                specialStrings[(i + offset) % specialStrings.count]
            }
            let subjectKind: SubjectKind = switch i % 3 {
            case 0: .agent
            case 1: .terminal
            default: .unknown
            }
            let hasLabel = (i % 2 == 0)
            let label = hasLabel ? DaemonText(pick(1) + "-\(i)") : nil
            let hasExe = (i % 3 != 0)
            let exe = hasExe ? DaemonText("/usr/local/bin/tool-\(i)" + pick(2)) : nil
            let callerPid = Int32((i % 7 == 0 ? -1 : 1) * (100 + (i * 17) % 50000))
            let rootPid = Int32((i % 11 == 0 ? -1 : 1) * (50 + (i * 13) % 40000))
            let startTime = UInt64(1_700_000_000 + i * 60)

            let bindingCount = i % 4
            var bindings: [BindingSummary] = []
            var bindingsDicts: [[String: Any]] = []
            for b in 0..<bindingCount {
                let classification = ((i + b) % 3 == 0) ? "live" : (((i + b) % 3 == 1) ? "test" : "unknown")
                let firstUse = ((i + b) % 2 == 0)
                let granted = ((i + b) % 5 == 0)
                let envName = "VAR_\(b)_\(i % 7)"
                let slug = "stripe/acct-\(b)-" + pick(b)
                let item = "01HITEM\(b)\(i)"
                let field = "01HFIELD\(b)\(i)"
                let fieldName = (b % 2 == 0) ? "value" : "secret_key"
                bindings.append(
                    BindingSummary(
                        env_name: DaemonText(envName),
                        slug: DaemonText(slug),
                        item: DaemonText(item),
                        field: DaemonText(field),
                        field_name: DaemonText(fieldName),
                        classification: DaemonText(classification),
                        first_use: firstUse,
                        granted: granted
                    )
                )
                bindingsDicts.append([
                    "env_name": envName,
                    "slug": slug,
                    "item": item,
                    "field": field,
                    "field_name": fieldName,
                    "classification": classification,
                    "first_use": firstUse,
                    "granted": granted
                ])
            }

            let proposalCount = i % 5
            var proposals: [Proposal] = []
            var proposalsDicts: [[String: Any]] = []
            for pIdx in 0..<proposalCount {
                let envName = "PROP_\(pIdx)"
                let liveSlug = "stripe/live-\(pIdx)"
                let testSlug = "stripe/test-\(pIdx)"
                let testField: String? = switch (i + pIdx) % 3 {
                case 0: nil
                case 1: ""
                default: "api_key_" + pick(pIdx)
                }
                let source: BindingSource
                let sourceDict: [String: Any]
                switch (i + pIdx) % 4 {
                case 0:
                    source = .env
                    sourceDict = ["layer": "env"]
                case 1:
                    let prof = "prof-" + pick(pIdx + 1)
                    source = .profile(DaemonText(prof))
                    sourceDict = ["layer": "profile", "profile": prof]
                case 2:
                    let line = UInt32(1 + (i + pIdx) * 3)
                    source = .envFile(line)
                    sourceDict = ["layer": "env_file", "line": line]
                default:
                    source = .ref
                    sourceDict = ["layer": "ref"]
                }
                proposals.append(
                    Proposal(
                        env_name: DaemonText(envName),
                        live_slug: DaemonText(liveSlug),
                        test_slug: DaemonText(testSlug),
                        test_field: testField.map(DaemonText.init),
                        source: source
                    )
                )
                proposalsDicts.append([
                    "env_name": envName,
                    "live_slug": liveSlug,
                    "test_slug": testSlug,
                    "test_field": testField as Any? ?? NSNull(),
                    "source": sourceDict
                ])
            }

            let argvStrings: [String]
            if i == 0 {
                argvStrings = []
            } else if i == 1 {
                argvStrings = ["env", String(repeating: "x", count: 102_400)]
            } else {
                argvStrings = (0..<(1 + (i % 4))).map { idx in
                    "arg-\(idx)-" + pick(idx)
                }
            }

            let mode: Mode = (i % 2 == 0) ? .inject : .proxy
            let uses: Uses = (i % 2 == 0) ? .once : .session
            let ttlSecs = UInt64(60 * (1 + (i % 60)))
            let liveList: [String] = (i % 3 == 0 && !bindings.isEmpty) ? [bindings[0].env_name.raw] : []

            let descriptor = PendingDescriptor(
                request: DaemonText(String(format: "REQ%05d", i)),
                nonce: DaemonText(String(repeating: String(format: "%02x", i % 256), count: 32)),
                created_secs: UInt64(1_750_000_000 + i),
                expires_in_secs: 60,
                subject: SubjectSummary(
                    kind: subjectKind,
                    label: label,
                    caller_pid: callerPid,
                    root: ProcessSummary(pid: rootPid, start_time: startTime, exe: exe)
                ),
                project: ProjectSummary(
                    dir: DaemonText("/tmp/proj-\(i)-" + pick(5)),
                    manifest: DaemonText("/tmp/proj-\(i)/envcloak.toml"),
                    manifest_sha256: DaemonText(String(repeating: "f", count: 64)),
                    new_project: (i % 2 == 1)
                ),
                bindings: bindings,
                proposals: proposals,
                mode: mode,
                argv: argvStrings.map(DaemonText.init),
                managed: nil,
                standing: nil
            )
            let options = ApprovalOptions(
                uses: uses,
                ttl_secs: ttlSecs,
                live: liveList,
                standing: nil
            )

            swiftSignedHex.append(HexCoding.encode(CanonicalStatement.encode(descriptor, options: options)))
            swiftV1Hex.append(HexCoding.encode(CanonicalStatement.encodeV1(descriptor, options: options)))

            let rootDict: [String: Any] = [
                "pid": rootPid,
                "start_time": startTime,
                "exe": exe?.raw as Any? ?? NSNull()
            ]
            let subjectDict: [String: Any] = [
                "kind": subjectKind.rawValue,
                "label": label?.raw as Any? ?? NSNull(),
                "caller_pid": callerPid,
                "root": rootDict
            ]

            let pObj: [String: Any] = [
                "request": String(format: "REQ%05d", i),
                "nonce": String(repeating: String(format: "%02x", i % 256), count: 32),
                "created_secs": UInt64(1_750_000_000 + i),
                "expires_in_secs": 60,
                "subject": subjectDict,
                "project": [
                    "dir": "/tmp/proj-\(i)-" + pick(5),
                    "manifest": "/tmp/proj-\(i)/envcloak.toml",
                    "manifest_sha256": String(repeating: "f", count: 64),
                    "new_project": (i % 2 == 1)
                ],
                "bindings": bindingsDicts,
                "proposals": proposalsDicts,
                "mode": mode.rawValue,
                "argv": argvStrings
            ]
            let oObj: [String: Any] = [
                "uses": uses.rawValue,
                "ttl_secs": ttlSecs,
                "live": liveList
            ]
            cases.append(["descriptor": pObj, "options": oObj])
        }

        let inputData = try JSONSerialization.data(withJSONObject: cases)
        let inputFile = FileManager.default.temporaryDirectory.appendingPathComponent("ec-stmt-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: inputFile) }
        try inputData.write(to: inputFile)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [oracleScript.path]
        proc.standardInput = try FileHandle(forReadingFrom: inputFile)
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        try proc.run()
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0)

        let oracleResults = try JSONSerialization.jsonObject(with: outData) as! [[String: String]]
        XCTAssertEqual(oracleResults.count, 1000)
        for i in 0..<1000 {
            XCTAssertEqual(swiftSignedHex[i], oracleResults[i]["signed"], "v2 mismatch at vector \(i)")
            XCTAssertEqual(swiftV1Hex[i], oracleResults[i]["v1"], "v1 mismatch at vector \(i)")
            XCTAssertNotEqual(swiftSignedHex[i], swiftV1Hex[i], "v2 must differ from v1 at vector \(i)")
        }
    }

    func testStatementV2DiffersFromV1AndCommitsToLiveFlagsAndProposals() {
        let baseBinding = BindingSummary(
            env_name: DaemonText("STRIPE_SECRET_KEY"),
            slug: DaemonText("stripe/acme-live"),
            item: DaemonText("01HITEM1"),
            field: DaemonText("01HFIELD1"),
            field_name: DaemonText("value"),
            classification: DaemonText("live"),
            first_use: true,
            granted: false
        )
        let proposal = Proposal(
            env_name: DaemonText("STRIPE_SECRET_KEY"),
            live_slug: DaemonText("stripe/acme-live"),
            test_slug: DaemonText("stripe/acme-test"),
            test_field: nil,
            source: .env
        )
        let descriptor = PendingDescriptor(
            request: DaemonText("ABCD2345"),
            nonce: DaemonText(String(repeating: "ab", count: 32)),
            created_secs: 1_750_000_000,
            expires_in_secs: 60,
            subject: SubjectSummary(
                kind: .agent,
                label: DaemonText("Claude Code"),
                caller_pid: 4312,
                root: ProcessSummary(pid: 4300, start_time: 1_749_999_000, exe: DaemonText("/usr/local/bin/claude"))
            ),
            project: ProjectSummary(
                dir: DaemonText("/Users/acme/shop"),
                manifest: DaemonText("/Users/acme/shop/envcloak.toml"),
                manifest_sha256: DaemonText(String(repeating: "cd", count: 32)),
                new_project: false
            ),
            bindings: [baseBinding],
            proposals: [proposal],
            mode: .inject,
            argv: [DaemonText("npm"), DaemonText("test")],
            managed: nil,
            standing: StandingSummary(
                exe: DaemonText("/usr/local/bin/claude"),
                linux_sha256: nil,
                recognized_release: nil,
                appends_to: nil
            )
        )
        let untickedOpts = ApprovalOptions(uses: .once, ttl_secs: 900, live: [], standing: nil)
        let tickedOpts = ApprovalOptions(uses: .once, ttl_secs: 900, live: ["STRIPE_SECRET_KEY"], standing: nil)
        let standingOpts = ApprovalOptions(uses: .session, ttl_secs: 28_800, live: ["STRIPE_SECRET_KEY"], standing: 604_800)

        let v2Unticked = CanonicalStatement.digestHex(descriptor, options: untickedOpts)
        let v1Unticked = CanonicalStatement.digestV1Hex(descriptor, options: untickedOpts)
        let v2Ticked = CanonicalStatement.digestHex(descriptor, options: tickedOpts)
        let v2Standing = CanonicalStatement.digestHex(descriptor, options: standingOpts)

        XCTAssertNotEqual(v2Unticked, v1Unticked, "v2 digest must never equal v1 digest")
        XCTAssertNotEqual(v2Unticked, v2Ticked, "ticking a live key must change the statement digest")
        XCTAssertNotEqual(v2Ticked, v2Standing, "enabling standing approval must change the statement digest")

        XCTAssertEqual(CanonicalStatement.untickedLive(descriptor, options: untickedOpts), ["STRIPE_SECRET_KEY"])
        XCTAssertTrue(CanonicalStatement.untickedLive(descriptor, options: tickedOpts).isEmpty)
    }

    func testProposalAdviceAndRefArgumentsAndArgvTruncation() {
        let manifest = DaemonText("/Users/acme/my shop/envcloak.toml")
        let envProp = Proposal(
            env_name: DaemonText("STRIPE_KEY"),
            live_slug: DaemonText("stripe/acme-live"),
            test_slug: DaemonText("stripe/acme-test"),
            test_field: nil,
            source: .env
        )
        XCTAssertTrue(envProp.canApplyAutomatically)
        XCTAssertEqual(
            envProp.refCommandArguments(manifest: manifest),
            ["ref", "--manifest", "/Users/acme/my shop/envcloak.toml", "STRIPE_KEY=stripe/acme-test"]
        )
        XCTAssertEqual(
            envProp.advice(manifest: manifest),
            "run `envcloak ref --manifest '/Users/acme/my shop/envcloak.toml' STRIPE_KEY=stripe/acme-test`"
        )

        let refProp = Proposal(
            env_name: DaemonText("STRIPE_KEY"),
            live_slug: DaemonText("stripe/acme-live"),
            test_slug: DaemonText("stripe/acme-test"),
            test_field: DaemonText("secret"),
            source: .ref
        )
        XCTAssertFalse(refProp.canApplyAutomatically)
        XCTAssertNil(refProp.refCommandArguments(manifest: manifest))
        XCTAssertEqual(
            refProp.advice(manifest: manifest),
            "give `--ref STRIPE_KEY=stripe/acme-test#secret` in place of the --ref for STRIPE_KEY"
        )

        let longArgv = [
            DaemonText("node"),
            DaemonText(String(repeating: "abcd", count: 800))
        ]
        let rendered = CanonicalStatement.renderArgv(longArgv)
        XCTAssertTrue(rendered.isTruncated)
        XCTAssertGreaterThan(rendered.hiddenByteCount, 1000)
        XCTAssertEqual(rendered.allLines.count, 2)
    }

    func testStandingViewScopeLabelMatchesSpecWordForWord() throws {
        let json = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "id": "01JSTANDING000000000000000",
                "agent_id": "claude-code",
                "agent_name": "Claude Code",
                "identity": "team:ABCD123456:com.anthropic.claude-code",
                "project_dir": "/Users/acme/shop",
                "bindings": ["STRIPE_KEY=stripe/acme-test"],
                "created_secs": 1750000000,
                "remaining_secs": 604800,
                "not_after_secs": 1750604800
            }
        }
        """
        let view: StandingView = try Frame(text: json).response(id: 1)
        XCTAssertEqual(
            view.scopeLabel,
            "any Claude Code session in this project, including one started by another program, gets these keys without asking"
        )
    }

    func testContextFactoryZeroReuseAndDistinctInstances() {
        let factory = ContextFactory()
        let first = factory.make(reason: ContextFactory.unlockReason)
        let second = factory.make(reason: ContextFactory.approvalReason(command: "npm test", project: "acme-shop", keyCount: 2))
        defer {
            first.invalidate()
            second.invalidate()
        }
        XCTAssertFalse(first === second, "Every prompt must construct a fresh LAContext instance")
        XCTAssertEqual(first.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertEqual(second.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertEqual(first.localizedReason, "unlock your vault")
        XCTAssertEqual(second.localizedReason, "approve npm test in acme-shop with 2 keys")
    }

    func testHPKEOpenAndResealRoundTripAndWireFrameCanarySweep() async throws {
        let softwareKey = SoftwareUnlockKey()
        let vmkCanary = Data((0..<32).map { UInt8(0xA0 + $0) })
        let vaultIDHex = "00112233445566778899aabbccddeeff"
        let unlockerIDHex = "ffeeddccbbaa99887766554433221100"
        let epoch: UInt32 = 7
        let requestID = "REQ12345"
        let challengeHex = String(repeating: "42", count: 32)
        let daemonKey = Curve25519.KeyAgreement.PrivateKey()
        let daemonPubHex = HexCoding.encode(daemonKey.publicKey.rawRepresentation)

        let envelope = try SoftwareUnlockKey.sealEnvelope(
            vmk: vmkCanary,
            recipientPublicKey: softwareKey.privateKey.publicKey,
            vaultIDHex: vaultIDHex,
            unlockerIDHex: unlockerIDHex,
            epoch: epoch
        )
        let beginView = AppUnlockBeginView(
            request_id: DaemonText(requestID),
            unlocker_id: DaemonText(unlockerIDHex),
            vault_id: DaemonText(vaultIDHex),
            epoch: epoch,
            challenge: DaemonText(challengeHex),
            envelope: envelope,
            daemon_eph_pub: DaemonText(daemonPubHex)
        )

        let sealedHex = try await softwareKey.openAndReseal(beginView, reason: ContextFactory.unlockReason)
        XCTAssertEqual(softwareKey.openCount, 1)
        XCTAssertEqual(softwareKey.lastReason, ContextFactory.unlockReason)
        XCTAssertEqual(sealedHex.count, SEHPKE.resealByteCount * 2)

        let rpcFrame = try AppUnlock(request_id: requestID, sealed: sealedHex).request(id: 99)
        let frameData = rpcFrame.body.withUnsafeBytes { Data($0) }
        let canaryHex = HexCoding.encode(vmkCanary)
        let canaryBase64 = vmkCanary.base64EncodedString()

        func containsCanary(_ data: Data) -> Bool {
            if data.range(of: vmkCanary) != nil { return true }
            if let text = String(data: data, encoding: .utf8) {
                if text.localizedCaseInsensitiveContains(canaryHex) || text.contains(canaryBase64) {
                    return true
                }
            }
            return false
        }

        // Positive control: confirm the detector fires when the canary is present.
        var spiked = frameData
        spiked.append(Data(canaryHex.utf8))
        XCTAssertTrue(containsCanary(spiked), "Positive control must detect VMK canary")

        // Actual check: the wire frame must never contain the raw, hex, or base64 VMK.
        XCTAssertFalse(containsCanary(frameData), "Plaintext VMK must never appear in AppUnlock wire frame")

        // Verify the daemon can open the resealed VMK and recover the exact 32-byte canary.
        let openedVMK = try SoftwareUnlockKey.openResealed(
            sealedHex: sealedHex,
            daemonPrivateKey: daemonKey,
            requestID: requestID,
            challengeHex: challengeHex
        )
        XCTAssertEqual(openedVMK, vmkCanary)

        // Tampered challenge or epoch must fail.
        XCTAssertThrowsError(
            try SoftwareUnlockKey.openResealed(
                sealedHex: sealedHex,
                daemonPrivateKey: daemonKey,
                requestID: requestID,
                challengeHex: String(repeating: "43", count: 32)
            )
        )
        let wrongEpochBegin = AppUnlockBeginView(
            request_id: DaemonText(requestID),
            unlocker_id: DaemonText(unlockerIDHex),
            vault_id: DaemonText(vaultIDHex),
            epoch: epoch + 1,
            challenge: DaemonText(challengeHex),
            envelope: envelope,
            daemon_eph_pub: DaemonText(daemonPubHex)
        )
        do {
            _ = try await softwareKey.openAndReseal(wrongEpochBegin, reason: ContextFactory.unlockReason)
            XCTFail("Expected wrong epoch to fail HPKE open")
        } catch let error as SEUnlockError {
            XCTAssertEqual(error, .openFailed)
        }
    }
}
