import Foundation
import XCTest
@testable import EnvCloakKit

final class CLITests: XCTestCase, @unchecked Sendable {
    func testClearedEnvironmentNullInputWorkingDirectoryAndJSON() async throws {
        let fixture = try fixture("""
        test "$#" -eq 2 && test "$1" = ref && test "$2" = --json || exit 7
        test -z "${ENVCLOAK_POISON+x}" || exit 8
        test "$PATH" = /usr/bin:/bin || exit 9
        test "$LANG" = en_US.UTF-8 || exit 10
        test -d "$HOME" || exit 11
        test "$PWD" -ef "$HOME" || exit 12
        if read -r ignored; then exit 13; fi
        printf '{"ok":true}'
        """)
        defer { try? FileManager.default.removeItem(atPath: fixture.root) }
        let result = try await fixture.runner.run(arguments: ["ref"], workingDirectory: fixture.root)
        XCTAssertEqual(result.json, "{\"ok\":true}")
    }

    func testFailuresTimeoutAndOversizedOutputNeverReportSuccess() async throws {
        let cases: [(String, CLIError, Duration)] = [
            ("printf '{}'; exit 2", .failed(512), .seconds(3)),
            ("printf 'not json'", .invalidOutput, .seconds(3)),
            ("while :; do :; done", .timedOut, .milliseconds(200)),
            ("/bin/sleep 30 & exit 0", .timedOut, .milliseconds(300)),
            ("/usr/bin/awk 'BEGIN { for (i=0; i<200000; i++) printf \"abcdefghij\" }'", .outputLimit, .seconds(3))
        ]
        for (script, expected, timeout) in cases {
            let fixture = try fixture(script, timeout: timeout)
            defer { try? FileManager.default.removeItem(atPath: fixture.root) }
            let start = ContinuousClock.now
            do { _ = try await fixture.runner.run(arguments: ["ref"], workingDirectory: fixture.root); XCTFail("failed CLI succeeded") }
            catch { XCTAssertEqual(error as? CLIError, expected) }
            XCTAssertLessThan(start.duration(to: .now), .seconds(5))
        }
    }

    private func fixture(_ script: String, timeout: Duration = .seconds(2)) throws -> (root: String, runner: CLIRunner) {
        let root = (ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp") + "/c" + String(UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let executable = root + "/envcloak"
        try ("#!/bin/sh\n" + script + "\n").write(toFile: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable)
        return (root, CLIRunner(executable: executable, home: root, timeout: timeout))
    }
}
