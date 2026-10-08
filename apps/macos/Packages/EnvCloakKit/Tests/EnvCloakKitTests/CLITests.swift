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
        test -c /dev/fd/0 && test /dev/fd/0 -ef /dev/null || exit 14
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

    func testCLICompletionAfterDeadlineNeverReportsSuccess() async throws {
        for expired in [false, true] {
            let clock = TestClock()
            let fixture = try fixture("printf '{}'")
            defer { try? FileManager.default.removeItem(atPath: fixture.root) }
            await CLIProbe.$hooks.withValue(CLITestHooks(now: { clock.now }, beforeResult: {
                if expired { clock.advance(.seconds(3)) }
            })) {
                do {
                    let result = try await fixture.runner.run(arguments: ["ref"], workingDirectory: fixture.root)
                    XCTAssertFalse(expired)
                    XCTAssertEqual(result.json, "{}")
                } catch { XCTAssertTrue(expired); XCTAssertEqual(error as? CLIError, .timedOut) }
            }
        }
    }

    func testInstallUsesExitStatusAndExactArguments() async throws {
        for output in ["installed", ""] {
            let fixture = try fixture("""
            test "$#" -eq 4 && test "$1" = daemon && test "$2" = install || exit 7
            test "$3" = --daemon && test "$4" = '/tmp/fixture daemon' || exit 8
            test "$PATH" = /usr/bin:/bin && test -d "$HOME" || exit 9
            printf '\(output)'
            """)
            try await fixture.runner.installDaemon(at: "/tmp/fixture daemon")
        }
    }

    func testInstallFailureBoundsAndCancellationNeverSucceed() async throws {
        for (script, expected, timeout) in [
            ("printf 'installed'; exit 2", CLIError.failed(512), Duration.seconds(3)),
            ("while :; do :; done", .timedOut, .milliseconds(200)),
            ("/bin/sleep 30 & exit 0", .timedOut, .milliseconds(300)),
            ("/usr/bin/awk 'BEGIN { for (i=0; i<200000; i++) printf \"abcdefghij\" }'", .outputLimit, .seconds(3))
        ] {
            let fixture = try fixture(script, timeout: timeout)
            do { try await fixture.runner.installDaemon(at: "/tmp/daemon"); XCTFail("failed install succeeded") }
            catch { XCTAssertEqual(error as? CLIError, expected) }
        }
        let fixture = try fixture("while :; do :; done")
        let install = Task { try await fixture.runner.installDaemon(at: "/tmp/daemon") }
        install.cancel()
        do { try await install.value; XCTFail("cancelled install succeeded") }
        catch { XCTAssertEqual(error as? CLIError, .timedOut) }
        for path in ["relative", "/tmp/bad\0path"] {
            do { try await fixture.runner.installDaemon(at: path); XCTFail("invalid install path accepted") }
            catch { XCTAssertEqual(error as? CLIError, .invalidArguments) }
        }
    }

    func testInstallCompletionAfterDeadlineNeverSucceeds() async throws {
        let clock = TestClock(); let fixture = try fixture("exit 0")
        await CLIProbe.$hooks.withValue(CLITestHooks(now: { clock.now }, beforeResult: { clock.advance(.seconds(3)) })) {
            do { try await fixture.runner.installDaemon(at: "/tmp/daemon"); XCTFail("late install succeeded") }
            catch { XCTAssertEqual(error as? CLIError, .timedOut) }
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

extension CLITests {
    func testPrivateUndoChannelNeverUsesArgvOrJSONAndStreamsBeyondPipeCapacity() async throws {
        let fixture = try fixture("""
        test "$1" = ref && test "$2" = VARIABLE=fixture && test "$3" = --json || exit 7
        test "$4" = --undo-fd && test "$5" = 3 && test "$#" = 5 || exit 8
        test -c /dev/fd/0 && test /dev/fd/0 -ef /dev/null || exit 9
        /usr/bin/awk 'BEGIN { for (i=0; i<120000; i++) printf "x" }' >&3
        printf '{"saved":true}'
        """)
        let (result, receipt) = try await fixture.runner.recordBinding(arguments: ["ref", "VARIABLE=fixture", "--json"], workingDirectory: fixture.root)
        XCTAssertEqual(result.json, "{\"saved\":true}")
        XCTAssertTrue(receipt.available)
        let script = """
        #!/bin/sh
        test "$1" = ref && test "$2" = --restore-fd && test "$3" = 3 && test "$4" = --json && test "$#" = 4 || exit 7
        test -c /dev/fd/0 && test /dev/fd/0 -ef /dev/null || exit 9
        bytes=$(/usr/bin/wc -c <&3)
        test "$bytes" -eq 120000 || exit 10
        printf '{"restored":true}'
        """
        try script.write(toFile: fixture.root + "/envcloak", atomically: false, encoding: .utf8)
        try await fixture.runner.undoBinding(receipt, workingDirectory: fixture.root)
        XCTAssertFalse(receipt.available)
        do { try await fixture.runner.undoBinding(receipt, workingDirectory: fixture.root); XCTFail("consumed receipt reused") }
        catch { XCTAssertEqual(error as? CLIError, .invalidArguments) }
    }
}
