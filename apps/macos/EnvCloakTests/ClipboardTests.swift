import AppKit
import XCTest
@testable import EnvCloak
@testable import EnvCloakKit

@MainActor final class ClipboardTests: XCTestCase {
    private var controls: [String] {
        (Array(0...31) + Array(127...159) + [0x061c, 0x200e, 0x200f] + Array(0x202a...0x202e) + Array(0x2066...0x2069))
            .compactMap(Unicode.Scalar.init).map(String.init)
    }

    func testTerminalCommandBuildersRefuseControls() {
        for control in controls {
            let path = DaemonText("/tmp/folder" + control + "[201~fixture")
            XCTAssertTrue(MetadataRequest.changeDirectoryCommand(path) == nil)
            XCTAssertTrue(MetadataRequest.replaceTarget(slug: path, field: DaemonText("value")) == nil)
            XCTAssertTrue(MetadataRequest.replaceTarget(slug: DaemonText("fixture"), field: path) == nil)
            XCTAssertTrue(MetadataRequest.terminalCommand(["rm", "/tmp/folder" + control]) == nil)
        }
    }

    func testTerminalControlsNeverReachClipboardOrLaunch() {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        board.setString("Fixture clipboard", forType: .string)
        let count = board.changeCount
        var launches = 0
        for control in controls {
            let raw = "/tmp/folder" + control + "[201~fixture"
            let path = DaemonText(raw)
            XCTAssertFalse(WorkspaceActions.copy(raw, to: board))
            XCTAssertFalse(WorkspaceActions.copyPath(path, to: board))
            XCTAssertFalse(WorkspaceActions.openFolderInTerminal(path, to: board, open: { launches += 1 }))
            XCTAssertNil(MetadataRequest.clipboardPath(path))
        }
        XCTAssertEqual(launches, 0)
        XCTAssertEqual(board.changeCount, count)
        XCTAssertEqual(board.string(forType: .string), "Fixture clipboard")
    }

    func testQuotedPathsCopyAndRunAsOneShellArgument() throws {
        let root = URL(fileURLWithPath: "/tmp/ec05-clipboard-" + UUID().uuidString.prefix(8))
        let folder = root.appendingPathComponent("space ' quote\\猫")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let path = DaemonText(folder.path)
        XCTAssertTrue(WorkspaceActions.copyPath(path, to: board))
        XCTAssertEqual(board.string(forType: .string), folder.path)
        var launches = 0
        XCTAssertTrue(WorkspaceActions.openFolderInTerminal(path, to: board, open: { launches += 1 }))
        XCTAssertEqual(launches, 1)
        let command = try XCTUnwrap(board.string(forType: .string))
        let shell = Process(); shell.executableURL = URL(fileURLWithPath: "/bin/sh")
        shell.arguments = ["-c", command + " && pwd -P"]
        shell.environment = ["HOME": root.path, "TMPDIR": root.path, "XDG_CONFIG_HOME": root.path,
                             "XDG_DATA_HOME": root.path, "XDG_STATE_HOME": root.path, "XDG_RUNTIME_DIR": root.path,
                             "XDG_CACHE_HOME": root.path, "PATH": "/usr/bin:/bin"]
        shell.currentDirectoryURL = root
        shell.standardInput = FileHandle.nullDevice
        let output = Pipe(); shell.standardOutput = output; shell.standardError = FileHandle.nullDevice
        try shell.run(); shell.waitUntilExit()
        XCTAssertEqual(shell.terminationStatus, 0)
        guard shell.terminationStatus == 0 else { return }
        let reachedPath = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).trimmingCharacters(in: .newlines)
        let reached = try FileManager.default.attributesOfItem(atPath: reachedPath)
        let expected = try FileManager.default.attributesOfItem(atPath: folder.path)
        // Compare filesystem identity, independent of Foundation's /tmp alias spelling.
        for key in [FileAttributeKey.systemNumber, .systemFileNumber] {
            XCTAssertNotNil(expected[key] as? NSNumber)
            XCTAssertEqual(reached[key] as? NSNumber, expected[key] as? NSNumber)
        }
    }

    func testInspectorCommandsRefuseHostileSlugAndField() async throws {
        let client = ScriptedClient(); let session = VaultSession(client: client); await session.poll()
        let hostileItem = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(InspectorAction.replace.command(item: hostileItem, field: DaemonText("secondary")))
        XCTAssertNil(InspectorAction.remove.command(item: hostileItem, field: nil))
        await client.plainSlugs(); await client.fieldSuffix("\u{1b}[201~"); await client.configure(head: 2)
        await session.poll()
        let item = try XCTUnwrap(session.items.rows.first)
        XCTAssertNil(InspectorAction.replace.command(item: item, field: item.fields.first?.name))
        XCTAssertNotNil(InspectorAction.remove.command(item: item, field: nil))
    }
}
