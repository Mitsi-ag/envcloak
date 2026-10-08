import XCTest

extension PasteTests {
    func sweep(repo: String, home: String, pid: pid_t, canary: String) throws {
        let task = Process(); task.executableURL = URL(fileURLWithPath: repo + "/scripts/macos/sweep.sh")
        task.arguments = ["--home", home, "--pid", String(pid)]
        task.environment = ["HOME": home, "PATH": "/usr/bin:/bin:/opt/homebrew/bin"]
        let input = Pipe(); task.standardInput = input
        let output = Pipe(); task.standardOutput = output; task.standardError = FileHandle.nullDevice
        try task.run()
        try input.fileHandleForWriting.write(contentsOf: Data(canary.utf8))
        try input.fileHandleForWriting.close()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(task.terminationStatus, 0, "gate 12 sweep failed: \(report)")
        XCTAssertEqual(report["complete"] as? Bool, true)
        XCTAssertEqual(report["file_hits"] as? Int, 0)
        XCTAssertEqual(report["log_hits"] as? Int, 0)
        XCTAssertGreaterThan(report["positive_controls"] as? Int ?? 0, 0)
    }
}
