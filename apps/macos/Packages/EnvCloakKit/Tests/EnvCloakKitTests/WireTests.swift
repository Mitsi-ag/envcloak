import Foundation
import XCTest
@testable import EnvCloakKit

final class WireTests: XCTestCase {
    func testGate11WipesFullAllocationAndGrowth() throws {
        var observed = 0
        var nonzero = 0
        do {
            var buffer = try SecretBuffer(capacity: 8, wipeObserver: { bytes in
                observed += 1
                nonzero += bytes.filter { $0 != 0 }.count
            })
            try buffer.append(contentsOf: Array(UUID().uuidString.utf8))
            try buffer.reserveCapacity(40_000)
            XCTAssertEqual(buffer.description, "[secret]")
        }
        XCTAssertGreaterThanOrEqual(observed, 2)
        XCTAssertEqual(nonzero, 0)
    }

    func testFrameBoundsRefuseBeforeReadingBody() throws {
        for count in [0, 1_048_577, UInt32.max] {
            var reads = 0
            XCTAssertThrowsError(try Frame.read { destination in
                reads += 1
                if reads == 1 {
                    for i in 0..<4 { destination[i] = UInt8(truncatingIfNeeded: count >> (24 - i * 8)) }
                    return 4
                }
                XCTFail("read body of refused frame")
                return 0
            }.count)
            XCTAssertEqual(reads, 1)
        }
        let text = String(repeating: " ", count: 1_048_576)
        let frame = try Frame(text: text)
        XCTAssertEqual(frame.count, 1_048_576)
    }

    func testStrictEnvelopeAndErrorMessageNeverEscapes() throws {
        let canary = UUID().uuidString
        let error = "{\"jsonrpc\":\"2.0\",\"id\":18446744073709551615,\"error\":{\"code\":-32002,\"message\":\"\(canary)\",\"data\":{\"kind\":\"vault_locked\",\"reason\":\"\(canary)\"}}}"
        let frame = try Frame(text: error)
        do {
            let _: LockedView = try frame.response(id: UInt64.max)
            XCTFail("error reported success")
        } catch {
            XCTAssertEqual(error as? EnvCloakError, .rpc(.vaultLocked, nil))
            XCTAssertFalse(String(describing: error).contains(canary))
            XCTAssertFalse(String(reflecting: error).contains(canary))
        }
        let good = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"was_unlocked\":true}}"
        XCTAssertTrue(try Frame(text: good).response(id: 1, as: LockedView.self).was_unlocked)
        let bad = [
            good.replacingOccurrences(of: "\"result\":", with: "\"unknown\":0,\"result\":"),
            good.replacingOccurrences(of: "true", with: "true,\"extra\":0"),
            good.replacingOccurrences(of: "\"id\":1", with: "\"id\":1,\"id\":1"),
            good.replacingOccurrences(of: "\"id\":1", with: "\"id\":1.0"),
            good.replacingOccurrences(of: "\"id\":1", with: "\"id\":18446744073709551616"),
            good.replacingOccurrences(of: "2.0", with: "1.0"),
            good + "true", "[]", "{", "{\"x\":\"\\ud800\"}",
            good.replacingOccurrences(of: "\"id\":1", with: "\"id\":2")
        ]
        for input in bad {
            XCTAssertThrowsError(try Frame(text: input).response(id: 1, as: LockedView.self))
        }
    }

    func testBase64IsCanonicalAndDecodedInPlace() throws {
        for length in 0...128 {
            let bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max) }
            let encoded = Data(bytes).base64EncodedString()
            let frame = try Frame(text: "\"\(encoded)\"")
            let secret = try frame.secret()
            secret.withUnsafeBytes { XCTAssertEqual(Array($0), bytes) }
        }
        for bad in ["A", "AA", "AAA", "AB==", "AAF=", "AA===", "AA==\n", "__==", "\\u0051Q==", "QQ\\/="] {
            XCTAssertThrowsError(try Frame(text: "\"\(bad)\"").validateSecret())
        }
    }

    func testGate31EscapeControls() {
        XCTAssertEqual(Escape.display("a\u{202e}\u{200d}\u{7f}\u{85}\\\n\r\t"),
                       "a\\u{202e}\\u{200d}\\u{7f}\\u{85}\\\\\\n\\r\\t")
    }
    func testGate11FrameGrowthAndFailureBuffersAreWiped() throws {
        let recorder = WipeRecorder()
        try BufferProbe.$observer.withValue(BufferObserver { recorder.observe($0) }) {
            let bytes = Array((UUID().uuidString + "a").utf8)
            let value = Data(bytes).base64EncodedString()
            let large = "\"" + String(repeating: value, count: 2000) + "\""
            let frame = try Frame(text: large)
            var wire: [UInt8] = []
            try frame.write { wire += $0; return $0.count }
            var offset = 0
            do {
                let received = try Frame.read { destination in
                    let n = min(destination.count, wire.count - offset)
                    for i in 0..<n { destination[i] = wire[offset + i] }
                    offset += n
                    return n
                }
                // Padding in the middle is invalid. The partial decoded
                // value is destroyed as part of this refusal.
                XCTAssertThrowsError(try received.validateSecret())
            }
            let poisoned = try Frame(text: "\"" + value + "!\"")
            XCTAssertThrowsError(try poisoned.validateSecret())
        }
        XCTAssertGreaterThan(recorder.regions, 4)
        XCTAssertEqual(recorder.dirty, 0)
    }

    /// Bounded fuzz entrypoint, runnable on its own with --filter. Includes
    /// every byte, malformed UTF-8, escapes, nesting, and truncated frames.
    func testFuzzHostileWireParser() throws {
        var state: UInt64 = 303
        for count in 0..<10_000 {
            var bytes: [UInt8] = []
            for _ in 0..<(count % 256) {
                state = state &* 6364136223846793005 &+ 1
                bytes.append(UInt8(truncatingIfNeeded: state >> 32))
            }
            do {
                _ = try bytes.withUnsafeBytes { bytes in
                    var parser = JSONParser(bytes: bytes)
                    return try parser.parse()
                }
            } catch { XCTAssertEqual(error as? EnvCloakError, .protocolError) }
        }
        for bad in [[UInt8]([34, 0xC0, 0x80, 34]), [34, 0xED, 0xA0, 0x80, 34], [34, 0xF4, 0x90, 0x80, 0x80, 34]] {
            XCTAssertThrowsError(try bad.withUnsafeBytes { bytes in
                var parser = JSONParser(bytes: bytes)
                return try parser.parse()
            })
        }
        let complete = Array("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"was_unlocked\":true}}".utf8)
        let wire = [UInt8(0), 0, 0, UInt8(complete.count)] + complete
        for cutoff in 0..<wire.count {
            var offset = 0
            XCTAssertThrowsError(try Frame.read { destination in
                let n = min(destination.count, cutoff - offset)
                for i in 0..<n { destination[i] = wire[offset + i] }
                offset += n
                return n
            }.count)
        }
        XCTAssertThrowsError(try Frame(text: String(repeating: "[", count: 65) + "0" + String(repeating: "]", count: 65)).validateSecret())
    }

}

private final class WipeRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var observed = 0
    private var nonzero = 0
    var regions: Int { lock.withLock { observed } }
    var dirty: Int { lock.withLock { nonzero } }
    func observe(_ bytes: UnsafeRawBufferPointer) {
        lock.withLock {
            observed += 1
            nonzero += bytes.filter { $0 != 0 }.count
        }
    }
}
