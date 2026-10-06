import Foundation
import XCTest
@testable import EnvCloakKit

final class OracleTests: XCTestCase {
    func testGate31IndependentPythonOracleTenThousandStrings() throws {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_SWIFT_VECTORS"] else {
            throw XCTSkip("Run scripts/macos/test-kit.sh for Python and Rust fixtures")
        }
        let records = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: directory + "/escape.json"))) as! [[String: Any]]
        XCTAssertEqual(records.count, 10_000)
        for record in records {
            let input = String(String.UnicodeScalarView((record["scalars"] as! [UInt32]).map { Unicode.Scalar($0)! }))
            XCTAssertEqual(Escape.display(input), record["display"] as! String)
            let frame = try Frame(text: record["json"] as! String)
            let decoded = try frame.body.withUnsafeBytes { bytes in
                var parser = JSONParser(bytes: bytes)
                return try String(wire: WireReader(bytes: bytes, node: parser.parse()))
            }
            XCTAssertEqual(decoded, input)
            var writer = try WireWriter()
            try writer.string("prefix:" + input)
            let actual = try writer.buffer.withUnsafeBytes { bytes in
                try JSONSerialization.jsonObject(with: Data(bytes), options: [.fragmentsAllowed]) as! String
            }
            XCTAssertEqual(actual, "prefix:" + input)
        }
    }

    func testRustVectorsFramesBase64EscapesAndTokens() throws {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_SWIFT_VECTORS"] else {
            throw XCTSkip("Run scripts/macos/test-kit.sh for Python and Rust fixtures")
        }
        let vectors = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: directory + "/rust.json"))) as! [String: Any]
        for row in vectors["base64"] as! [[String: Any]] {
            let bytes = (row["bytes"] as! [Int]).map { UInt8($0) }
            let wire = (row["frame"] as! [Int]).map { UInt8($0) }
            var offset = 0
            let frame = try Frame.read { destination in
                let count = min(destination.count, min(7, wire.count - offset))
                for i in 0..<count { destination[i] = wire[offset + i] }
                offset += count
                return count
            }
            let value = try frame.secret()
            value.withUnsafeBytes { XCTAssertEqual(Array($0), bytes) }
            var output = try WireWriter()
            try output.secret(value)
            var encoded: [UInt8] = []
            try output.frame().write { encoded += $0; return $0.count }
            XCTAssertEqual(encoded, wire)
        }
        for row in vectors["escapes"] as! [[String: String]] {
            XCTAssertEqual(Escape.display(row["input"]!), row["display"]!)
        }
        XCTAssertEqual(Set(vectors["reasons"] as! [String]), Set(Reason.allCases.map(\.rawValue)))
        let errors = vectors["errors"] as! [[String: Any]]
        XCTAssertEqual(errors.count, ErrorKind.allCases.count)
        for error in errors {
            let kind = try XCTUnwrap(ErrorKind(rawValue: error["kind"] as! String))
            XCTAssertEqual(kind.code, (error["code"] as! NSNumber).int64Value)
        }
    }
}
