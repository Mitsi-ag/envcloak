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
    func testEveryTypedSuccessResponseFromRust() throws {
        guard let directory = ProcessInfo.processInfo.environment["ENVCLOAK_SWIFT_VECTORS"] else {
            throw XCTSkip("Run scripts/macos/test-kit.sh for Rust fixtures")
        }
        let vectors = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: directory + "/rust.json"))) as! [String: Any]
        let responses = vectors["responses"] as! [String: [Int]]
        func decode<M: DaemonMethod & ~Copyable>(_ type: M.Type) throws -> M.Output {
            let bytes = try XCTUnwrap(responses[M.name]).map { UInt8($0) }
            var offset = 0
            let frame = try Frame.read { destination in
                let n = min(destination.count, bytes.count - offset)
                for i in 0..<n { destination[i] = bytes[offset + i] }
                offset += n
                return n
            }
            return try M.response(frame, id: UInt64.max)
        }
        XCTAssertEqual(try decode(Status.self).audit.head_seq, 8)
        XCTAssertTrue(try decode(Lock.self).was_unlocked)
        XCTAssertEqual(try decode(ItemsList.self).items.count, 1)
        let item = try decode(ItemsShow.self)
        XCTAssertEqual(item.fields.first?.prior_count, 2)
        XCTAssertEqual(item.exposed?.sources, [.agentConfig])
        XCTAssertEqual(item.account?.email?.escaped, "fixture@example.invalid")
        XCTAssertEqual(item.detail?.allowed_hosts.map(\.escaped), ["example.invalid"])
        XCTAssertEqual(try decode(ItemsAdd.self).length, .ok)
        XCTAssertEqual(try decode(ItemsCheck.self).refs, [.unknownItem])
        XCTAssertEqual(try decode(GrantsList.self).grants.first?.uses, .session)
        XCTAssertEqual(try decode(GrantsRevoke.self).revoked, 1)
        XCTAssertTrue(try decode(Deny.self).root_auto_denied)
        XCTAssertEqual(try decode(AuditVerify.self).first_problem?.kind, .altered)
        XCTAssertEqual(try decode(BackupCreate.self).bytes, 1024)
    }

}
