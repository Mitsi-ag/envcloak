import Foundation
import XCTest
@testable import EnvCloakKit

final class ProjectsTests: XCTestCase {
    func testPagesRoundTripOpaqueCursorAndEscapeMetadata() throws {
        let json: [String: Any] = ["jsonrpc": "2.0", "id": 1, "result": [
            "projects": [["dir": "/tmp/project\u{202e}\u{1b}[31m", "manifest_sha256": String(repeating: "a", count: 64),
                          "bindings": [["env_name": "VARIABLE", "reference": "envcloak://fixture"]], "last_seen_secs": 42]],
            "next": ["last_seen": UInt64.max, "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"]]]
        let frame = try Frame(text: String(decoding: JSONSerialization.data(withJSONObject: json), as: UTF8.self))
        let page = try ProjectsList.response(frame, id: 1)
        XCTAssertEqual(page.projects.first?.dir.escaped, "/tmp/project\\u{202e}\\u{1b}[31m")
        let request = try ProjectsList(after: page.next).request(id: 2)
        let params = try request.body.withUnsafeBytes {
            (try JSONSerialization.jsonObject(with: Data($0)) as! [String: Any])["params"] as! [String: Any]
        }
        let cursor = try XCTUnwrap(params["after"] as? [String: Any])
        XCTAssertEqual((cursor["last_seen"] as? NSNumber)?.uint64Value, UInt64.max)
        XCTAssertEqual(cursor["id"] as? String, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
    }

    func testPageRefusesUnknownFieldsAndInvalidCursor() throws {
        for result in [
            #"{"projects":[],"next":null,"extra":true}"#,
            #"{"projects":[],"next":{"last_seen":-1,"id":"invalid"}}"#,
            #"{"projects":[],"next":{"last_seen":0,"id":"invalid"}}"#,
            #"{"projects":[],"next":{"last_seen":0,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","extra":true}}"#,
        ] {
            let frame = try Frame(text: "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" + result + "}")
            XCTAssertThrowsError(try ProjectsList.response(frame, id: 1))
        }
    }
}
