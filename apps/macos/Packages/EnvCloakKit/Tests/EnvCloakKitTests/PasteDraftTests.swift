import XCTest
@testable import EnvCloakKit

final class PasteDraftTests: XCTestCase {
    func testLineEndingEnvOfferAndRefusal() throws {
        let expected = UUID().uuidString
        var text = "VARIABLE=" + expected + "\r\n"
        var draft = try PasteDraft(taking: &text)
        XCTAssertTrue(text.isEmpty)
        XCTAssertTrue(draft.droppedLineEnding)
        XCTAssertEqual(draft.envName, "VARIABLE")
        try draft.useEnvLine()
        let value = draft.takeValue()
        value.withUnsafeBytes { XCTAssertEqual(Array($0), Array(expected.utf8)) }
        for bad in ["", "a\nb", "a\r\n\r\n", "x\u{0}y", String(repeating: "猫", count: Frame.limit)] {
            var input = bad
            XCTAssertThrowsError(try reject(&input))
            XCTAssertTrue(input.isEmpty)
        }
    }

    private func reject(_ input: inout String) throws { _ = try PasteDraft(taking: &input) }

    func testKeepPastedDoesNotTreatArbitraryEqualsAsEnvName() throws {
        for input in ["https://example.invalid/?a=b", "lower-case=value", "猫=value", "A B=value"] {
            var text = input
            let draft = try PasteDraft(taking: &text)
            XCTAssertNil(draft.envName)
            draft.value.withUnsafeBytes { XCTAssertEqual(Array($0), Array(input.utf8)) }
        }
    }
}
