import AppKit
import EnvCloakKit
import XCTest
@testable import EnvCloak

@MainActor final class PasteTests: XCTestCase {
    func testClipboardClearOnlyIfUnchanged() {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        board.setString(UUID().uuidString, forType: .string)
        let captured = board.changeCount
        XCTAssertTrue(PasteClipboard.finish(board, captured: captured))
        XCTAssertNil(board.string(forType: .string))
        board.setString(UUID().uuidString, forType: .string)
        let earlier = board.changeCount
        board.clearContents(); board.setString("Later clipboard", forType: .string)
        XCTAssertFalse(PasteClipboard.finish(board, captured: earlier))
        XCTAssertEqual(board.string(forType: .string), "Later clipboard")
    }

    func testDraftRefusalAndResetRemoveDerivedState() {
        let model = PasteModel()
        var text = "VARIABLE=" + UUID().uuidString + "\r\n"
        model.receive(&text)
        XCTAssertTrue(text.isEmpty)
        XCTAssertEqual(model.envName, "VARIABLE")
        model.useEnvLine()
        XCTAssertEqual(model.variable, "VARIABLE")
        XCTAssertNil(model.envName)
        text = "one\ntwo"
        model.receive(&text)
        XCTAssertEqual(model.count, 0)
        XCTAssertNotNil(model.notice)
        XCTAssertNil(model.saved)
        model.reset()
        XCTAssertEqual(model.variable, "")
        XCTAssertNil(model.notice)
    }

    func testBindingArgumentsContainReferencesOnlyAndRefuseHostileNames() {
        for name in ["A=b", "-option", "", "猫", "A\u{1b}", String(repeating: "A", count: 129)] {
            XCTAssertNil(BindingEdit(project: .init("/tmp/fixture"), profile: nil, envName: name, reference: "fixture", previous: nil).cliArguments)
        }
        let edit = BindingEdit(project: .init("/tmp/fixture"), profile: "short", envName: "VARIABLE", reference: "fixture#value", previous: nil)
        XCTAssertEqual(edit.cliArguments, ["ref", "VARIABLE=fixture#value", "--profile", "short", "--json"])
    }
}
