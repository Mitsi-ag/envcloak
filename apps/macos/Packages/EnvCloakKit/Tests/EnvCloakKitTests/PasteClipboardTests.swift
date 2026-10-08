import AppKit
import XCTest
@testable import EnvCloakKit

@MainActor final class PasteClipboardTests: XCTestCase {
    func testClearCapturedClipboardAndPreserveLaterCopy() {
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
}
