import AppKit

@MainActor public enum PasteClipboard {
    public static func finish(_ board: NSPasteboard, captured: Int) -> Bool {
        guard board.changeCount == captured else { return false }
        board.clearContents()
        return true
    }
}
