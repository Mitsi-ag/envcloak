import AppKit
import EnvCloakKit
import SwiftUI

/// NSSecureTextField is SecureField's native control. Handling its paste
/// action captures changeCount at paste time; typed input never clears an
/// unrelated clipboard. No undo, accessibility value, cut or copy channel.
struct PasteField: NSViewRepresentable {
    let receive: (inout String) -> Void
    let cleared: (Bool) -> Void
    func makeNSView(context: Context) -> SecurePasteField {
        let field = SecurePasteField()
        field.placeholderString = "Paste the key"
        field.setAccessibilityIdentifier("paste.value")
        field.receive = receive; field.cleared = cleared
        field.delegate = context.coordinator
        return field
    }
    func updateNSView(_ field: SecurePasteField, context: Context) {
        field.receive = receive; field.cleared = cleared
    }
    func makeCoordinator() -> Coordinator { Coordinator() }
    final class Coordinator: NSObject, NSTextFieldDelegate {
        func controlTextDidBeginEditing(_ notification: Notification) {
            let field = notification.object as? SecurePasteField
            (field?.currentEditor() as? NSTextView)?.allowsUndo = false
        }
        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? SecurePasteField, !field.stringValue.isEmpty else { return }
            var text = field.stringValue
            field.stringValue = ""
            field.currentEditor()?.string = ""
            field.receive(&text)
        }
    }
}

final class SecurePasteField: NSSecureTextField {
    var receive: (inout String) -> Void = { $0 = "" }
    var cleared: (Bool) -> Void = { _ in }
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.contains(.command), event.charactersIgnoringModifiers == "v" {
            pasteValue(); return true
        }
        return super.performKeyEquivalent(with: event)
    }
    @objc func paste(_ sender: Any?) { pasteValue() }
    private func pasteValue() {
        let board = NSPasteboard.general
        let captured = board.changeCount
        guard var text = board.string(forType: .string) else { return }
        receive(&text)
        cleared(PasteClipboard.finish(board, captured: captured))
    }
}
