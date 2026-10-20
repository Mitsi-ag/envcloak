import AppKit
import Foundation

@MainActor
public struct ClipboardWriter {
    public static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    public static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    public static let clearDelay: Duration = .seconds(30)
    public static let copiedNotice = "Copied. Cleared in 30 s."

    public let pasteboard: NSPasteboard
    private let clock: any Clock<Duration>

    public init(
        pasteboard: NSPasteboard = .general,
        clock: any Clock<Duration> = ContinuousClock()
    ) {
        self.pasteboard = pasteboard
        self.clock = clock
    }

    @discardableResult
    public func copySecret(_ b: borrowing SecretBuffer) -> Task<Bool, Never> {
        let text = Self.utf8String(b)
        pasteboard.clearContents()
        pasteboard.declareTypes([.string, Self.concealedType, Self.transientType], owner: nil)
        pasteboard.setString(text, forType: .string)
        pasteboard.setData(Data(), forType: Self.concealedType)
        pasteboard.setData(Data(), forType: Self.transientType)
        let captured = pasteboard.changeCount
        let board = pasteboard
        let clock = self.clock
        return Task { @MainActor in
            do {
                try await clock.sleep(for: Self.clearDelay)
            } catch {
                return false
            }
            return PasteClipboard.finish(board, captured: captured)
        }
    }

    public func copyReference(_ text: String) {
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }

    public static func utf8String(_ b: borrowing SecretBuffer) -> String {
        b.withUnsafeBytes { rawPtr in
            String(decoding: rawPtr, as: UTF8.self)
        }
    }
}
