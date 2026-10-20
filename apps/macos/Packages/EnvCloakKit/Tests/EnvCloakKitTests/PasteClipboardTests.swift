import AppKit
import XCTest
@testable import EnvCloakKit

final class ManualClipboardClock: Clock, @unchecked Sendable {
    typealias Duration = Swift.Duration

    struct Instant: InstantProtocol {
        var offset: Swift.Duration

        func advanced(by duration: Swift.Duration) -> Instant {
            Instant(offset: offset + duration)
        }

        func duration(to other: Instant) -> Swift.Duration {
            other.offset - offset
        }

        static func < (lhs: Instant, rhs: Instant) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    private struct Waiter {
        let id: UUID
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private let lock = NSLock()
    private var current = Instant(offset: .zero)
    private var waiters: [Waiter] = []
    private var waiterArrivalContinuations: [CheckedContinuation<Void, Never>] = []

    var now: Instant {
        lock.withLock { current }
    }

    var minimumResolution: Swift.Duration { .milliseconds(1) }

    func waitForWaiter() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let hasWaiter = lock.withLock { () -> Bool in
                if !waiters.isEmpty {
                    return true
                }
                waiterArrivalContinuations.append(cont)
                return false
            }
            if hasWaiter {
                cont.resume()
            }
        }
    }

    func sleep(until deadline: Instant, tolerance: Swift.Duration?) async throws {
        let shouldWait = lock.withLock { () -> Bool in
            deadline > current
        }
        if !shouldWait {
            try Task.checkCancellation()
            return
        }
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
                let result = lock.withLock { () -> (ready: Bool, arrivals: [CheckedContinuation<Void, Never>]) in
                    if deadline <= current {
                        return (true, [])
                    }
                    waiters.append(Waiter(id: waiterID, deadline: deadline, continuation: cont))
                    let arrivals = waiterArrivalContinuations
                    waiterArrivalContinuations.removeAll()
                    return (false, arrivals)
                }
                for arrival in result.arrivals {
                    arrival.resume()
                }
                if result.ready {
                    cont.resume()
                }
            }
        } onCancel: {
            let removed = lock.withLock { () -> CheckedContinuation<Void, any Error>? in
                guard let idx = waiters.firstIndex(where: { $0.id == waiterID }) else { return nil }
                return waiters.remove(at: idx).continuation
            }
            removed?.resume(throwing: CancellationError())
        }
    }

    func advance(by duration: Swift.Duration) {
        let due = lock.withLock { () -> [CheckedContinuation<Void, any Error>] in
            current = current.advanced(by: duration)
            var ready: [CheckedContinuation<Void, any Error>] = []
            var remaining: [Waiter] = []
            for w in waiters {
                if w.deadline <= current {
                    ready.append(w.continuation)
                } else {
                    remaining.append(w)
                }
            }
            waiters = remaining
            return ready
        }
        for cont in due {
            cont.resume()
        }
    }
}

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

    func testClipboardWriterSetsConcealedAndTransientAndClearsAt30SecondsWhenUnchanged() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clock = ManualClipboardClock()
        let writer = ClipboardWriter(pasteboard: board, clock: clock)

        let secretText = "sk-test-clipboard-canary-\(UUID().uuidString)"
        var buf = try SecretBuffer(capacity: 64)
        try Array(secretText.utf8).withUnsafeBytes { rawPtr in
            try buf.append(contentsOf: rawPtr)
        }

        let clearTask = writer.copySecret(buf)
        let types = board.types ?? []
        XCTAssertTrue(types.contains(ClipboardWriter.concealedType), "ConcealedType must be set on secret copy")
        XCTAssertTrue(types.contains(ClipboardWriter.transientType), "TransientType must be set on secret copy")
        XCTAssertEqual(board.string(forType: .string), secretText)

        await clock.waitForWaiter()

        // At 10 seconds, still present.
        clock.advance(by: .seconds(10))
        await Task.yield()
        XCTAssertEqual(board.string(forType: .string), secretText)

        // At 30 seconds, cleared because changeCount still matches.
        clock.advance(by: .seconds(20))
        let didClear = await clearTask.value
        XCTAssertTrue(didClear)
        XCTAssertNil(board.string(forType: .string))
    }

    func testClipboardWriterLeavesPasteboardUntouchedWhenAnotherWriterChangesItAt10Seconds() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let clock = ManualClipboardClock()
        let writer = ClipboardWriter(pasteboard: board, clock: clock)

        let secretText = "sk-test-overwritten-\(UUID().uuidString)"
        var buf = try SecretBuffer(capacity: 64)
        try Array(secretText.utf8).withUnsafeBytes { rawPtr in
            try buf.append(contentsOf: rawPtr)
        }

        let clearTask = writer.copySecret(buf)
        await clock.waitForWaiter()

        clock.advance(by: .seconds(10))
        await Task.yield()

        // Another writer replaces the clipboard at 10 seconds.
        board.clearContents()
        board.setString("user-copied-note", forType: .string)

        clock.advance(by: .seconds(20))
        let didClear = await clearTask.value
        XCTAssertFalse(didClear, "Clipboard must not be cleared when changeCount moved")
        XCTAssertEqual(board.string(forType: .string), "user-copied-note")
    }


    func testCopyReferenceWritesPlainTextOnlyWithoutConcealedOrTransientMarkers() {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let writer = ClipboardWriter(pasteboard: board)

        writer.copyReference("envcloak://stripe/acme-live")
        XCTAssertEqual(board.string(forType: .string), "envcloak://stripe/acme-live")
        let types = board.types ?? []
        XCTAssertFalse(types.contains(ClipboardWriter.concealedType))
        XCTAssertFalse(types.contains(ClipboardWriter.transientType))
    }
}
