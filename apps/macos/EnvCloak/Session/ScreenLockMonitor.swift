import AppKit
import EnvCloakKit
import Foundation

enum LockSignal: String, Equatable, Sendable {
    case screenLocked = "screen_lock"
    case screensDidSleep = "screens_sleep"
    case sessionDidResign = "session_resign"

    var appLockReason: AppLockReason {
        switch self {
        case .screenLocked, .screensDidSleep:
            .screenLock
        case .sessionDidResign:
            .sessionResign
        }
    }
}

@MainActor protocol LockSignalSource: AnyObject {
    func start(handler: @escaping @MainActor (LockSignal) -> Void)
    func stop()
}

@MainActor final class WorkspaceLockSignalSource: LockSignalSource {
    static let screenIsLockedNotification = Notification.Name("com.apple.screenIsLocked")
    private var workspaceTokens: [NSObjectProtocol] = []
    private var distributedTokens: [NSObjectProtocol] = []

    init() {}

    func start(handler: @escaping @MainActor (LockSignal) -> Void) {
        stop()
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        let sleepToken = workspaceCenter.addObserver(
            forName: NSWorkspace.screensDidSleepNotification,
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor in
                handler(.screensDidSleep)
            }
        }
        let resignToken = workspaceCenter.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification,
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor in
                handler(.sessionDidResign)
            }
        }
        workspaceTokens = [sleepToken, resignToken]

        let distCenter = DistributedNotificationCenter.default()
        let lockToken = distCenter.addObserver(
            forName: Self.screenIsLockedNotification,
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor in
                handler(.screenLocked)
            }
        }
        distributedTokens = [lockToken]
    }

    func stop() {
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        for token in workspaceTokens {
            workspaceCenter.removeObserver(token)
        }
        workspaceTokens.removeAll()

        let distCenter = DistributedNotificationCenter.default()
        for token in distributedTokens {
            distCenter.removeObserver(token)
        }
        distributedTokens.removeAll()
    }
}

@MainActor final class ScreenLockMonitor {
    static let didLockNotification = Notification.Name("ai.envcloak.app.screenLockDidFire")
    private let source: any LockSignalSource
    private let onLock: @MainActor (AppLockReason) async -> Void
    private(set) var lastSignal: LockSignal?
    private(set) var lockCount = 0
    var isEnabled = true

    init(
        source: any LockSignalSource = WorkspaceLockSignalSource(),
        onLock: @escaping @MainActor (AppLockReason) async -> Void
    ) {
        self.source = source
        self.onLock = onLock
    }

    func start() {
        source.start { [weak self] signal in
            guard let self else { return }
            Task { @MainActor in
                await self.handle(signal)
            }
        }
    }

    func stop() {
        source.stop()
    }

    func handle(_ signal: LockSignal) async {
        lastSignal = signal
        NotificationCenter.default.post(name: Self.didLockNotification, object: nil)
        guard isEnabled else { return }
        lockCount += 1
        await onLock(signal.appLockReason)
    }
}
