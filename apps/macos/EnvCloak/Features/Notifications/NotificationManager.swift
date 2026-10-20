import AppKit
import EnvCloakKit
import Foundation
import UserNotifications

struct ApprovalNotificationPayload: Equatable, Sendable {
    let requestID: String
    let categoryIdentifier: String
    let title: String
    let body: String
}

@MainActor protocol NotificationSink {
    func configureCategories(actionIdentifiers: [String])
    func post(_ payload: ApprovalNotificationPayload) async
    func removeDelivered(requestIDs: [String])
    func setDockBadge(_ label: String?)
    func postVoiceOverAnnouncement(_ text: String)
}

@MainActor final class SystemNotificationSink: NSObject, NotificationSink {
    static let categoryID = "approval"
    static let denyActionID = "DENY_ACTION"
    private var configured = false

    private static var canUseUserNotifications: Bool {
        #if ENVCLOAK_SCREEN_TESTS
        return false
        #else
        return Bundle.main.bundleIdentifier != nil
        #endif
    }

    func configureCategories(actionIdentifiers: [String]) {
        guard !configured, Self.canUseUserNotifications else { return }
        configured = true
        let denyAction = UNNotificationAction(
            identifier: Self.denyActionID,
            title: "Deny",
            options: [.destructive]
        )
        let category = UNNotificationCategory(
            identifier: Self.categoryID,
            actions: [denyAction],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    func post(_ payload: ApprovalNotificationPayload) async {
        guard Self.canUseUserNotifications else { return }
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
        }
        let content = UNMutableNotificationContent()
        content.title = payload.title
        content.body = payload.body
        content.categoryIdentifier = payload.categoryIdentifier
        content.userInfo = ["request": payload.requestID]
        let req = UNNotificationRequest(
            identifier: "envcloak.approval.\(payload.requestID)",
            content: content,
            trigger: nil
        )
        try? await center.add(req)
    }

    func removeDelivered(requestIDs: [String]) {
        guard Self.canUseUserNotifications, !requestIDs.isEmpty else { return }
        let ids = requestIDs.map { "envcloak.approval.\($0)" }
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ids)
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: ids)
    }

    func setDockBadge(_ label: String?) {
        NSApplication.shared.dockTile.badgeLabel = label
    }

    func postVoiceOverAnnouncement(_ text: String) {
        guard let window = NSApplication.shared.mainWindow ?? NSApplication.shared.windows.first else { return }
        NSAccessibility.post(
            element: window,
            notification: .announcementRequested,
            userInfo: [
                .announcement: text,
                .priority: NSAccessibilityPriorityLevel.medium.rawValue
            ]
        )
    }
}

@MainActor final class NotificationManager {
    static let categoryIdentifier = "approval"
    static let denyActionId = "DENY_ACTION"
    static let actionIdentifiers = [denyActionId]

    private let sink: any NotificationSink
    private let isFrontmost: @MainActor () -> Bool
    private var notifiedRequests: Set<String> = []
    private(set) var lastBadge: String?
    private(set) var lastAnnouncement: String?
    var onDeny: (@MainActor (DaemonText) async -> Void)?
    var onOpenRequest: (@MainActor (DaemonText) -> Void)?

    var notifiedRequestIds: Set<String> {
        notifiedRequests
    }

    init(
        sink: (any NotificationSink)? = nil,
        isFrontmost: @escaping @MainActor () -> Bool = { NSApplication.shared.isActive }
    ) {
        self.sink = sink ?? SystemNotificationSink()
        self.isFrontmost = isFrontmost
        self.sink.configureCategories(actionIdentifiers: Self.actionIdentifiers)
    }

    func reconcile(
        pending: [AppPendingView],
        asksCount: Int = 0,
        isFrontmost frontmostOverride: Bool? = nil
    ) async {
        let totalWaiting = pending.count + max(0, asksCount)
        let badge = totalWaiting == 0 ? nil : "\(totalWaiting)"
        if badge != lastBadge {
            lastBadge = badge
            sink.setDockBadge(badge)
        }

        let currentIDs = Set(pending.map { MetadataRequest.raw($0.request) })
        let finished = notifiedRequests.subtracting(currentIDs)
        if !finished.isEmpty {
            sink.removeDelivered(requestIDs: Array(finished))
            notifiedRequests.subtract(finished)
        }

        let frontmost = frontmostOverride ?? isFrontmost()
        for item in pending {
            let rawID = MetadataRequest.raw(item.request)
            guard !notifiedRequests.contains(rawID) else { continue }
            notifiedRequests.insert(rawID)

            let payload = Self.makePayload(for: item)
            if frontmost {
                let announcement = "\(payload.title). \(payload.body)"
                lastAnnouncement = announcement
                sink.postVoiceOverAnnouncement(announcement)
            } else {
                await sink.post(payload)
            }
        }
    }

    func handleNotificationAction(actionIdentifier: String, requestId: DaemonText) async {
        if actionIdentifier == Self.denyActionId {
            await onDeny?(requestId)
        } else {
            onOpenRequest?(requestId)
        }
    }

    func announce(_ text: String) {
        lastAnnouncement = text
        sink.postVoiceOverAnnouncement(text)
    }

    func clear() {
        if !notifiedRequests.isEmpty {
            sink.removeDelivered(requestIDs: Array(notifiedRequests))
            notifiedRequests.removeAll()
        }
        lastAnnouncement = nil
        if lastBadge != nil {
            lastBadge = nil
            sink.setDockBadge(nil)
        }
    }

    func requestAuthorizationIfNeeded() async {
        #if !ENVCLOAK_SCREEN_TESTS
        guard Bundle.main.bundleIdentifier != nil else { return }
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
        }
        #endif
    }

    static func subjectLabel(_ subject: SubjectSummary) -> String {
        subject.label?.escaped ?? subject.kind.rawValue.capitalized
    }

    static func pendingCallerLabel(_ item: AppPendingView) -> String {
        item.agent?.escaped ?? item.kind.rawValue.capitalized
    }

    static func bodyText(for item: AppPendingView) -> String {
        let caller = pendingCallerLabel(item)
        let project = MetadataRequest.basename(item.project)
        let total = UInt64(item.bindings.count) + item.more_bindings
        let keyWord = total == 1 ? "key" : "keys"
        return "\(caller) asked for \(total) \(keyWord) in \(project)."
    }

    static func makePayload(for item: AppPendingView) -> ApprovalNotificationPayload {
        ApprovalNotificationPayload(
            requestID: MetadataRequest.raw(item.request),
            categoryIdentifier: categoryIdentifier,
            title: "Secret approval requested",
            body: bodyText(for: item)
        )
    }
}
