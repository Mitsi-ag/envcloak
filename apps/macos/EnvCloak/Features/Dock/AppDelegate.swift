import AppKit

@MainActor final class EnvCloakAppDelegate: NSObject, NSApplicationDelegate {
    weak var session: VaultSession?

    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        let menu = NSMenu(title: "EnvCloak")

        let review = NSMenuItem(
            title: "Review requests",
            action: #selector(reviewRequests(_:)),
            keyEquivalent: ""
        )
        review.target = self
        menu.addItem(review)

        let addKey = NSMenuItem(
            title: "Add key",
            action: #selector(addKey(_:)),
            keyEquivalent: ""
        )
        addKey.target = self
        menu.addItem(addKey)

        let lock = NSMenuItem(
            title: "Lock",
            action: #selector(lockVault(_:)),
            keyEquivalent: ""
        )
        lock.target = self
        menu.addItem(lock)

        return menu
    }

    @objc private func reviewRequests(_ sender: Any?) {
        session?.openApprovalWindow()
        session?.onOpenApprovalWindow?()
        NSApplication.shared.activate()
    }

    @objc private func addKey(_ sender: Any?) {
        session?.activeAsk = nil
        session?.onOpenPasteWindow?()
        NSApplication.shared.activate()
    }

    @objc private func lockVault(_ sender: Any?) {
        guard let session else { return }
        Task { await session.lock() }
    }
}
