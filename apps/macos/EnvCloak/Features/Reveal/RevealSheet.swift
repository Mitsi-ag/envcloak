import AppKit
import EnvCloakDesign
import EnvCloakKit
import Observation
import SwiftUI

@Observable @MainActor final class KeySightModel {
    @ObservationIgnored private var secretBuffer: SecretBuffer?
    @ObservationIgnored private var countdownTask: Task<Void, Never>?
    let slug: DaemonText
    var selectedField: DaemonText?
    var clientRequestId: DaemonText?
    var descriptor: RevealDescriptor?
    var isShown = false
    var secondsRemaining = 0
    var busy = false
    var notice: String?
    var copiedNotice: String?

    init(slug: DaemonText, field: DaemonText?, clientRequestId: DaemonText? = nil) {
        self.slug = slug
        self.selectedField = field
        self.clientRequestId = clientRequestId
    }

    var hasSecretBuffer: Bool {
        secretBuffer != nil
    }

    var renderedSecret: String? {
        guard let buffer = secretBuffer.take() else { return nil }
        let text = ClipboardWriter.utf8String(buffer)
        secretBuffer = consume buffer
        return text
    }

    func receiveSecret(_ buffer: consuming SecretBuffer, startCountdown: Bool = true) {
        countdownTask?.cancel()
        secretBuffer = consume buffer
        isShown = true
        secondsRemaining = 30
        if startCountdown {
            countdownTask = Task { [weak self] in
                for remaining in stride(from: 29, through: 0, by: -1) {
                    do {
                        try await Task.sleep(for: .seconds(1))
                    } catch {
                        return
                    }
                    guard !Task.isCancelled, let self, self.isShown else { return }
                    if remaining == 0 {
                        self.hideNow()
                        return
                    }
                    self.secondsRemaining = remaining
                }
            }
        }
    }

    func performSight(_ session: VaultSession) async {
        guard !busy else { return }
        busy = true
        notice = nil
        copiedNotice = nil
        defer { busy = false }
        do {
            let desc: RevealDescriptor
            if let reqId = clientRequestId {
                desc = try await session.beginClientReveal(request: reqId)
            } else {
                desc = try await session.beginReveal(slug: slug, field: selectedField)
            }
            descriptor = desc
            let opened = try await session.completeRevealWithTouchID(descriptor: desc)
            receiveSecret(opened)
        } catch SignerError.userCancelled, KeyStoreError.userCancelled {
            notice = "Touch ID was cancelled. The key value was not shown."
        } catch {
            notice = session.notice ?? "The key value could not be shown."
        }
    }

    func copySecret(using writer: ClipboardWriter = ClipboardWriter()) {
        guard let buffer = secretBuffer.take() else { return }
        writer.copySecret(buffer)
        secretBuffer = consume buffer
        let message = "Copied. Cleared in 30 s."
        copiedNotice = message
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                .announcement: message,
                .priority: NSAccessibilityPriorityLevel.high.rawValue,
            ]
        )
    }

    func hideNow() {
        countdownTask?.cancel()
        countdownTask = nil
        secretBuffer = nil
        isShown = false
        secondsRemaining = 0
    }
}

struct RevealSheet: View {
    static let allowsValueSelection = false

    let session: VaultSession
    let item: ItemView
    let clipboardWriter: ClipboardWriter
    @Environment(\.dismiss) private var dismiss
    @State private var model: KeySightModel

    init(
        session: VaultSession,
        item: ItemView,
        field: DaemonText?,
        clipboardWriter: ClipboardWriter = ClipboardWriter(),
        model: KeySightModel? = nil
    ) {
        self.session = session
        self.item = item
        self.clipboardWriter = clipboardWriter
        let defaultField = field ?? (item.fields.count == 1 ? item.fields.first?.name : nil)
        _model = State(initialValue: model ?? KeySightModel(slug: item.slug, field: defaultField))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Reveal \(item.slug.escaped)")
                .font(.title3)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("reveal.title")

            if item.fields.count > 1 && !model.isShown {
                Picker("Field", selection: $model.selectedField) {
                    Text("Choose a field").tag(Optional<DaemonText>.none)
                    ForEach(DisplayRow.of(item.fields)) { row in
                        Text(row.value.name.escaped).tag(Optional(row.value.name))
                    }
                }
            }

            Text("The value will show on screen for 30 seconds. EnvCloak cannot stop screen recording or someone looking at your screen.")
                .font(.subheadline)
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("reveal.limit")

            if let req = model.descriptor?.requester {
                let caller = req.label?.escaped ?? req.kind.rawValue.capitalized
                let exe = req.root.exe?.escaped ?? ""
                Text("Requested by \(caller) (PID \(req.caller_pid)\(exe.isEmpty ? "" : " · \(exe)")).")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("reveal.evidence")
            }


            if model.isShown, let secret = model.renderedSecret {
                Text(secret)
                    .font(ECFont.martianMono(size: 13))
                    .foregroundStyle(ECToken.text.color)
                    .textSelection(.disabled)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .privacySensitive()
                    .accessibilityLabel("Value shown on screen")
                    .accessibilityIdentifier("reveal.value")

                Text("Hides in \(model.secondsRemaining) \(model.secondsRemaining == 1 ? "second" : "seconds")")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("reveal.countdown")

                if let copied = model.copiedNotice {
                    Text(copied)
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("reveal.copied")
                }

                HStack {
                    Button("Copy") {
                        model.copySecret(using: clipboardWriter)
                    }
                    .accessibilityIdentifier("reveal.copy")
                    Spacer()
                    Button("Hide now") {
                        model.hideNow()
                        dismiss()
                    }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("reveal.hide")
                }
            } else {
                if let notice = model.notice {
                    Text(notice)
                        .foregroundStyle(ECToken.warning.color)
                        .accessibilityIdentifier("reveal.error")
                }
                HStack {
                    Button("Cancel") {
                        model.hideNow()
                        dismiss()
                    }
                    .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button(session.revealButtonTitle) {
                        Task { await model.performSight(session) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.busy || session.state != .ready || (item.fields.count > 1 && model.selectedField == nil))
                    .accessibilityIdentifier("reveal.confirm")
                }
            }
        }
        .padding(24)
        .frame(width: 480)
        .interactiveDismissDisabled(model.busy)
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            model.hideNow()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            model.hideNow()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
            model.hideNow()
        }
        .onReceive(NotificationCenter.default.publisher(for: ScreenLockMonitor.didLockNotification)) { _ in
            model.hideNow()
        }
        .onChange(of: session.state) { _, state in
            if state != .ready {
                model.hideNow()
                dismiss()
            }
        }
        .onDisappear {
            model.hideNow()
        }
    }
}
