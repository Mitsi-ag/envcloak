import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct EnrolView: View {
    let session: VaultSession

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if session.enrolmentCompleted || session.enrolledTouchID {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle")
                        .foregroundStyle(ECToken.success.color)
                        .accessibilityHidden(true)
                    Text("Touch ID added")
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityIdentifier("enrol.completed")
                }
            } else if let pendingId = session.enrolmentPendingId {
                let commandText = session.enrolmentCommand ?? ("envcloak approve " + pendingId.escaped)
                Text("Approve this once in Terminal with your passphrase: \(commandText)")
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityIdentifier("enrol.instructions")
                Text(commandText)
                    .font(ECFont.martianMono(size: 12))
                    .foregroundStyle(ECToken.text.color)
                    .padding(12)
                    .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .accessibilityIdentifier("enrol.command")
                HStack(spacing: 12) {
                    Button("Copy") {
                        _ = WorkspaceActions.copy(commandText)
                    }
                    .accessibilityIdentifier("enrol.copy")
                    Button("Open Terminal") {
                        WorkspaceActions.openTerminal()
                    }
                    .accessibilityIdentifier("enrol.terminal")
                }
                .task(id: pendingId) {
                    while !Task.isCancelled && session.enrolmentPendingId == pendingId {
                        do { try await Task.sleep(for: .seconds(1)) } catch { return }
                        guard !Task.isCancelled, session.enrolmentPendingId == pendingId else { return }
                        _ = await session.pollEnrolment()
                    }
                }
            } else {
                Text("Touch ID, or your login password when Touch ID is not available")
                    .foregroundStyle(ECToken.secondary.color)
                Button("Add Touch ID") {
                    Task { _ = await session.beginEnrolment() }
                }
                .disabled(session.actionInProgress)
                .accessibilityIdentifier("enrol.begin")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("enrol.section")
    }
}
