import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct EnrolView: View {
    let session: VaultSession
    @State private var showPassphraseSheet = false

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

                VStack(alignment: .leading, spacing: 6) {
                    Text("Require Touch ID. Your login password will no longer approve.")
                        .font(.subheadline)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("enrol.touchIDOnly.caption")
                    if session.touchIDOnlyEnabled {
                        Text("Touch ID only is enabled.")
                            .font(.subheadline)
                            .foregroundStyle(ECToken.success.color)
                            .accessibilityIdentifier("enrol.touchIDOnly.enabled")
                    } else {
                        Button("Require Touch ID only") {
                            Task { _ = await session.enrollTouchIDOnlyUnlocker() }
                        }
                        .disabled(session.actionInProgress || session.state != .ready)
                        .accessibilityIdentifier("enrol.touchIDOnly.enable")
                    }
                }

                if session.passphraseUnlockerRemoved {
                    Text("Passphrase unlocker removed. Touch ID and the Recovery Kit remain.")
                        .font(.subheadline)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("enrol.passphrase.removed")
                } else {
                    Button("Remove passphrase unlocker…") {
                        showPassphraseSheet = true
                    }
                    .disabled(session.actionInProgress || session.state != .ready)
                    .accessibilityIdentifier("enrol.passphrase.remove")
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
        .sheet(isPresented: $showPassphraseSheet) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Remove passphrase unlocker?")
                    .font(.title3)
                    .foregroundStyle(ECToken.text.color)
                Text("Touch ID and your Recovery Kit remain. Terminal approvals with your passphrase stop working.")
                    .font(.subheadline)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("enrol.passphrase.facts")
                HStack {
                    Button("Cancel") { showPassphraseSheet = false }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button(session.removeButtonTitle) {
                        Task {
                            if await session.removePassphraseUnlockerWithTouchID() {
                                showPassphraseSheet = false
                            }
                        }
                    }
                    .foregroundStyle(ECToken.danger.color)
                    .disabled(session.actionInProgress || session.state != .ready)
                    .accessibilityIdentifier("enrol.passphrase.confirm")
                }
            }
            .padding(24)
            .frame(width: 440)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("enrol.section")
    }
}

