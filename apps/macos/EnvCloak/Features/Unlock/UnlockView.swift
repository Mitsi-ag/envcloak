import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct UnlockView: View {
    let session: VaultSession

    var body: some View {
        VStack(spacing: 12) {
            if session.sshSession {
                Text("Touch ID cannot be used over SSH. Approve in a terminal with envcloak approve <id>.")
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("unlock.ssh")
            } else {
                if session.clamshellClosed {
                    Text("Touch ID is not available with the lid closed. Use your password.")
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("unlock.clamshell")
                }
                Button(session.unlockButtonTitle) {
                    Task { _ = await session.unlockWithTouchID() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(session.actionInProgress || session.proofWait > 0)
                .accessibilityIdentifier("unlock.touchid")

                if !session.enrolledTouchID {
                    EnrolView(session: session)
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("unlock.section")
    }
}
