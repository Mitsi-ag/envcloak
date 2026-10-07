import AppKit
import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct ConnectionView: View {
    let session: VaultSession
    @State private var showConnecting = false
    @State private var details = false
    @State private var recoveryHelp = false
    var body: some View {
        VStack(spacing: 16) {
            if session.state == .connecting {
                ECBusy(size: .regular)
                if showConnecting { Text(session.state.title) }
            } else {
                Image(systemName: session.state == .locked ? "lock.fill" : "exclamationmark.triangle")
                    .font(.largeTitle).foregroundStyle(ECToken.secondary.color).accessibilityHidden(true)
                Text(session.state.title).font(.title2)
                Text(session.state.detail).foregroundStyle(ECToken.secondary.color)
                if session.state == .locked {
                    Text(session.lockReason)
                    if session.proofWait > 0 { Text("Too many failed attempts. Try again in \(session.proofWait) seconds.") }
                }
                if let action = session.state.action {
                    Button(action) { perform() }.disabled(session.actionInProgress)
                        .accessibilityIdentifier("state.action")
                }
                if session.state == .locked {
                    Button("Open Terminal") { WorkspaceActions.openTerminal() }
                }
                if details { Text(session.verificationDetails).textSelection(.enabled) }
            }
        }
        .multilineTextAlignment(.center).padding(32).frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain).accessibilityIdentifier("connection.state")
        .sheet(isPresented: $recoveryHelp) {
            RecoveryHelp()
        }
        .task(id: session.state == .connecting) {
            showConnecting = false
            do { try await Task.sleep(for: .milliseconds(300)); showConnecting = true } catch { }
        }
    }
    private func perform() {
        switch session.state {
        case .noDaemon: Task { await WorkspaceActions.startDaemon(session) }
        case .unverified: details = true
        case .noVault: WorkspaceActions.copy(CopiedCommand.createVault.text)
        case .locked: WorkspaceActions.copy(CopiedCommand.unlock.text)
        case .readOnly: recoveryHelp = true
        case .unavailable: WorkspaceActions.copy(CopiedCommand.status.text)
        default: break
        }
    }
}

struct DevelopmentBanner: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Daemon identity unverified", systemImage: "exclamationmark.triangle")
            Text("In this build, a program running as you could stand in for the background process (guarantees table).")
            Button("Open guarantees") { openWindow(id: WindowID.about) }
        }.padding().foregroundStyle(ECToken.warning.color)
            .accessibilityIdentifier("development.banner")
    }
}

struct ReadOnlyBanner: View {
    @State private var recoveryHelp = false
    var body: some View {
        HStack {
            Text(ConnectionState.readOnly.title)
            Spacer()
            Button("How to recover") { recoveryHelp = true }
        }.padding(12).foregroundStyle(ECToken.danger.color)
            .accessibilityIdentifier("read-only.banner")
            .sheet(isPresented: $recoveryHelp) { RecoveryHelp() }
    }
}

struct RecoveryHelp: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recover from a backup").font(.title2)
            Text("Keep a copy of the vault and its backups. In a human Terminal session, use envcloak recover with your Recovery Kit. Read the command's instructions before choosing a backup. Recovery ends existing grants.")
            Button("Copy recovery help command") { WorkspaceActions.copy(CopiedCommand.recoveryHelp.text) }
            Button("Open Terminal") { WorkspaceActions.openTerminal() }
            Button("Done") { dismiss() }
        }.padding(24).frame(width: 480)
    }
}
