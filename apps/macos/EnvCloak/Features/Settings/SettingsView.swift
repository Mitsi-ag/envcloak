import AppKit
import EnvCloakDesign
import EnvCloakKit
import SwiftUI

/// Design §5.6 Settings area (`M3-17` and `M3-18`).
struct SettingsView: View {
    @Bindable var session: VaultSession
    @Environment(\.openWindow) private var openWindow
    @State private var defaultApprovalDuration: String = "8 h"

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                DevelopmentBanner()

                if session.loginItem.showsApprovalBanner {
                    loginItemApprovalBanner
                }

                unlockSection
                recoveryKitSection
                lockingSection
                approvalsSection
                projectPoliciesSection
                menuBarSection
                cliToolSection
                backgroundItemSection
                launchAtLoginSection
                aboutAndLimitsSection
            }
            .padding(20)
        }
        .background(ECToken.background.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("settings.view")
    }

    private var loginItemApprovalBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(ECToken.warning.color)
                .accessibilityHidden(true)
            Text(LoginItemController.approvalBannerText)
                .font(.callout.weight(.medium))
                .foregroundStyle(ECToken.text.color)
            Spacer()
            Button(LoginItemController.openLoginItemsTitle) {
                session.loginItem.openSystemSettings()
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("settings.loginItem.open")
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(ECToken.raised.color)
        )
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("settings.loginItem.banner")
    }

    private var unlockSection: some View {
        settingsCard(title: "Unlock", identifier: "settings.section.unlock") {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Secure Enclave")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(ECToken.text.color)
                    Text("Touch ID, or your login password when Touch ID is not available")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                }
                Spacer()
                Text(session.enrolledTouchID ? "Enrolled" : "Not enrolled")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.unlock.seState")
            }

            EnrolView(session: session)

            Divider().overlay(ECToken.rule.color)

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Passphrase")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(ECToken.text.color)
                    Text(session.passphrasePresent ? "On" : "Removed")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("settings.unlock.passphraseState")
                }
                Spacer()
            }

            Divider().overlay(ECToken.rule.color)

            VStack(alignment: .leading, spacing: 4) {
                Toggle(
                    "Touch ID only",
                    isOn: Binding(
                        get: { session.touchIDOnly },
                        set: { enabled in
                            Task { await session.setTouchIDOnly(enabled) }
                        }
                    )
                )
                .disabled(!session.enrolledTouchID || session.state != .ready)
                .accessibilityIdentifier("settings.touchIDOnly")

                Text("Require Touch ID. Your login password will no longer approve.")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.touchIDOnly.restriction")
            }
        }
    }

    private var recoveryKitSection: some View {
        settingsCard(title: "Recovery Kit", identifier: "settings.section.recoveryKit") {
            if session.recoveryConfirmed {
                Text("Confirmed. Your Recovery Kit can open the vault if Touch ID is unavailable.")
                    .font(.body)
                    .foregroundStyle(ECToken.text.color)
                    .accessibilityIdentifier("settings.recoveryKit.confirmed")
            } else {
                Text("Not confirmed. Plaintext .env files cannot be removed until it is.")
                    .font(.body)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("settings.recoveryKit.unconfirmed")
                HStack(spacing: 8) {
                    Text("envcloak recovery confirm")
                        .font(ECFont.martianMono(size: 11))
                        .foregroundStyle(ECToken.text.color)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            RoundedRectangle(cornerRadius: 4)
                                .fill(ECToken.background.color)
                        )
                        .accessibilityIdentifier("settings.recoveryKit.command")
                    Button("Copy") {
                        ClipboardWriter().copyReference("envcloak recovery confirm")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
    }

    private var lockingSection: some View {
        settingsCard(title: "Locking", identifier: "settings.section.locking") {
            HStack {
                Text("Idle limit")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text("8 hours")
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.secondary.color)
            }
            Text("Policies and the idle limit cannot be edited in this build.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
            Divider().overlay(ECToken.rule.color)
            Text("Locks when this Mac sleeps")
                .font(.body)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("settings.locking.sleep")
            Text("Locks when the screen locks")
                .font(.body)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("settings.locking.screenLock")
        }
    }

    private var approvalsSection: some View {
        settingsCard(title: "Approvals", identifier: "settings.section.approvals") {
            HStack {
                Picker("Default length", selection: $defaultApprovalDuration) {
                    Text("Once").tag("Once")
                    Text("1 h").tag("1 h")
                    Text("8 h").tag("8 h")
                }
                .frame(maxWidth: 280)
                .accessibilityIdentifier("settings.approvals.defaultDuration")
                Spacer()
            }

            HStack {
                Text("Notifications")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Button("Open Notification settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityIdentifier("settings.notifications.open")
            }

            Text("Standing approvals can last up to 30 days for test keys only, and require your password in Terminal.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("settings.approvals.standingCap")

            Text("EnvCloak never asks for your login password in its own window. Only macOS does.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("settings.approvals.standingPasswordLine")
        }
    }

    private var projectPoliciesSection: some View {
        settingsCard(title: "Project policies", identifier: "settings.section.projectPolicies") {
            Text("Per-project policy edits in the app arrive in a later release. Edit envcloak.toml directly in the meantime.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("settings.projectPolicies.unavailable")
        }
    }

    private var menuBarSection: some View {
        settingsCard(title: "Menu bar", identifier: "settings.section.menuBar") {
            Toggle(
                "Show EnvCloak in the menu bar",
                isOn: Binding(
                    get: { session.showMenuBarExtra },
                    set: { session.setShowMenuBarExtra($0) }
                )
            )
            .accessibilityIdentifier("settings.menuBar")

            HStack {
                Text("Global shortcut")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text("None")
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.menuBar.shortcut")
            }
        }
    }

    private var cliToolSection: some View {
        settingsCard(title: "Command-line tool", identifier: "settings.section.cli") {
            if let installed = session.cliStatus.installedPath {
                HStack {
                    Text("Installed at")
                        .font(.body)
                        .foregroundStyle(ECToken.text.color)
                    Text(Escape.display(installed))
                        .font(ECFont.martianMono(size: 11))
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityIdentifier("settings.cli.installedPath")
                    Spacer()
                }
            } else {
                HStack {
                    Text("Agents and your terminal use the envcloak command.")
                        .font(.body)
                        .foregroundStyle(ECToken.text.color)
                    Spacer()
                    Button("Install command-line tool") {
                        session.installCommandLineTool()
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("settings.cli.install")
                }
            }

            if let shadow = session.cliStatus.shadowingPath {
                Text("Another envcloak earlier on PATH (\(Escape.display(shadow))) would shadow this link.")
                    .font(.caption)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("settings.cli.shadowWarning")
            }

            if case .manualCommand(let command, let reason) = session.cliInstallOutcome {
                VStack(alignment: .leading, spacing: 4) {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                    Text(command)
                        .font(ECFont.martianMono(size: 11))
                        .foregroundStyle(ECToken.text.color)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("settings.cli.manualCommand")
                }
            }
        }
    }

    private var backgroundItemSection: some View {
        settingsCard(title: "Background item", identifier: "settings.section.backgroundItem") {
            HStack {
                Text("Status")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text(backgroundStatusLabel(session.loginItem.agentStatus))
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.backgroundItem.status")
            }

            if session.loginItem.showsApprovalBanner {
                HStack(spacing: 8) {
                    Text(LoginItemController.approvalBannerText)
                        .font(.caption)
                        .foregroundStyle(ECToken.warning.color)
                    Spacer()
                    Button(LoginItemController.openLoginItemsTitle) {
                        session.loginItem.openSystemSettings()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("settings.backgroundItem.openLoginItems")
                }
            } else if session.loginItem.agentStatus != .enabled {
                HStack {
                    Spacer()
                    Button("Turn on") {
                        Task { await session.loginItem.registerAgentIfSafe() }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("settings.backgroundItem.turnOn")
                }
            }

            if session.loginItem.cliAgentInstalled {
                HStack {
                    Text("Command-line LaunchAgent ai.envcloak.envcloakd is installed.")
                        .font(.caption)
                        .foregroundStyle(ECToken.warning.color)
                    Spacer()
                    Button("Replace command-line background process") {
                        Task { await session.loginItem.replaceCLILaunchAgent() }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("settings.backgroundItem.migrateCLI")
                }
            }
        }
    }

    private var launchAtLoginSection: some View {
        settingsCard(title: "Launch at login", identifier: "settings.section.launchAtLogin") {
            Toggle(
                "Launch EnvCloak at login",
                isOn: Binding(
                    get: { session.loginItem.launchAtLoginEnabled },
                    set: { session.loginItem.setLaunchAtLogin($0) }
                )
            )
            .accessibilityIdentifier("settings.launchAtLogin")
        }
    }

    private var aboutAndLimitsSection: some View {
        settingsCard(title: "About and limits", identifier: "settings.section.about") {
            HStack {
                Text("Version")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text(AboutMetadata.versionString)
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.about.version")
            }
            HStack {
                Text("Daemon identity")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text(session.daemonIdentitySummary)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.about.daemonIdentity")
            }
            HStack {
                Text("Hardening")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(ECToken.text.color)
                Spacer()
                Text(session.latestDaemonHardeningSummary)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("settings.about.hardening")
            }
            HStack {
                Button("See what EnvCloak guarantees today") {
                    openWindow(id: WindowID.about)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("settings.about.guarantees")
                Spacer()
            }
        }
    }

    private func backgroundStatusLabel(_ status: LoginItemStatus) -> String {
        switch status {
        case .enabled:
            "Enabled"
        case .requiresApproval:
            "Background item disabled in Login Items"
        case .notRegistered:
            "Not registered"
        case .notFound:
            "Not found"
        }
    }

    private func settingsCard<Content: View>(
        title: String,
        identifier: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(ECToken.raised.color)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(ECToken.rule.color, lineWidth: 1)
            )
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(identifier)
    }
}
