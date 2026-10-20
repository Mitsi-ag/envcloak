import EnvCloakDesign
import EnvCloakKit
import SwiftUI

enum WelcomeStep: Int, CaseIterable, Identifiable {
    case welcome = 1
    case backgroundItem = 2
    case vault = 3
    case cliTool = 4
    case menuAndNotifications = 5
    case firstRunScan = 6

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .welcome: "Welcome"
        case .backgroundItem: "Background process"
        case .vault: "Vault"
        case .cliTool: "Command-line tool"
        case .menuAndNotifications: "Menu bar and notifications"
        case .firstRunScan: "First-run scan"
        }
    }
}

struct WelcomeView: View {
    @Bindable var session: VaultSession
    @State private var step: WelcomeStep
    @State private var scanModel: FirstRunScanModel
    @State private var notifyWhenAgentAsks = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow

    init(session: VaultSession, initialStep: WelcomeStep = .welcome, scanModel: FirstRunScanModel? = nil) {
        self.session = session
        _step = State(initialValue: initialStep)
        _scanModel = State(initialValue: scanModel ?? FirstRunScanModel(session: session))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                ForEach(WelcomeStep.allCases) { item in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(item.rawValue <= step.rawValue ? ECToken.text.color : ECToken.secondary.color.opacity(ECMotion.ghost))
                        .frame(width: 18, height: 6)
                        .accessibilityLabel("\(item.title), step \(item.rawValue) of 6")
                }
                Spacer()
                if step != .firstRunScan {
                    Button("Skip to first-run scan") { step = .firstRunScan }
                }
            }
            .padding(16)
            .background(ECToken.raised.color)
            .accessibilityIdentifier("welcome.steps")

            switch step {
            case .welcome:
                welcomeStepView
            case .backgroundItem:
                backgroundItemStepView
            case .vault:
                vaultStepView
            case .cliTool:
                cliToolStepView
            case .menuAndNotifications:
                menuAndNotificationsStepView
            case .firstRunScan:
                FirstRunScanView(
                    model: scanModel,
                    onOpenProjects: { dismiss() },
                    onDone: { dismiss() }
                )
            }
        }
        .frame(minWidth: 720, minHeight: 540)
        .background(ECToken.background.color)
        .task {
            session.loginItem.refreshStatus()
        }
    }

    private var welcomeStepView: some View {
        VStack(alignment: .leading, spacing: 16) {
            ECReveal(module: 8)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
                .background(ECToken.plate.color)
            VStack(alignment: .leading, spacing: 12) {
                Text("Your AI agents use your API keys. They never see them.")
                    .font(.title2)
                    .foregroundStyle(ECToken.text.color)
                Text("Fully true in proxy mode for HTTPS APIs. In inject mode, the command you approve holds the key while it runs.")
                    .foregroundStyle(ECToken.secondary.color)
                Button("What EnvCloak does and does not guarantee.") {
                    openWindow(id: WindowID.about)
                }
                .buttonStyle(.link)
                .accessibilityIdentifier("welcome.guarantees")
                Spacer()
                HStack {
                    Spacer()
                    Button("Continue") { step = .backgroundItem }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("welcome.continue")
                }
            }
            .padding(24)
        }
    }

    private var backgroundItemStepView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Background item, step 2 of 6")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("welcome.background.heading")
            Text("EnvCloak keeps your vault in a background process that starts when you log in. It holds the vault key while it is unlocked, and nothing else does.")
                .foregroundStyle(ECToken.text.color)

            if let banner = session.loginItem.banner {
                HStack(spacing: 12) {
                    Text(banner)
                        .font(.callout.weight(.medium))
                        .foregroundStyle(ECToken.warning.color)
                    Spacer()
                    Button("Open Login Items") {
                        session.loginItem.openLoginItemsSettings()
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("welcome.background.openLoginItems")
                }
                .padding(12)
                .background(ECToken.raised.color)
                .accessibilityIdentifier("welcome.background.banner")
            }

            if session.loginItem.cliLaunchAgentPresent {
                HStack {
                    Text("An existing command-line LaunchAgent (ai.envcloak.envcloakd) was detected. Enabling the app's background item removes it first so both never run at once.")
                        .font(.caption)
                        .foregroundStyle(ECToken.warning.color)
                        .accessibilityIdentifier("welcome.background.cliMigrationNotice")
                    Spacer()
                    Button("Replace command-line background process") {
                        Task { await session.loginItem.registerBackgroundAgent() }
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("welcome.background.migrateCLI")
                }
            }

            HStack(spacing: 8) {
                Button("Turn on") {
                    Task { await session.loginItem.registerBackgroundAgent() }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("welcome.background.turnOn")

                if session.loginItem.agentStatus == .enabled {
                    Text("Background item enabled.")
                        .font(.caption)
                        .foregroundStyle(ECToken.success.color)
                        .accessibilityIdentifier("welcome.background.enabled")
                }
            }

            if let notice = session.loginItem.notice {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("welcome.background.notice")
            }

            Spacer()
            HStack {
                Spacer()
                Button("Continue") { step = .vault }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("welcome.background.continue")
            }
        }
        .padding(24)
    }

    private var vaultStepView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Vault")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
            Text(session.state == .noVault
                ? "Create one in Terminal with envcloak vault create."
                : "Found your vault. Add Touch ID to it.")
                .foregroundStyle(ECToken.text.color)
            if session.state != .noVault {
                EnrolView(session: session)
            }
            Spacer()
            HStack {
                Spacer()
                Button("Continue") { step = .cliTool }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("welcome.vault.continue")
            }
        }
        .padding(24)
    }

    private var cliToolStepView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Command-line tool, step 4 of 6")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
                .accessibilityIdentifier("welcome.cli.heading")
            Text("Agents and your terminal use the envcloak command.")
                .foregroundStyle(ECToken.text.color)

            if let installed = session.cliStatus.installedLinkPath {
                Text("Installed at \(Escape.display(installed))")
                    .font(ECFont.martianMono(size: 11))
                    .foregroundStyle(ECToken.success.color)
                    .accessibilityIdentifier("welcome.cli.installed")
            } else {
                Button("Install command-line tool") {
                    session.installCommandLineTool()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("welcome.cli.install")
            }

            if let shadow = session.cliStatus.shadowedBy {
                Text("Another envcloak earlier on PATH (\(Escape.display(shadow))) would shadow this link.")
                    .font(.caption)
                    .foregroundStyle(ECToken.warning.color)
                    .accessibilityIdentifier("welcome.cli.shadowWarning")
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
                        .accessibilityIdentifier("welcome.cli.manualCommand")
                }
            }

            Spacer()
            HStack {
                Button("Skip") { step = .menuAndNotifications }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Continue") { step = .menuAndNotifications }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("welcome.cli.continue")
            }
        }
        .padding(24)
    }

    private var menuAndNotificationsStepView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Menu bar and notifications")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
            Text("Show EnvCloak in the menu bar and get notified when an agent asks for a key.")
                .foregroundStyle(ECToken.text.color)

            Toggle(
                "Show EnvCloak in the menu bar",
                isOn: Binding(
                    get: { session.showMenuBarExtra },
                    set: { session.setShowMenuBarExtra($0) }
                )
            )
            .accessibilityIdentifier("welcome.menuBar")

            Toggle(
                "Tell me when an agent asks for a key",
                isOn: Binding(
                    get: { notifyWhenAgentAsks },
                    set: { enabled in
                        notifyWhenAgentAsks = enabled
                        if enabled {
                            Task { await session.requestNotificationPermission() }
                        }
                    }
                )
            )
            .accessibilityIdentifier("welcome.notifications")

            Spacer()
            HStack {
                Button("Skip") { step = .firstRunScan }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Continue") { step = .firstRunScan }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("welcome.menu.continue")
            }
        }
        .padding(24)
    }
}
