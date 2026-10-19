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
    let session: VaultSession
    @State private var step: WelcomeStep
    @State private var scanModel: FirstRunScanModel
    @Environment(\.dismiss) private var dismiss

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
                        Spacer()
                        HStack {
                            Spacer()
                            Button("Continue") { step = .backgroundItem }
                                .buttonStyle(.borderedProminent)
                        }
                    }
                    .padding(24)
                }
            case .backgroundItem:
                stepContainer(
                    title: "Background process",
                    bodyText: "EnvCloak keeps your vault in a background process that starts when you log in. It holds the vault key while it is unlocked, and nothing else does.",
                    next: .vault
                )
            case .vault:
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
                    }
                }
                .padding(24)
            case .cliTool:
                stepContainer(
                    title: "Command-line tool",
                    bodyText: "Agents and your terminal use the envcloak command.",
                    next: .menuAndNotifications
                )
            case .menuAndNotifications:
                stepContainer(
                    title: "Menu bar and notifications",
                    bodyText: "Show EnvCloak in the menu bar and get notified when an agent asks for a key.",
                    next: .firstRunScan
                )
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
    }

    private func stepContainer(title: String, bodyText: String, next: WelcomeStep) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title)
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
            Text(bodyText)
                .foregroundStyle(ECToken.text.color)
            Spacer()
            HStack {
                Spacer()
                Button("Continue") { step = next }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
    }
}
