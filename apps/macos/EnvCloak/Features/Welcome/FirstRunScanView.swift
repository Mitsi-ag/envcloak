import AppKit
import EnvCloakDesign
import EnvCloakKit
import Observation
import SwiftUI

@Observable @MainActor final class FirstRunScanModel {
    static let scanCommands = "envcloak import --scan ~ --machine --report\nenvcloak doctor --report"
    static let deletePlaintextCommand = "envcloak init --delete-plaintext"

    let session: VaultSession?
    let reportsDirectory: String?
    private let usesFixtureOnly: Bool
    var report: FirstRunReportView?
    var errorNotice: String?
    var copiedNotice: String?

    init(session: VaultSession? = nil, reportsDirectory: String? = nil, report: FirstRunReportView? = nil) {
        self.session = session
        self.reportsDirectory = reportsDirectory
        self.usesFixtureOnly = (report != nil && reportsDirectory == nil)
        self.report = report
    }

    func refresh() async {
        guard !usesFixtureOnly else { return }
        do {
            let loaded = try FirstRunReportReader.read(inDirectory: reportsDirectory)
            let changed = (loaded != nil && loaded != report)
            report = loaded
            errorNotice = nil
            if changed, let session, session.state.canReadMetadata {
                await session.items.refetch(.items)
                await session.projects.refetch(.projects)
            }
        } catch {
            errorNotice = "The first-run scan report could not be read. Run the scan command in Terminal again."
        }
    }

    func watch() async {
        guard !usesFixtureOnly else { return }
        while !Task.isCancelled {
            await refresh()
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
        }
    }

    func copyScanCommands(to board: NSPasteboard = .general) {
        if WorkspaceActions.copy(Self.scanCommands, to: board) {
            copiedNotice = "Copied the scan commands. Paste them into Terminal."
        }
    }

    func copyRotate(_ slug: DaemonText, to board: NSPasteboard = .general) {
        guard let command = MetadataRequest.rotateSlugCommand(slug) else {
            copiedNotice = TerminalCopy.refusalMessage
            return
        }
        if WorkspaceActions.copy(command, to: board) {
            copiedNotice = "Copied \(command.display). Run it in Terminal."
        }
    }

    func copyDeletePlaintext(_ directory: DaemonText, to board: NSPasteboard = .general) {
        guard let command = MetadataRequest.deletePlaintextCommand(directory) else {
            copiedNotice = TerminalCopy.refusalMessage
            return
        }
        if WorkspaceActions.copy(command, to: board) {
            copiedNotice = "Copied \(command.display). Run it in Terminal."
        }
    }

    func copyDefaultDeletePlaintext(to board: NSPasteboard = .general) {
        if WorkspaceActions.copy(Self.deletePlaintextCommand, to: board) {
            copiedNotice = "Copied \(Self.deletePlaintextCommand). Run it in Terminal."
        }
    }
}

struct FirstRunScanView: View {
    let model: FirstRunScanModel
    var onOpenProjects: () -> Void = {}
    var onDone: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let report = model.report {
                resultView(report)
            } else {
                waitingView
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(ECToken.background.color)
        .task { await model.watch() }
    }

    private var waitingView: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("First-run scan")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
            Text("Find every key on this Mac. The scan reads .env files, shell profiles, agent MCP configs and exports you name. It runs in Terminal, so macOS asks Terminal, not EnvCloak, for folder access.")
                .foregroundStyle(ECToken.text.color)
            VStack(alignment: .leading, spacing: 12) {
                Text(FirstRunScanModel.scanCommands)
                    .font(ECFont.martianMono(size: 12))
                    .foregroundStyle(ECToken.text.color)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("first-run.commands")
                HStack(spacing: 12) {
                    Button("Copy") { model.copyScanCommands() }
                    Button("Open Terminal") { WorkspaceActions.openTerminal() }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ECToken.raised.color)
            if let notice = model.copiedNotice ?? model.errorNotice {
                Text(notice)
                    .font(.callout)
                    .foregroundStyle(ECToken.secondary.color)
            }
            HStack(spacing: 16) {
                ECBusy(size: .large, color: ECToken.text.color)
                Text("Waiting for the scan in Terminal")
                    .font(.headline)
                    .foregroundStyle(ECToken.secondary.color)
            }
            .padding(.top, 8)
            Spacer()
        }
        .padding(24)
    }

    private func resultView(_ report: FirstRunReportView) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Spacer()
                ECRedaction(fontSize: 24)
                Spacer()
            }
            .frame(maxWidth: .infinity)
            .frame(height: 120)
            .background(ECToken.plate.color)
            .accessibilityIdentifier("first-run.hero")

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack(spacing: 24) {
                        figureCard(count: report.keys_found, label: "keys found", id: "first-run.figure.keys")
                        figureCard(count: report.projects, label: "projects", id: "first-run.figure.projects")
                        figureCard(count: report.already_leaked, label: "already leaked", id: "first-run.figure.leaked")
                        figureCard(count: report.plaintext_files, label: "plaintext files", id: "first-run.figure.plaintext")
                    }

                    if let notice = model.copiedNotice ?? model.errorNotice {
                        Text(notice)
                            .font(.callout)
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("first-run.notice")
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("By provider").font(.headline)
                        if report.providers.isEmpty {
                            Text("No providers detected yet.")
                                .foregroundStyle(ECToken.secondary.color)
                        } else {
                            ForEach(DisplayRow.of(report.providers)) { row in
                                Text(row.value.summaryLabel)
                                    .foregroundStyle(ECToken.text.color)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("By account").font(.headline)
                        if report.accounts.isEmpty {
                            Text("Owning accounts are not detected yet. You can add them per key.")
                                .foregroundStyle(ECToken.secondary.color)
                        } else {
                            ForEach(DisplayRow.of(report.accounts)) { row in
                                Text(row.value.summaryLabel)
                                    .foregroundStyle(ECToken.text.color)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Already leaked").font(.headline)
                        Label("Rotate these at the provider. EnvCloak cannot recall copies already sent to a model provider.", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(ECToken.warning.color)
                        if report.leaked.isEmpty {
                            Text("No leaked keys found in scanned files.")
                                .foregroundStyle(ECToken.secondary.color)
                        } else {
                            ForEach(DisplayRow.of(report.leaked)) { row in
                                let item = row.value
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack(spacing: 12) {
                                        Text(item.slug.escaped)
                                            .font(ECFont.martianMono(size: 12))
                                            .foregroundStyle(ECToken.text.color)
                                        Text(item.whereSummary)
                                            .foregroundStyle(ECToken.secondary.color)
                                        Spacer()
                                        if let url = MetadataRequest.safeLink(item.rotate_url) {
                                            Link("Open keys page", destination: url)
                                        }
                                        Button("Replace…") { model.copyRotate(item.slug) }
                                            .disabled(MetadataRequest.rotateSlugCommand(item.slug) == nil)
                                    }
                                    if MetadataRequest.rotateSlugCommand(item.slug) == nil {
                                        Text(TerminalCopy.refusalMessage)
                                            .font(.caption)
                                            .foregroundStyle(ECToken.warning.color)
                                    }
                                }
                                .padding(10)
                                .background(ECToken.raised.color)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Still in plain text").font(.headline)
                        Text("Runs envcloak init --delete-plaintext in Terminal. It needs your Recovery Kit confirmed first, keeps an encrypted backup, and leaves files that changed in the last 2 minutes.")
                            .foregroundStyle(ECToken.secondary.color)
                        if report.plaintext_projects.isEmpty {
                            Button("Remove plaintext") { model.copyDefaultDeletePlaintext() }
                        } else {
                            ForEach(DisplayRow.of(report.plaintext_projects)) { row in
                                let project = row.value
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack(spacing: 12) {
                                        Text(project.summaryLabel)
                                            .foregroundStyle(ECToken.text.color)
                                        Spacer()
                                        Button("Remove plaintext") { model.copyDeletePlaintext(project.dir) }
                                            .disabled(MetadataRequest.deletePlaintextCommand(project.dir) == nil)
                                    }
                                    if MetadataRequest.deletePlaintextCommand(project.dir) == nil {
                                        Text(TerminalCopy.refusalMessage)
                                            .font(.caption)
                                            .foregroundStyle(ECToken.warning.color)
                                    }
                                }
                                .padding(10)
                                .background(ECToken.raised.color)
                            }
                        }
                    }
                }
                .padding(24)
            }

            HStack {
                Spacer()
                Button("Done") { onDone() }
                Button("Open projects") { onOpenProjects() }
                    .buttonStyle(.borderedProminent)
            }
            .padding(16)
            .background(ECToken.raised.color)
        }
    }

    private func figureCard(count: UInt64, label: String, id: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(count)")
                .font(.title)
                .monospacedDigit()
                .foregroundStyle(ECToken.text.color)
            Text("\(count) \(label)")
                .font(.subheadline)
                .foregroundStyle(ECToken.secondary.color)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(id)
    }
}
