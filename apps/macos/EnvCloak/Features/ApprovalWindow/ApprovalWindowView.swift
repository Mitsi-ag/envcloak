import AppKit
import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct ApprovalWindowView: View {
    @Bindable var model: ApprovalWindowModel
    @Environment(\.dismiss) private var dismiss

    init(model: ApprovalWindowModel) {
        self.model = model
    }

    var body: some View {
        VStack(spacing: 0) {
            if let descriptor = model.descriptor {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        headerSection(descriptor)
                            .accessibilitySortPriority(7)
                            .accessibilityIdentifier("approval.section.header")
                        commandSection(descriptor)
                            .accessibilitySortPriority(6)
                            .accessibilityIdentifier("approval.section.command")
                        projectSection(descriptor)
                            .accessibilitySortPriority(5)
                            .accessibilityIdentifier("approval.section.project")
                        keysSection(descriptor)
                            .accessibilitySortPriority(4)
                            .accessibilityIdentifier("approval.section.keys")
                        accessSection(descriptor)
                            .accessibilitySortPriority(3)
                            .accessibilityIdentifier("approval.section.access")
                        evidenceSection(descriptor)
                            .accessibilitySortPriority(2)
                    }
                    .padding(24)
                }
                footerSection(descriptor)
                    .accessibilitySortPriority(1)
                    .accessibilityIdentifier("approval.section.footer")
            } else if model.outcome == .vaultLocked {
                VStack(spacing: 16) {
                    Text("EnvCloak locked, so this request ended. Agents ask again after you unlock.")
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityIdentifier("approval.outcome")
                    Button("Close") { dismiss() }
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 16) {
                    Text("Nothing waiting. Requests from Claude Code, Codex and other agents appear here.")
                        .foregroundStyle(ECToken.secondary.color)
                    Button("Close") { dismiss() }
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(width: 560)
        .frame(minHeight: 520, maxHeight: 760)
        .background(ECToken.background.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approval.window")
        .onKeyPress(.return) {
            .handled
        }
        .sheet(isPresented: $model.showFullCommand) {
            if let descriptor = model.descriptor {
                fullCommandSheet(descriptor)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            model.noteWindowBecameKey()
        }
        .task(id: model.session.activeApprovalRequestId) {
            if model.descriptor == nil || (model.session.activeApprovalRequestId != nil && model.descriptor?.request != model.session.activeApprovalRequestId) {
                await model.load(requestId: model.session.activeApprovalRequestId)
            }
        }
        .task {
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                model.checkExpiry()
            }
        }
    }

    private func headerSection(_ descriptor: PendingDescriptor) -> some View {
        let agentName = NotificationManager.subjectLabel(descriptor.subject)
        let cmd = ApprovalWindowModel.headerCommand(descriptor.argv)
        let projectName = MetadataRequest.basename(descriptor.project.dir)
        let count = model.requestedBindings.count
        let keyWord = count == 1 ? "1 key" : "\(count) keys"

        return HStack(alignment: .top, spacing: 16) {
            ECApprovalMark(waiting: model.outcome == .signing, module: 6)
                .accessibilityIdentifier("approval.mark")
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Text("\(agentName) wants to run")
                        .font(.title3)
                        .foregroundStyle(ECToken.text.color)
                    Text(cmd)
                        .font(ECFont.martianMono(size: 13))
                        .foregroundStyle(ECToken.text.color)
                }
                .accessibilityIdentifier("approval.header.title")
                Text("in \(projectName) with \(keyWord)")
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("approval.header.subtitle")
                HStack(spacing: 8) {
                    Label(Self.subjectBadgeTitle(descriptor.subject.kind), systemImage: ApprovalsView.subjectSymbol(descriptor.subject.kind))
                        .font(.subheadline)
                        .foregroundStyle(ECToken.secondary.color)
                    if model.requestedBindings.contains(where: { $0.classificationView == .live }) {
                        Label("Live key", systemImage: "bolt.fill")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(ECToken.text.color)
                            .accessibilityLabel("Live key")
                    }
                    if model.requestedBindings.contains(where: { $0.first_use }) {
                        Label("First use", systemImage: "sparkles")
                            .font(.subheadline)
                            .foregroundStyle(ECToken.secondary.color)
                    }
                }
            }
        }
    }

    private func commandSection(_ descriptor: PendingDescriptor) -> some View {
        let rendered = CanonicalStatement.renderArgv(descriptor.argv)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Command")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            VStack(alignment: .leading, spacing: 4) {
                ForEach(rendered.truncatedLines) { line in
                    Text(line.formatted)
                        .font(ECFont.martianMono(size: 12))
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityLabel(Self.argvAccessibilityLabel(index: line.index, text: line.text))
                        .accessibilityIdentifier("approval.argv.\(line.index)")
                }
                if rendered.isTruncated {
                    HStack(spacing: 12) {
                        Text("(\(rendered.hiddenByteCount) more bytes)")
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("approval.argv.omitted")
                        Button("Show full command") {
                            model.showFullCommand = true
                        }
                        .accessibilityIdentifier("approval.argv.showFull")
                    }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            Text("Approving covers the full command line, including any part not shown.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
        }
    }

    private func projectSection(_ descriptor: PendingDescriptor) -> some View {
        let projectName = MetadataRequest.basename(descriptor.project.dir)
        let shortHash = String(descriptor.project.manifest_sha256.escaped.prefix(12))
        return VStack(alignment: .leading, spacing: 6) {
            Text("Project")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            Text(projectName)
                .foregroundStyle(ECToken.text.color)
            Text(descriptor.project.dir.escaped)
                .font(ECFont.martianMono(size: 12))
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("approval.project.dir")
            HStack(spacing: 8) {
                Text("Manifest SHA-256: \(shortHash)")
                    .font(ECFont.martianMono(size: 10))
                    .foregroundStyle(ECToken.secondary.color)
                Button("Copy") {
                    _ = WorkspaceActions.copy(descriptor.project.manifest_sha256.escaped)
                }
                .font(.caption)
            }
            if descriptor.project.new_project {
                Text("New project: EnvCloak has not seen this folder before.")
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
            }
        }
    }

    private func keysSection(_ descriptor: PendingDescriptor) -> some View {
        let requested = model.requestedBindings
        let covered = model.coveredBindings
        return VStack(alignment: .leading, spacing: 12) {
            Text("Keys")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            ForEach(Array(requested.enumerated()), id: \.offset) { _, binding in
                bindingRow(binding, proposals: descriptor.proposals, manifest: descriptor.project.manifest)
            }
            if !covered.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Already granted in this project. This approval includes them too.")
                        .font(.subheadline)
                        .foregroundStyle(ECToken.secondary.color)
                        .accessibilityIdentifier("approval.covered.heading")
                    ForEach(Array(covered.enumerated()), id: \.offset) { _, item in
                        let envEscaped = item.env_name.escaped
                        let isLive = item.classificationView == .live
                        let isTicked = model.tickedLiveVariables.contains(envEscaped)
                        HStack(spacing: 8) {
                            if model.isLiveGuarded && isLive {
                                Toggle(
                                    "Allow live key",
                                    isOn: Binding(
                                        get: { isTicked },
                                        set: { model.toggleLiveKey(envEscaped, isTicked: $0) }
                                    )
                                )
                                .accessibilityLabel(Self.liveTickAccessibilityLabel(envName: envEscaped, slug: item.slug.escaped))
                                .accessibilityIdentifier("approval.live." + envEscaped)
                            }
                            Text(envEscaped)
                                .font(ECFont.martianMono(size: 12))
                                .foregroundStyle(ECToken.text.color)
                            Text("→")
                                .foregroundStyle(ECToken.secondary.color)
                            Text(item.slug.escaped)
                                .font(ECFont.martianMono(size: 12))
                                .foregroundStyle(ECToken.secondary.color)
                            Spacer()
                            Text(item.classificationView.rawValue.capitalized)
                                .font(.caption)
                                .foregroundStyle(ECToken.secondary.color)
                                .accessibilityLabel(KeysView.classBadgeAccessibilityLabel(item.classificationView))
                        }
                        .accessibilityElement(children: .contain)
                        .accessibilityIdentifier("approval.covered." + envEscaped)
                    }
                }
                .padding(.top, 4)
            }
        }
    }

    private func bindingRow(_ binding: BindingSummary, proposals: [Proposal], manifest: DaemonText) -> some View {
        let envEscaped = binding.env_name.escaped
        let isLive = binding.classificationView == .live
        let isTicked = model.tickedLiveVariables.contains(envEscaped)
        let matchingProposal = proposals.first { $0.env_name == binding.env_name }

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                if model.isLiveGuarded && isLive {
                    Toggle(
                        "Allow live key",
                        isOn: Binding(
                            get: { isTicked },
                            set: { model.toggleLiveKey(envEscaped, isTicked: $0) }
                        )
                    )
                    .accessibilityLabel(Self.liveTickAccessibilityLabel(envName: envEscaped, slug: binding.slug.escaped))
                    .accessibilityIdentifier("approval.live." + envEscaped)
                }
                Text(envEscaped)
                    .font(ECFont.martianMono(size: 12))
                    .foregroundStyle(ECToken.text.color)
                Text("→")
                    .foregroundStyle(ECToken.secondary.color)
                Text(binding.slug.escaped)
                    .font(ECFont.martianMono(size: 12))
                    .foregroundStyle(ECToken.secondary.color)
                Spacer()
                Label(
                    binding.classificationView.rawValue.capitalized,
                    systemImage: KeysView.classBadgeSymbol(binding.classificationView)
                )
                .font(.subheadline)
                .foregroundStyle(isLive ? ECToken.text.color : ECToken.secondary.color)
                .accessibilityLabel(KeysView.classBadgeAccessibilityLabel(binding.classificationView))
                if binding.first_use {
                    Text("First use")
                        .font(.caption)
                        .foregroundStyle(ECToken.secondary.color)
                }
            }
            if let proposal = matchingProposal {
                if proposal.canApplyAutomatically {
                    HStack(spacing: 12) {
                        Text("Test key available: \(proposal.testReferenceDisplay).")
                            .font(.caption)
                            .foregroundStyle(ECToken.info.color)
                            .accessibilityIdentifier("approval.proposal.label." + envEscaped)
                        Button("Use test key instead") {
                            Task { await model.useTestKeyInstead(proposal) }
                        }
                        .font(.caption)
                        .accessibilityIdentifier("approval.proposal.use." + envEscaped)
                    }
                } else {
                    HStack(spacing: 12) {
                        Text(proposal.advice(manifest: manifest))
                            .font(.caption)
                            .foregroundStyle(ECToken.info.color)
                            .accessibilityIdentifier("approval.proposal.label." + envEscaped)
                        Button("Copy advice") {
                            _ = WorkspaceActions.copy(proposal.advice(manifest: manifest))
                        }
                        .font(.caption)
                        .accessibilityIdentifier("approval.proposal.copy." + envEscaped)
                    }
                }
            }
        }
        .padding(10)
        .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approval.binding." + envEscaped)
    }

    private func accessSection(_ descriptor: PendingDescriptor) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Access")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            Picker("Access duration", selection: $model.durationChoice) {
                ForEach(model.availableDurationChoices) { choice in
                    Text(choice.rawValue).tag(choice)
                }
            }
            .accessibilityIdentifier("approval.duration")
            if let standingWarning = model.standingWarningText {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(ECToken.warning.color)
                        .accessibilityHidden(true)
                    Text(standingWarning)
                        .font(.caption)
                        .foregroundStyle(ECToken.warning.color)
                        .accessibilityIdentifier("approval.standing.warning")
                }
            }
            Text("Inject: the command and everything it starts hold these keys while they run. Output is masked.")
                .font(.subheadline)
                .foregroundStyle(ECToken.secondary.color)
            Text("Everything in this process tree gets these keys until it ends or the time runs out, including test code, install scripts and prompt-injected turns.")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("approval.meaning")
        }
    }

    private func evidenceSection(_ descriptor: PendingDescriptor) -> some View {
        let exe = descriptor.subject.root.exe?.escaped ?? "unknown"
        return VStack(alignment: .leading, spacing: 4) {
            Text("Evidence")
                .font(.headline)
                .foregroundStyle(ECToken.text.color)
            Text("PID \(descriptor.subject.caller_pid) · Root PID \(descriptor.subject.root.pid) · Start \(descriptor.subject.root.start_time)")
                .font(.caption)
                .foregroundStyle(ECToken.secondary.color)
            Text("Executable: \(exe)")
                .font(ECFont.martianMono(size: 10))
                .foregroundStyle(ECToken.secondary.color)
            Text("Request ID: \(descriptor.request.escaped)")
                .font(ECFont.martianMono(size: 10))
                .foregroundStyle(ECToken.secondary.color)
            Text("Nonce: \(descriptor.nonce.escaped)")
                .font(ECFont.martianMono(size: 10))
                .foregroundStyle(ECToken.secondary.color)
                .accessibilityIdentifier("approval.evidence.nonce")
            Text("Created \(descriptor.created_secs) · Expires in \(descriptor.expires_in_secs)s")
                .font(.caption.monospacedDigit())
                .foregroundStyle(ECToken.secondary.color)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("approval.evidence")
    }

    private func footerSection(_ descriptor: PendingDescriptor) -> some View {
        let agentName = NotificationManager.subjectLabel(descriptor.subject)
        let projectName = MetadataRequest.basename(descriptor.project.dir)
        let count = model.requestedBindings.count
        let keyWord = count == 1 ? "1 key" : "\(count) keys"
        let rem = model.remainingSecs
        let mins = rem / 60
        let secs = rem % 60
        let clockText = String(format: "%d:%02d", mins, secs)

        return VStack(alignment: .leading, spacing: 8) {
            if let outcomeBanner = Self.outcomeText(model.outcome, agent: agentName, project: projectName, keys: keyWord, durationWords: model.durationChoice.words) {
                HStack(spacing: 12) {
                    Text(outcomeBanner)
                        .font(.subheadline)
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityIdentifier("approval.outcome")
                    Spacer()
                    if case .approved(let grantId, _) = model.outcome {
                        Button("Revoke") {
                            Task { await model.session.revoke(grantId) }
                        }
                        .accessibilityIdentifier("approval.outcome.revoke")
                    }
                    if model.outcome == .expired {
                        Button("Close") { dismiss() }
                            .accessibilityIdentifier("approval.outcome.close")
                    }
                }
            }
            if let reason = model.disabledReasonText, model.outcome == .pending {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("approval.disabled.reason")
            }
            HStack(spacing: 12) {
                Text("Expires in \(clockText)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityLabel("Expires in \(mins) minutes")
                    .accessibilityIdentifier("approval.expires")
                Spacer()
                Button("Not now") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("approval.notNow")
                Button("Deny") {
                    Task { await model.deny() }
                }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(model.outcome == .signing || model.isExpired)
                .accessibilityIdentifier("approval.deny")
                Button(model.session.approveButtonTitle) {
                    Task { await model.approve() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canApprove)
                .accessibilityIdentifier("approval.approve")
            }
        }
        .padding(16)
        .background(ECToken.raised.color)
    }

    private func fullCommandSheet(_ descriptor: PendingDescriptor) -> some View {
        let rendered = CanonicalStatement.renderArgv(descriptor.argv)
        return VStack(alignment: .leading, spacing: 16) {
            Text("Full command")
                .font(.title3)
                .foregroundStyle(ECToken.text.color)
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(rendered.allLines) { line in
                        Text(line.formatted)
                            .font(ECFont.martianMono(size: 12))
                            .foregroundStyle(ECToken.text.color)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(12)
            }
            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            HStack {
                Spacer()
                Button("Done") { model.showFullCommand = false }
            }
        }
        .padding(24)
        .frame(width: 520, height: 420)
        .background(ECToken.background.color)
    }

    static let readingOrderSections = [
        "header",
        "command",
        "project",
        "keys",
        "access",
        "evidence",
        "footer",
    ]

    static func liveTickAccessibilityLabel(envName: String, slug: String) -> String {
        let spokenSlug = slug.replacingOccurrences(of: "/", with: " slash ")
        return "Allow live key \(envName), \(spokenSlug)"
    }

    static func argvAccessibilityLabel(index: Int, text: String) -> String {
        let spoken = text.replacing(#/\\u\{([0-9A-Fa-f]+)\}/#) { match in
            "backslash u, \(match.output.1.uppercased())"
        }
        return "Argument \(index): \(spoken)"
    }

    static func subjectBadgeTitle(_ kind: SubjectKind) -> String {
        switch kind {
        case .agent: "Agent"
        case .terminal: "Terminal"
        case .unknown: "Unknown process"
        }
    }

    static func outcomeText(
        _ outcome: ApprovalOutcome,
        agent: String,
        project: String,
        keys: String,
        durationWords: String
    ) -> String? {
        switch outcome {
        case .pending:
            return nil
        case .signing:
            return "Touch the sensor to approve, or press Escape."
        case .approved:
            return "Approved for \(durationWords). \(agent) can run in \(project) with \(keys)."
        case .cancelled:
            return "Not approved. The request is still waiting."
        case .authFailed:
            return "Touch ID did not match. Try again, or use your password."
        case .denied:
            return "Denied. \(agent) was told no."
        case .expired:
            return "This request expired. \(agent) was told it timed out."
        case .statementChanged:
            return "The request changed while you read it. Nothing was approved. Read it again."
        case .liveNotTicked:
            return "Tick each live key to approve."
        case .vaultLocked:
            return "EnvCloak locked, so this request ended. Agents ask again after you unlock."
        case .proposalApplied(_, _):
            return "This edits envcloak.toml to use the test key and denies this request. \(agent)'s next run asks for the test key."
        case .failed(let message):
            return message
        }
    }
}
