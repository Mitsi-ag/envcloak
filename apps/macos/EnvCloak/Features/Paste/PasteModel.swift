import AppKit
import EnvCloakKit
import Observation

@Observable @MainActor final class PasteModel {
    @ObservationIgnored private var draft: PasteDraft?
    @ObservationIgnored private var inspectTask: Task<Void, Never>?
    var ask: AskSummary?
    var stagedId: DaemonText?
    var inspection: AppPasteInspectView?
    var name = ""
    var account = ""
    var variable = ""
    var count = 0
    var envName: String?
    var droppedLineEnding = false
    var notice: String?
    var clipboardNotice: String?
    var saved: AddedView?
    var busy = false

    init(ask: AskSummary? = nil) {
        self.ask = ask
        if let askAccount = ask?.account?.escaped {
            self.account = askAccount
        }
    }

    func receive(_ text: inout String) {
        inspectTask?.cancel()
        inspectTask = nil
        draft = nil; stagedId = nil; inspection = nil
        count = 0; envName = nil; notice = nil; saved = nil; droppedLineEnding = false
        do {
            let incoming = try PasteDraft(taking: &text)
            count = incoming.characters
            envName = incoming.envName
            droppedLineEnding = incoming.droppedLineEnding
            draft = consume incoming
        } catch PasteError.multipleLines {
            notice = "This looks like several lines of an env file. Import files with envcloak import instead."
        } catch { notice = "The key could not be read. Paste one nonempty value of at most 64 KiB." }
    }

    func startInspect(_ session: VaultSession) {
        inspectTask?.cancel()
        guard envName == nil, count > 0 else { return }
        inspectTask = Task { await self.inspect(session) }
    }

    func inspect(_ session: VaultSession) async {
        guard envName == nil, stagedId == nil, draft != nil else { return }
        do {
            let stage = try await session.beginPasteStage()
            guard let incoming = draft.take() else { return }
            let info = try await session.inspectPasteStage(
                stage: stage.stage,
                secret: incoming.value,
                daemonEphPubHex: MetadataRequest.raw(stage.daemon_eph_pub)
            )
            stagedId = stage.stage
            inspection = info
        } catch {
            // Leave `draft` intact when `beginPasteStage` is unavailable so `save` can proceed.
        }
    }

    func useEnvLine() {
        guard var incoming = draft.take() else { return }
        do {
            try incoming.useEnvLine()
            variable = incoming.envName ?? ""
            count = incoming.characters
            envName = nil
            draft = consume incoming
        } catch { count = 0; envName = nil; notice = "The env line has no value." }
    }

    func keepPasted() { envName = nil }

    func save(_ session: VaultSession) async {
        if let task = inspectTask {
            inspectTask = nil
            await task.value
        }
        guard !busy, envName == nil, (stagedId != nil || draft != nil) else { return }
        busy = true; notice = nil
        defer { busy = false; count = 0 }
        do {
            if let stage = stagedId {
                stagedId = nil
                _ = draft.take()
                saved = try await session.commitPasteStage(
                    stage: stage,
                    slug: name.isEmpty ? nil : name,
                    provider: inspection?.provider?.escaped ?? ask?.provider?.escaped,
                    account: account.isEmpty ? nil : account,
                    envHint: variable.isEmpty ? nil : variable,
                    ask: ask?.ask
                )
            } else if let incoming = draft.take() {
                do {
                    let stage = try await session.beginPasteStage()
                    let info = try await session.inspectPasteStage(
                        stage: stage.stage,
                        secret: incoming.value,
                        daemonEphPubHex: MetadataRequest.raw(stage.daemon_eph_pub)
                    )
                    inspection = info
                    saved = try await session.commitPasteStage(
                        stage: stage.stage,
                        slug: name.isEmpty ? nil : name,
                        provider: info.provider?.escaped ?? ask?.provider?.escaped,
                        account: account.isEmpty ? nil : account,
                        envHint: variable.isEmpty ? nil : variable,
                        ask: ask?.ask
                    )
                } catch EnvCloakError.rpc(let kind, _) where kind == .methodNotFound || kind == .roleDenied {
                    saved = try await session.add(ItemsAdd(
                        value: incoming.takeValue(),
                        slug: name.isEmpty ? nil : name,
                        account: account.isEmpty ? nil : account,
                        envHint: variable.isEmpty ? nil : variable
                    ))
                }
            }
            if saved != nil, ask != nil {
                session.activeAsk = nil
            }
        } catch {
            // The request may have committed before a connection failed.
            notice = "The save outcome could not be confirmed. Check Keys before pasting again. Names shaped like a key are refused."
        }
    }

    func decline(_ session: VaultSession) async -> Bool {
        guard let askId = ask?.ask, !busy else { return false }
        busy = true
        defer { busy = false }
        return await session.declineAsk(askId)
    }

    func reset() {
        inspectTask?.cancel()
        inspectTask = nil
        draft = nil; stagedId = nil; inspection = nil
        name = ""; account = ask?.account?.escaped ?? ""; variable = ""; count = 0
        envName = nil; saved = nil; notice = nil; clipboardNotice = nil; droppedLineEnding = false
    }
}

