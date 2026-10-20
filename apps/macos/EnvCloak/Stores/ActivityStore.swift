import EnvCloakKit
import Foundation
import Observation

@Observable @MainActor final class ActivityStore: Store {
    private let client: (any WorkspaceClient)?
    private var generation = 0
    private(set) var entries: [AppAuditEntryView] = []
    private(set) var nextBeforeSeq: UInt64?
    private(set) var loadingMore = false
    private(set) var failure: EnvCloakError?
    var selectedSeq: UInt64?
    var verifySummary: String?
    var verifyIsOK: Bool?
    var verifying = false

    init(client: (any WorkspaceClient)?) {
        self.client = client
    }

    var hasMore: Bool {
        nextBeforeSeq != nil
    }

    var selectedEntry: AppAuditEntryView? {
        guard let seq = selectedSeq else { return nil }
        return entries.first(where: { $0.seq == seq })
    }

    func clear() {
        generation += 1
        entries = []
        nextBeforeSeq = nil
        loadingMore = false
        failure = nil
        selectedSeq = nil
        verifySummary = nil
        verifyIsOK = nil
        verifying = false
    }

    func refetch(_ change: Change) async {
        guard !change.isEmpty || failure != nil else { return }
        guard let client else { return }
        generation += 1
        let captured = generation
        do {
            let page = try await client.call(MetadataRequest.auditList(limit: 200))
            guard captured == generation, !Task.isCancelled else { return }
            entries = page.entries
            nextBeforeSeq = page.next_before_seq
            failure = nil
            if let seq = selectedSeq, !entries.contains(where: { $0.seq == seq }) {
                selectedSeq = entries.first?.seq
            }
        } catch {
            guard captured == generation, !Task.isCancelled else { return }
            entries = []
            nextBeforeSeq = nil
            failure = error as? EnvCloakError ?? .protocolError
        }
    }

    func loadMore() async {
        guard let cursor = nextBeforeSeq, !loadingMore, let client else { return }
        loadingMore = true
        let captured = generation
        defer { loadingMore = false }
        do {
            let page = try await client.call(MetadataRequest.auditList(limit: 200, beforeSeq: cursor))
            guard captured == generation, !Task.isCancelled else { return }
            let existingSeqs = Set(entries.map(\.seq))
            let additions = page.entries.filter { !existingSeqs.contains($0.seq) }
            entries.append(contentsOf: additions)
            nextBeforeSeq = additions.isEmpty ? nil : page.next_before_seq
            failure = nil
        } catch {
            guard captured == generation, !Task.isCancelled else { return }
            failure = error as? EnvCloakError ?? .protocolError
        }
    }

    func verifyLog() async {
        guard !verifying, let client else { return }
        verifying = true
        let captured = generation
        defer { verifying = false }
        do {
            let report = try await client.call(AuditVerify())
            guard captured == generation, !Task.isCancelled else { return }
            verifyIsOK = report.problems == 0 && report.first_problem == nil && !report.torn_tail
            verifySummary = Self.formatVerifySummary(report)
        } catch {
            guard captured == generation, !Task.isCancelled else { return }
            verifyIsOK = false
            verifySummary = "The audit log could not be verified."
        }
    }

    static func formatVerifySummary(_ report: AuditVerifyView) -> String {
        if let problem = report.first_problem {
            return switch problem.kind {
            case .altered:
                "Entry \(problem.seq) was changed after it was written."
            case .chainBroken:
                "Entry \(problem.seq) does not chain to the previous entry."
            case .missing:
                "Entry \(problem.seq) has a sequence gap."
            case .reordered:
                "Entry \(problem.seq) is out of sequence order."
            case .segmentDamaged:
                "Entry \(problem.seq) is in a damaged log segment."
            case .unreadable:
                "Entry \(problem.seq) could not be read."
            case .anchorMismatch:
                "Entry \(problem.seq) does not match the vault anchor."
            }
        }
        if report.torn_tail {
            return "The audit log has a torn tail (\(report.torn_bytes) bytes)."
        }
        if report.problems == 0 {
            if report.anchor.state == .matched {
                return "All \(report.entries) entries check out. The last one is anchored in the vault."
            }
            return "All \(report.entries) entries check out."
        }
        return "Audit log verification failed (\(report.problems) problems)."
    }
}
