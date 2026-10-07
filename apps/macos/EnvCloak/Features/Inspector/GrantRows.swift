import EnvCloakDesign
import EnvCloakKit
import SwiftUI

struct GrantRows: View {
    let session: VaultSession
    let directory: DaemonText?
    let slug: DaemonText?
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            let grants = session.grants.rows.filter {
                (directory == nil || $0.project_dir == directory) &&
                (slug == nil || $0.bindings.contains { $0.slug == slug }) && session.grants.remaining($0) > 0
            }
            VStack(alignment: .leading, spacing: 8) {
                if session.grants.failure != nil { Text("Grants could not be refreshed. Try again.") }
                else if grants.isEmpty { Text("No grants in force").foregroundStyle(ECToken.secondary.color) }
                ForEach(grants, id: \.id) { grant in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(grant.label?.escaped ?? grant.kind.rawValue.capitalized)
                            Text(grant.project_dir.escaped).font(.caption)
                            Text("\(session.grants.remaining(grant)) seconds left").font(.caption)
                        }
                        Spacer()
                        Button("Revoke") { Task { await session.revoke(grant.id) } }
                            .disabled(session.actionInProgress || session.state != .ready)
                    }
                }
            }
        }
    }
}
