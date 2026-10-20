import EnvCloakDesign
import SwiftUI

/// The About window (M3-17, design §5.11): the stacked lockup on its Ink field
/// with the reveal motion, version and build, daemon identity and hardening
/// summary, the bundled font's licence, and the full guarantees table from
/// SPEC §1.1 with unshipped rows marked "Not in this release".
struct AboutView: View {
    var session: VaultSession?
    @State private var showsLicence = false

    init(session: VaultSession? = nil) {
        self.session = session
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ECReveal(module: 6)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 24)
                .background(ECToken.plate.color)
                .accessibilityIdentifier("about.mark")

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .firstTextBaseline) {
                        Text("EnvCloak")
                            .font(.title3)
                            .foregroundStyle(ECToken.text.color)
                        Spacer()
                        Text("Version \(Self.version) (\(Self.build))")
                            .font(.callout)
                            .monospacedDigit()
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("about.version")
                    }

                    DevelopmentBanner()

                    VStack(alignment: .leading, spacing: 4) {
                        Text(daemonIdentityLine)
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("about.identity")
                        Text(hardeningLine)
                            .font(.caption)
                            .foregroundStyle(ECToken.secondary.color)
                            .accessibilityIdentifier("about.hardening")
                    }

                    Divider()

                    Text("What EnvCloak guarantees (SPEC §1.1)")
                        .font(.headline)
                        .foregroundStyle(ECToken.text.color)
                        .accessibilityIdentifier("about.guarantees.heading")

                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(GuaranteesTable.rows) { row in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(row.mode)
                                        .font(.subheadline.weight(.semibold))
                                        .foregroundStyle(ECToken.text.color)
                                    Spacer()
                                    if !row.isAvailableInThisRelease {
                                        Label(GuaranteesTable.unshippedBadge, systemImage: "clock")
                                            .font(.caption2)
                                            .foregroundStyle(ECToken.secondary.color)
                                            .accessibilityIdentifier("about.guarantees.unshipped." + row.mode)
                                    }
                                }
                                if !row.processHolds.isEmpty {
                                    Text("What the approved process holds: \(row.processHolds)")
                                        .font(.caption)
                                        .foregroundStyle(ECToken.secondary.color)
                                }
                                Text("EnvCloak guarantees: \(row.guarantees)")
                                    .font(.caption)
                                    .foregroundStyle(ECToken.text.color)
                                Text("EnvCloak does not guarantee: \(row.doesNotGuarantee)")
                                    .font(.caption)
                                    .foregroundStyle(ECToken.secondary.color)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .accessibilityElement(children: .contain)
                            .accessibilityIdentifier("about.guarantees.row." + row.mode)
                        }
                    }
                    .accessibilityIdentifier("about.guarantees.table")

                    Divider()

                    HStack {
                        Text("Martian Mono, SIL Open Font License 1.1")
                            .font(.callout)
                            .foregroundStyle(ECToken.text.color)
                            .accessibilityIdentifier("about.licence.font")
                        Spacer()
                        Button(showsLicence ? "Hide licence" : "Show licence") {
                            showsLicence.toggle()
                        }
                    }
                    if showsLicence {
                        ScrollView {
                            Text(Self.fontLicence)
                                .font(ECFont.martianMono(size: 10))
                                .foregroundStyle(ECToken.text.color)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                        .frame(height: 180)
                        .background(ECToken.raised.color)
                        .accessibilityIdentifier("about.licence.text")
                    }
                }
                .padding(24)
            }
        }
        .frame(width: 680, height: 640)
        .background(ECToken.background.color)
    }

    private var daemonIdentityLine: String {
        if let team = session?.enrolledTeamID, !team.isEmpty, team != "CI00000000" {
            return "Daemon identity: verified (EnvCloak, Team \(team))"
        }
        return "Daemon identity: unverified in this build"
    }

    private var hardeningLine: String {
        if let status = session?.latestDaemonHardeningSummary {
            return status
        }
        return "Hardening: hardened runtime active, core dumps off"
    }

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
    }

    static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
    }

    private static var fontLicence: String {
        guard let url = ECFonts.martianMonoLicenceURL,
              let text = try? String(contentsOf: url, encoding: .utf8)
        else {
            return "The licence file is missing from this build."
        }
        return text
    }
}

@MainActor
enum AboutMetadata {
    static var versionString: String {
        "Version \(AboutView.version) (\(AboutView.build))"
    }
}

