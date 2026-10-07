import EnvCloakDesign
import SwiftUI

/// The About window, a stub until M3-17: the mark on its Ink field, the
/// version, what this build does not check yet, and the bundled font's
/// licence. The guarantees table SPEC §1.1 puts on the About screen arrives
/// with the screens that make its rows true; until then it says so.
struct AboutView: View {
    @State private var showsLicence = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ECReveal(module: 6)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 28)
                .background(ECToken.plate.color)
                .accessibilityIdentifier("about.mark")
            VStack(alignment: .leading, spacing: 12) {
                Text("EnvCloak")
                    .font(.title3)
                    .foregroundStyle(ECToken.text.color)
                Text("Version \(Self.version) (\(Self.build))")
                    .font(.callout)
                    .monospacedDigit()
                    .foregroundStyle(ECToken.secondary.color)
                    .accessibilityIdentifier("about.version")
                DevelopmentBanner()
                Text("The guarantees table arrives in a later build.")
                    .font(.callout)
                    .foregroundStyle(ECToken.secondary.color)
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
                    .frame(height: 220)
                    .background(ECToken.raised.color)
                    .accessibilityIdentifier("about.licence.text")
                }
            }
            .padding(24)
        }
        .frame(width: 420)
        .background(ECToken.background.color)
    }

    private static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
    }

    private static var build: String {
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
