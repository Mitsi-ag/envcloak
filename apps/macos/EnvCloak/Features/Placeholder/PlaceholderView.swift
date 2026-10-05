import EnvCloakDesign
import SwiftUI

/// The main window until the real screens land (M3-05). It says plainly
/// that nothing is managed here yet (SPEC §1.1: a feature that has not
/// shipped is shown as unavailable, never implied).
struct PlaceholderView: View {
    var body: some View {
        VStack(spacing: 20) {
            ECSymbol(module: 8, equalsColor: ECToken.text.color, blockColor: ECToken.text.color)
                .accessibilityHidden(true)
            Text("EnvCloak")
                .font(.title2)
                .foregroundStyle(ECToken.text.color)
            Text("Projects and keys arrive in a later build. Until then, EnvCloak works from Terminal.")
                .font(.body)
                .foregroundStyle(ECToken.secondary.color)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Text("envcloak status")
                .font(ECFont.martianMono(size: 12))
                .foregroundStyle(ECToken.text.color)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(ECToken.raised.color, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .textSelection(.enabled)
        }
        .padding(32)
        .frame(minWidth: 480, maxWidth: .infinity, minHeight: 320, maxHeight: .infinity)
        .background(ECToken.background.color)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("main.placeholder")
    }
}
