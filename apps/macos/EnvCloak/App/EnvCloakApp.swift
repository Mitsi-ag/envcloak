import EnvCloakDesign
import EnvCloakKit
import SwiftUI

/// The macOS app (SPEC §12). Task M3-02 lays out the bundle with a
/// placeholder main window and an About stub; the screens arrive with
/// M3-05 onwards. The app reads nothing from how it was started: no launch
/// argument, environment variable, standard stream or defaults domain
/// (docs/APP.md "The app run by an agent", checked by
/// scripts/macos/check-swift.sh).
@main
struct EnvCloakApp: App {
    init() {
        let fonts: AppEvent = ECFonts.martianMonoRegistered ? .fontsRegistered : .fontsMissing
        ECLog.logger(.app).notice(
            "\(AppEvent.launched.logToken, privacy: .public) \(fonts.logToken, privacy: .public)"
        )
    }

    var body: some Scene {
        Window("EnvCloak", id: WindowID.main) {
            PlaceholderView()
        }
        .defaultSize(width: 720, height: 480)
        .commands {
            CommandGroup(replacing: .appInfo) {
                AboutCommand()
            }
            CommandGroup(replacing: .newItem) {}
        }

        Window("About EnvCloak", id: WindowID.about) {
            AboutView()
        }
        .windowResizability(.contentSize)
        .restorationBehavior(.disabled)
    }
}

/// The scenes' identifiers.
enum WindowID {
    static let main = "main"
    static let about = "about"
}

/// The app's log events: fixed words, the only text the app's log holds.
enum AppEvent: String, LogToken {
    case launched = "launched"
    case fontsRegistered = "fonts-registered"
    case fontsMissing = "fonts-missing"
}

/// "About EnvCloak" in the app menu opens the About window.
private struct AboutCommand: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("About EnvCloak") {
            openWindow(id: WindowID.about)
        }
    }
}
