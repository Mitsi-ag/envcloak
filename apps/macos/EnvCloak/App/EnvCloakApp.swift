import EnvCloakDesign
import EnvCloakKit
import SwiftUI

/// The EU-0 metadata workspace. Launch input never selects a vault or action.
@main
struct EnvCloakApp: App {
    #if ENVCLOAK_SCREEN_TESTS
    // A compile-only test host. It never connects to the person's daemon.
    @State private var session = ScreenTestBootstrap.session()
    #else
    @State private var session = VaultSession.live()
    #endif
    init() {
        let fonts: AppEvent = ECFonts.martianMonoRegistered ? .fontsRegistered : .fontsMissing
        ECLog.logger(.app).notice(
            "\(AppEvent.launched.logToken, privacy: .public) \(fonts.logToken, privacy: .public)"
        )
    }

    var body: some Scene {
        Window("EnvCloak", id: WindowID.main) {
            MainView(session: session)
                #if ENVCLOAK_SCREEN_TESTS
                .task { await ScreenTestBootstrap.positionWindow() }
                #endif
        }
        .defaultSize(width: 1180, height: 740)
        .commands {
            CommandGroup(replacing: .appInfo) {
                AboutCommand()
            }
            CommandGroup(replacing: .newItem) {}
            SidebarCommands()
            InspectorCommands()
            WorkspaceCommands()
        }

        // Opened from the app menu only: no second "About EnvCloak" item in
        // the Window menu, which SwiftUI adds for a Window scene otherwise.
        Window("About EnvCloak", id: WindowID.about) {
            AboutView()
        }
        .windowResizability(.contentSize)
        .restorationBehavior(.disabled)
        .commandsRemoved()
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
