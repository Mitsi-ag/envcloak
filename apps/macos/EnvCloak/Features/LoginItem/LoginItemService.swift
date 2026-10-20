import Darwin
import EnvCloakKit
import Foundation
import Observation
import ServiceManagement

enum LoginItemStatus: String, Equatable, Sendable {
    case notRegistered = "not_registered"
    case enabled = "enabled"
    case requiresApproval = "requires_approval"
    case notFound = "not_found"

    var statusLabel: String {
        switch self {
        case .enabled: "Enabled"
        case .requiresApproval: "Background item disabled in Login Items"
        case .notRegistered: "Not enabled"
        case .notFound: "App bundle not found in /Applications"
        }
    }
}

protocol LoginItemService: Sendable {
    func agentStatus() -> LoginItemStatus
    func registerAgent() throws
    func unregisterAgent() throws
    func mainAppStatus() -> LoginItemStatus
    func setMainAppEnabled(_ enabled: Bool) throws
    func openSystemSettingsLoginItems()
}

struct SystemLoginItemService: LoginItemService {
    static let agentPlistName = "ai.envcloak.agent.plist"

    private static func mapStatus(_ status: SMAppService.Status) -> LoginItemStatus {
        switch status {
        case .notRegistered: .notRegistered
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .notFound
        @unknown default: .notRegistered
        }
    }

    func agentStatus() -> LoginItemStatus {
        let service = SMAppService.agent(plistName: Self.agentPlistName)
        return Self.mapStatus(service.status)
    }

    func registerAgent() throws {
        let service = SMAppService.agent(plistName: Self.agentPlistName)
        try service.register()
    }

    func unregisterAgent() throws {
        let service = SMAppService.agent(plistName: Self.agentPlistName)
        try service.unregister()
    }

    func mainAppStatus() -> LoginItemStatus {
        Self.mapStatus(SMAppService.mainApp.status)
    }

    func setMainAppEnabled(_ enabled: Bool) throws {
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }

    func openSystemSettingsLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }
}

@Observable @MainActor final class LoginItemController {
    static let requiresApprovalBanner = "Background item disabled in Login Items"
    static let approvalBannerText = requiresApprovalBanner
    static let openLoginItemsTitle = "Open Login Items"
    static let cliAgentPlistRelativePath = "Library/LaunchAgents/ai.envcloak.envcloakd.plist"
    static let stateFileRelativePath = "Library/Application Support/EnvCloak/app/login-item-bundle-path.json"

    private let service: any LoginItemService
    private let cliAgentDetector: @MainActor () -> Bool
    private let cliDaemonUninstaller: @MainActor () async throws -> Void
    private let bundlePathProvider: @MainActor () -> String
    private let stateFileURL: URL?
    var lastRegisteredBundlePath: String? {
        didSet {
            if let stateFileURL {
                ProjectFolders.writeLoginItemBundlePath(lastRegisteredBundlePath, to: stateFileURL)
            }
        }
    }
    var performLaunchStatusCheck = true
    var uninstallCLIBeforeRegister = true

    private(set) var agentStatus: LoginItemStatus = .notRegistered
    private(set) var mainAppStatus: LoginItemStatus = .notRegistered
    private(set) var cliLaunchAgentPresent = false
    private(set) var banner: String?
    var notice: String?
    var busy = false

    init(
        service: any LoginItemService = SystemLoginItemService(),
        cliAgentDetector: (@MainActor () -> Bool)? = nil,
        cliDaemonUninstaller: (@MainActor () async throws -> Void)? = nil,
        bundlePathProvider: (@MainActor () -> String)? = nil,
        stateFileURL: URL? = LoginItemController.defaultStateFileURL(),
        runner: CLIRunner? = try? CLIRunner()
    ) {
        self.service = service
        self.cliAgentDetector = cliAgentDetector ?? {
            guard let path = Self.defaultCLILaunchAgentPath() else { return false }
            return FileManager.default.fileExists(atPath: path)
        }
        self.cliDaemonUninstaller = cliDaemonUninstaller ?? {
            guard let runner else { throw CLIError.unavailable }
            try await runner.uninstallDaemon()
        }
        self.bundlePathProvider = bundlePathProvider ?? {
            Bundle.main.bundlePath
        }
        self.stateFileURL = stateFileURL
        self.lastRegisteredBundlePath = stateFileURL.flatMap(ProjectFolders.readLoginItemBundlePath)
        checkStatusOnLaunch()
    }

    static func defaultCLILaunchAgentPath() -> String? {
        guard let record = getpwuid(getuid()), let dir = record.pointee.pw_dir else {
            return nil
        }
        let home = String(cString: dir)
        return (home as NSString).appendingPathComponent(cliAgentPlistRelativePath)
    }

    static func defaultStateFileURL() -> URL? {
        #if ENVCLOAK_SCREEN_TESTS
        return nil
        #else
        guard let record = getpwuid(getuid()), let dir = record.pointee.pw_dir else {
            return nil
        }
        let home = String(cString: dir)
        return URL(fileURLWithPath: home).appendingPathComponent(stateFileRelativePath)
        #endif
    }

    var isInApplicationsFolder: Bool {
        let path = bundlePathProvider()
        return path == "/Applications/EnvCloak.app"
            || (path.hasPrefix("/Applications/") && path.hasSuffix(".app"))
    }

    var launchAtLoginEnabled: Bool {
        mainAppStatus == .enabled
    }

    var showsApprovalBanner: Bool {
        banner != nil
    }

    var cliAgentInstalled: Bool {
        cliLaunchAgentPresent
    }

    func checkLaunchStatus() {
        checkStatusOnLaunch()
    }

    func checkStatusOnLaunch() {
        guard performLaunchStatusCheck else { return }
        refreshStatus()
        let currentPath = bundlePathProvider()
        if let previousPath = lastRegisteredBundlePath,
           previousPath != currentPath,
           agentStatus == .enabled || agentStatus == .requiresApproval {
            try? service.unregisterAgent()
            try? service.registerAgent()
            lastRegisteredBundlePath = currentPath
            refreshStatus()
        }
    }

    func refreshStatus() {
        agentStatus = service.agentStatus()
        mainAppStatus = service.mainAppStatus()
        cliLaunchAgentPresent = cliAgentDetector()
        banner = agentStatus == .requiresApproval ? Self.requiresApprovalBanner : nil
    }

    @discardableResult
    func registerAgentIfSafe() async -> Bool {
        await registerBackgroundAgent()
    }

    @discardableResult
    func replaceCLILaunchAgent() async -> Bool {
        await registerBackgroundAgent()
    }

    @discardableResult
    func registerBackgroundAgent() async -> Bool {
        guard !busy else { return false }
        busy = true
        notice = nil
        defer { busy = false }

        guard isInApplicationsFolder else {
            refreshStatus()
            notice = "Move EnvCloak.app to /Applications before enabling the background item."
            return false
        }

        cliLaunchAgentPresent = cliAgentDetector()
        if cliLaunchAgentPresent && uninstallCLIBeforeRegister {
            do {
                try await cliDaemonUninstaller()
            } catch {
                refreshStatus()
                notice = "Could not remove the command-line LaunchAgent (ai.envcloak.envcloakd). EnvCloak never runs both background processes at once."
                return false
            }
            cliLaunchAgentPresent = cliAgentDetector()
            if cliLaunchAgentPresent {
                refreshStatus()
                notice = "The command-line LaunchAgent (ai.envcloak.envcloakd) is still installed. Run envcloak daemon uninstall before enabling the app's background item."
                return false
            }
        }

        do {
            try service.registerAgent()
            lastRegisteredBundlePath = bundlePathProvider()
            refreshStatus()
            return true
        } catch {
            refreshStatus()
            notice = "The background item could not be registered with Login Items."
            return false
        }
    }

    @discardableResult
    func unregisterBackgroundAgent() -> Bool {
        notice = nil
        do {
            try service.unregisterAgent()
            refreshStatus()
            return true
        } catch {
            refreshStatus()
            notice = "The background item could not be removed from Login Items."
            return false
        }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        notice = nil
        do {
            try service.setMainAppEnabled(enabled)
            refreshStatus()
        } catch {
            refreshStatus()
            notice = "Launch at login could not be updated."
        }
    }

    func openLoginItemsSettings() {
        service.openSystemSettingsLoginItems()
    }

    func openSystemSettings() {
        openLoginItemsSettings()
    }
}
