import Darwin
import EnvCloakKit
import Foundation

/// The only persistent app metadata in EU-0: user-selected folder paths.
/// The location comes from the uid database, never launch input/defaults.
@MainActor final class ProjectFolders {
    private struct SecurityState: Codable {
        var touchIDOnlyEnabled: Bool = false
        var recoveryConfirmed: Bool = false
        var passphraseUnlockerRemoved: Bool = false
    }

    private let file: URL
    private(set) var paths: [DaemonText]
    private(set) var scope: DaemonText?
    private(set) var showMenuBarExtra: Bool
    private(set) var touchIDOnlyEnabled: Bool
    private(set) var recoveryConfirmed: Bool
    private(set) var passphraseUnlockerRemoved: Bool
    private var scopeFile: URL { file.appendingPathExtension("scope") }
    private var menuBarFile: URL { file.appendingPathExtension("menubar") }
    private var securityFile: URL { file.appendingPathExtension("security") }
    init(file: URL) throws {
        self.file = file
        paths = try Self.read(file)
        let scopes = try Self.read(file.appendingPathExtension("scope"))
        guard scopes.count <= 1 else { throw EnvCloakError.protocolError }
        scope = scopes.first
        showMenuBarExtra = (try? Self.readBool(file.appendingPathExtension("menubar"))) ?? false
        let sec = (try? Self.readSecurity(file.appendingPathExtension("security"))) ?? SecurityState()
        touchIDOnlyEnabled = sec.touchIDOnlyEnabled
        recoveryConfirmed = sec.recoveryConfirmed
        passphraseUnlockerRemoved = sec.passphraseUnlockerRemoved
    }
    private static func readBool(_ file: URL) throws -> Bool {
        guard FileManager.default.fileExists(atPath: file.path) else { return false }
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 64 else { throw EnvCloakError.protocolError }
        return try JSONDecoder().decode(Bool.self, from: Data(contentsOf: file))
    }
    private static func readSecurity(_ file: URL) throws -> SecurityState {
        guard FileManager.default.fileExists(atPath: file.path) else { return SecurityState() }
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 1024 else { throw EnvCloakError.protocolError }
        return try JSONDecoder().decode(SecurityState.self, from: Data(contentsOf: file))
    }
    private static func read(_ file: URL) throws -> [DaemonText] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576 else { throw EnvCloakError.protocolError }
        let decoded = try JSONDecoder().decode([String].self, from: Data(contentsOf: file))
        guard decoded.count <= 1000, decoded.allSatisfy({ $0.hasPrefix("/") && !$0.utf8.contains(0) }) else { throw EnvCloakError.protocolError }
        return decoded.map(DaemonText.init)
    }
    static func live() throws -> ProjectFolders {
        guard let record = getpwuid(getuid()), let directory = record.pointee.pw_dir else { throw EnvCloakError.protocolError }
        let home = String(cString: directory)
        return try ProjectFolders(file: URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/EnvCloak/app/project-folders.json"))
    }
    func save(_ paths: [DaemonText]) throws {
        try Self.write(paths, to: file)
        self.paths = paths
    }
    func saveScope(_ scope: DaemonText?) throws {
        try Self.write(scope.map { [$0] } ?? [], to: scopeFile)
        self.scope = scope
    }
    func saveMenuBarExtra(_ enabled: Bool) throws {
        let parent = menuBarFile.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(enabled)
        try data.write(to: menuBarFile, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: menuBarFile.path)
        self.showMenuBarExtra = enabled
    }
    func saveSecurityState(
        touchIDOnlyEnabled: Bool? = nil,
        recoveryConfirmed: Bool? = nil,
        passphraseUnlockerRemoved: Bool? = nil
    ) throws {
        let next = SecurityState(
            touchIDOnlyEnabled: touchIDOnlyEnabled ?? self.touchIDOnlyEnabled,
            recoveryConfirmed: recoveryConfirmed ?? self.recoveryConfirmed,
            passphraseUnlockerRemoved: passphraseUnlockerRemoved ?? self.passphraseUnlockerRemoved
        )
        let parent = securityFile.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(next)
        try data.write(to: securityFile, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: securityFile.path)
        self.touchIDOnlyEnabled = next.touchIDOnlyEnabled
        self.recoveryConfirmed = next.recoveryConfirmed
        self.passphraseUnlockerRemoved = next.passphraseUnlockerRemoved
    }
    static func readLoginItemBundlePath(_ file: URL) -> String? {
        guard FileManager.default.fileExists(atPath: file.path),
              let attrs = try? FileManager.default.attributesOfItem(atPath: file.path),
              attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 4096,
              let data = try? Data(contentsOf: file),
              let decoded = try? JSONDecoder().decode(String.self, from: data),
              decoded.hasPrefix("/"),
              !decoded.utf8.contains(0) else {
            return nil
        }
        return decoded
    }
    static func writeLoginItemBundlePath(_ path: String?, to file: URL) {
        guard let path else {
            try? FileManager.default.removeItem(at: file)
            return
        }
        let parent = file.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        guard let data = try? JSONEncoder().encode(path) else { return }
        try? data.write(to: file, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    private static func write(_ paths: [DaemonText], to file: URL) throws {
        guard paths.count <= 1000, paths.allSatisfy({ MetadataRequest.directoryURL($0) != nil }) else { throw EnvCloakError.protocolError }
        let parent = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(paths.map(MetadataRequest.path))
        try data.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}
