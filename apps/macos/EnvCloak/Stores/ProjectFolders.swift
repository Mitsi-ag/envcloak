import Darwin
import EnvCloakKit
import Foundation

/// The only persistent app metadata in EU-0: user-selected folder paths.
/// The location comes from the uid database, never launch input/defaults.
@MainActor final class ProjectFolders {
    private let file: URL
    private(set) var paths: [DaemonText]
    private(set) var scope: DaemonText?
    private var scopeFile: URL { file.appendingPathExtension("scope") }
    init(file: URL) throws {
        self.file = file
        paths = try Self.read(file)
        let scopes = try Self.read(file.appendingPathExtension("scope"))
        guard scopes.count <= 1 else { throw EnvCloakError.protocolError }
        scope = scopes.first
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
    private static func write(_ paths: [DaemonText], to file: URL) throws {
        guard paths.count <= 1000, paths.allSatisfy({ MetadataRequest.directoryURL($0) != nil }) else { throw EnvCloakError.protocolError }
        let parent = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(paths.map(MetadataRequest.path))
        try data.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}
