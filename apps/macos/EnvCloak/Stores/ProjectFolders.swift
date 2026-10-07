import Darwin
import EnvCloakKit
import Foundation

/// The only persistent app metadata in EU-0: user-selected folder paths.
/// The location comes from the uid database, never launch input/defaults.
@MainActor final class ProjectFolders {
    private let file: URL
    private(set) var paths: [DaemonText]
    init(file: URL) throws {
        self.file = file
        if FileManager.default.fileExists(atPath: file.path) {
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            guard attrs[.type] as? FileAttributeType == .typeRegular,
                  (attrs[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576 else { throw EnvCloakError.protocolError }
            let decoded = try JSONDecoder().decode([String].self, from: Data(contentsOf: file))
            guard decoded.count <= 1000, decoded.allSatisfy({ $0.hasPrefix("/") && !$0.utf8.contains(0) }) else { throw EnvCloakError.protocolError }
            paths = decoded.map(DaemonText.init)
        } else { paths = [] }
    }
    static func live() throws -> ProjectFolders {
        guard let record = getpwuid(getuid()), let directory = record.pointee.pw_dir else { throw EnvCloakError.protocolError }
        let home = String(cString: directory)
        return try ProjectFolders(file: URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/EnvCloak/app/project-folders.json"))
    }
    func save(_ paths: [DaemonText]) throws {
        guard paths.count <= 1000 else { throw EnvCloakError.protocolError }
        let parent = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(paths.map(MetadataRequest.path))
        try data.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        self.paths = paths
    }
}
