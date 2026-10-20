import Darwin
import Foundation

enum CLIInstallOutcome: Equatable, Sendable {
    case installed(linkPath: String, targetPath: String, shadowedBy: String?)
    case manualCommand(command: String, reason: String)
}

struct CLIInstallStatus: Equatable, Sendable {
    let installedLinkPath: String?
    let targetPath: String
    let shadowedBy: String?

    var isInstalled: Bool {
        installedLinkPath != nil
    }

    var installedPath: String? {
        installedLinkPath
    }

    var shadowingPath: String? {
        shadowedBy
    }
}

struct CLIInstaller: Sendable {
    let bundledCLIPath: String
    let candidateDirectories: [String]
    let searchDirectories: [String]

    init(
        bundledCLIPath: String? = nil,
        candidateDirectories: [String]? = nil,
        searchDirectories: [String]? = nil
    ) {
        let resolvedBundled = bundledCLIPath
            ?? (Bundle.main.bundlePath as NSString).appendingPathComponent("Contents/MacOS/envcloak")
        let resolvedCandidates = candidateDirectories ?? Self.defaultCandidateDirectories()
        self.bundledCLIPath = resolvedBundled
        self.candidateDirectories = resolvedCandidates
        self.searchDirectories = searchDirectories ?? (resolvedCandidates + ["/usr/bin", "/bin"])
    }

    static func defaultCandidateDirectories() -> [String] {
        var dirs = ["/opt/homebrew/bin", "/usr/local/bin"]
        if let record = getpwuid(getuid()), let pwDir = record.pointee.pw_dir {
            let home = String(cString: pwDir)
            let localBin = (home as NSString).appendingPathComponent(".local/bin")
            dirs.append(localBin)
        }
        return dirs
    }

    static func manualSymlinkCommand(targetPath: String, destinationPath: String = "/usr/local/bin/envcloak") -> String {
        let quotedTarget = "'" + targetPath.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let quotedDest = "'" + destinationPath.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return "ln -sf \(quotedTarget) \(quotedDest)"
    }

    func status() -> CLIInstallStatus {
        let fm = FileManager.default
        for candidate in candidateDirectories {
            let linkPath = (candidate as NSString).appendingPathComponent("envcloak")
            if let dest = try? fm.destinationOfSymbolicLink(atPath: linkPath), dest == bundledCLIPath {
                let shadow = firstShadowingExecutable(beforeDirectory: candidate)
                return CLIInstallStatus(
                    installedLinkPath: linkPath,
                    targetPath: bundledCLIPath,
                    shadowedBy: shadow
                )
            }
        }
        return CLIInstallStatus(
            installedLinkPath: nil,
            targetPath: bundledCLIPath,
            shadowedBy: nil
        )
    }

    func install() -> CLIInstallOutcome {
        let fm = FileManager.default
        for candidate in candidateDirectories {
            if candidate.hasSuffix("/.local/bin") && !fm.fileExists(atPath: candidate) {
                let parent = (candidate as NSString).deletingLastPathComponent
                if fm.isWritableFile(atPath: parent) {
                    try? fm.createDirectory(
                        atPath: candidate,
                        withIntermediateDirectories: true,
                        attributes: [.posixPermissions: 0o755]
                    )
                }
            }
            guard fm.isWritableFile(atPath: candidate) else { continue }
            let linkPath = (candidate as NSString).appendingPathComponent("envcloak")
            if (try? fm.attributesOfItem(atPath: linkPath)) != nil {
                do {
                    try fm.removeItem(atPath: linkPath)
                } catch {
                    continue
                }
            }
            do {
                try fm.createSymbolicLink(atPath: linkPath, withDestinationPath: bundledCLIPath)
                let shadow = firstShadowingExecutable(beforeDirectory: candidate)
                return .installed(
                    linkPath: linkPath,
                    targetPath: bundledCLIPath,
                    shadowedBy: shadow
                )
            } catch {
                continue
            }
        }
        let fallbackDest = candidateDirectories.first.map {
            ($0 as NSString).appendingPathComponent("envcloak")
        } ?? "/usr/local/bin/envcloak"
        return .manualCommand(
            command: Self.manualSymlinkCommand(targetPath: bundledCLIPath, destinationPath: fallbackDest),
            reason: "No writable PATH folder was found. Run this command in Terminal to link envcloak:"
        )
    }

    private func firstShadowingExecutable(beforeDirectory chosenDirectory: String) -> String? {
        let fm = FileManager.default
        for dir in searchDirectories {
            if dir == chosenDirectory {
                break
            }
            let candidate = (dir as NSString).appendingPathComponent("envcloak")
            if let dest = try? fm.destinationOfSymbolicLink(atPath: candidate) {
                if dest != bundledCLIPath {
                    return candidate
                }
            } else if fm.fileExists(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }
}
