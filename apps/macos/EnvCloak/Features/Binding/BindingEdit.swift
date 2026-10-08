import EnvCloakKit
import Foundation

struct BindingEdit {
    let project: DaemonText
    let profile: String?
    let envName: String
    let reference: String?
    let previous: DaemonText?

    var cliArguments: [String]? {
        guard Self.variable(envName), profile.map(Self.profileName) ?? true else { return nil }
        var args = ["ref"]
        if let reference {
            guard Self.referenceName(reference) else { return nil }
            args += [envName + "=" + reference]
        } else { args += ["--unset", envName] }
        if let profile { args += ["--profile", profile] }
        return args + ["--json"]
    }
    static func variable(_ text: String) -> Bool {
        let b = Array(text.utf8)
        return !b.isEmpty && b.count <= 128 && !(48...57).contains(b[0]) && b.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 95
        }
    }
    static func profileName(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.count <= 64 && text.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }
    }
    static func referenceName(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.count <= 256 && !text.hasPrefix("-") && text.utf8.allSatisfy {
            (97...122).contains($0) || (65...90).contains($0) || (48...57).contains($0) || [45, 95, 47, 35, 46].contains($0)
        }
    }
    var preview: String {
        let header = profile.map { "[env." + Escape.display($0) + "]" } ?? "[env]"
        return header + "\n" + Escape.display(envName) + " = \"" + Escape.display(reference ?? "") + "\""
    }
}

