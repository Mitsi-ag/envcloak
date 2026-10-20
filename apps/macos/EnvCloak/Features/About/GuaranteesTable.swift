import Foundation

struct GuaranteesRow: Equatable, Sendable, Identifiable {
    let mode: String
    let processHolds: String
    let guarantees: String
    let doesNotGuarantee: String
    let isAvailableInThisRelease: Bool

    var id: String { mode }

    static func isShippedInM3(mode: String) -> Bool {
        !mode.contains("; M6)") && !mode.contains("; M9)") && !mode.contains("; M2b)")
    }
}

struct GuaranteesTable: Equatable, Sendable {
    static let unshippedBadge = "Not in this release"

    static let rows: [GuaranteesRow] = [
        GuaranteesRow(
            mode: "Proxy (HTTPS APIs; M6)",
            processHolds: "A session placeholder, never the key",
            guarantees: "The key is inserted only into the provider's declared auth slot, only for that item's exact hosts, only over verified TLS, and only while the grant lasts. Key-management and key-minting paths are refused. The placeholder is useless outside the session.",
            doesNotGuarantee: "That the agent will not use the key's permissions with that provider during the grant (spend, delete, create). Non-HTTP protocols. Programs that ignore proxy settings fail instead of connecting directly. A program that can read the child's environment can use the session until it ends.",
            isAvailableInThisRelease: false
        ),
        GuaranteesRow(
            mode: "Inject + redact (the default until M6)",
            processHolds: "The real key, in its environment and memory",
            guarantees: "Every delivery is approved and audited. There is no plaintext in the repo or agent configs. The exact value and the encodings listed in §6.1 are masked in that command's own stdout and stderr.",
            doesNotGuarantee: "Anything a careless, deliberate or prompt-injected process does with a key it holds: transformed output, files, network, child processes. Other programs running as you can read a running process's environment on macOS and Linux.",
            isAvailableInThisRelease: true
        ),
        GuaranteesRow(
            mode: "Native credential helpers (AWS, git, Docker, kube; M9)",
            processHolds: "A short-lived or scoped credential, in plaintext",
            guarantees: "The long-lived source credential never leaves EnvCloak. Every delivery is approved, audited and time-bounded.",
            doesNotGuarantee: "The delivered credential until it expires. Stopping delivery does not revoke credentials already issued.",
            isAvailableInThisRelease: false
        ),
        GuaranteesRow(
            mode: "Dev sign-in (own apps and test accounts; M2b)",
            processHolds: "A usable session for a dedicated test account, in a fresh browser context EnvCloak creates and publishes for that grant",
            guarantees: "The password and TOTP seed are used only by EnvCloak's sign-in worker, only on the target's exact credential-entry origins, and are never returned in a tool result, error, log or audit entry; the agent's browser tools never receive a filled credential form. A one-time code is generated only for an approved attempt. Only the target's declared session state is delivered, and only after the account, tenant and role are verified in the receiving context.",
            doesNotGuarantee: "What the agent does with the session: it can use and export it for as long as the app honours it. Browser cookies are not port-scoped, so other services on the same hostname can receive them. Ending access stops EnvCloak and clears its browser context; server-side revocation is reported separately, and only when verified. A page that captures or reflects the password it receives. A process running as you with debugger, memory or file access to the worker (§10). TOTP is not phishing-resistant, and a password stored with its TOTP seed in one unlocked vault is one factor, not two.",
            isAvailableInThisRelease: false
        ),
        GuaranteesRow(
            mode: "Reveal and cards",
            processHolds: "Nothing: human only",
            guarantees: "Values appear only in the EnvCloak app after Touch ID, or (secrets only, never cards) on Linux on the terminal after the passphrase; never in CLI stdout or stderr, MCP or agent paths.",
            doesNotGuarantee: "Screen capture, an agent that drives the terminal where a value is shown, or someone reading your screen.",
            isAvailableInThisRelease: true
        ),
        GuaranteesRow(
            mode: "Every mode",
            processHolds: "",
            guarantees: "The vault is encrypted at rest and unlocks only with the Secure Enclave, your passphrase or your Recovery Kit. Grants are limited to a project, a key list, one process tree and a time window, and need an approval proof that a program cannot produce by itself.",
            doesNotGuarantee: "Protection from root, kernel malware or a fully compromised account. Removal of anything already sent to a model provider. On Linux and in builds without EnvCloak's signature: protection from a program running as you that impersonates the daemon or the `envcloak` command to capture your passphrase, or that watches a terminal where you type it. On macOS, your login password is also an approval factor, because Touch ID falls back to it.",
            isAvailableInThisRelease: true
        ),
    ]

    static func parse(specMarkdown: String) -> [GuaranteesRow] {
        guard let sectionRange = specMarkdown.range(of: "### 1.1 What EnvCloak guarantees") else {
            return []
        }
        let remainder = specMarkdown[sectionRange.upperBound...]
        var parsed: [GuaranteesRow] = []
        var inTable = false
        for rawLine in remainder.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("## ") || (line.hasPrefix("### ") && !line.hasPrefix("### 1.1")) {
                break
            }
            guard line.hasPrefix("|"), line.hasSuffix("|") else {
                if inTable { break }
                continue
            }
            let inner = line.dropFirst().dropLast()
            let cells = inner.split(separator: "|", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard cells.count == 4 else { continue }
            if cells[0] == "Mode" || cells.allSatisfy({ $0.allSatisfy({ $0 == "-" }) && !$0.isEmpty }) {
                inTable = true
                continue
            }
            inTable = true
            let mode = cells[0]
            parsed.append(
                GuaranteesRow(
                    mode: mode,
                    processHolds: cells[1],
                    guarantees: cells[2],
                    doesNotGuarantee: cells[3],
                    isAvailableInThisRelease: GuaranteesRow.isShippedInM3(mode: mode)
                )
            )
        }
        return parsed
    }
}
