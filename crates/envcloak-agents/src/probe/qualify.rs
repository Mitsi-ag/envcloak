//! Whether the probe is qualified for a host version (M2 plan task M2-28):
//! the scripted model speaks the wire protocol of the host versions it was
//! qualified against in CI ([`super::model::QUALIFIED`]), and a probe of
//! any other version would measure the stub as much as the host. So a
//! person's host at a version outside that table is not probed at all:
//! every outcome is `not_qualified`, which `agents status --json` keeps
//! apart from a failed probe, and the message names the versions CI
//! results exist for (docs/INSTALLERS.md, "Coverage").

use super::model::QUALIFIED;
use crate::hook::Host;
use crate::install::host_name;

/// Whether `host` at a version is probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qualification {
    /// The version is in the table: probed.
    Qualified,
    /// It is not: never probed, every outcome `not_qualified`.
    NotQualified {
        /// The versions of this host the table holds, for which CI
        /// results are published.
        qualified: Vec<&'static str>,
    },
}

impl Qualification {
    /// Whether the version is probed.
    pub fn is_qualified(&self) -> bool {
        matches!(self, Qualification::Qualified)
    }

    /// The versions of the host the table holds (empty when qualified).
    pub fn qualified_versions(&self) -> &[&'static str] {
        match self {
            Qualification::Qualified => &[],
            Qualification::NotQualified { qualified } => qualified,
        }
    }
}

/// Whether `host` at `version` is probed: its id and exact version in
/// [`QUALIFIED`].
pub fn qualify(host: Host, version: &str) -> Qualification {
    if super::model::qualified(host.id(), version) {
        return Qualification::Qualified;
    }
    Qualification::NotQualified {
        qualified: QUALIFIED
            .iter()
            .filter(|q| q.host == host.id())
            .map(|q| q.version)
            .collect(),
    }
}

/// The line `agents status --probe` prints for a host it does not probe:
/// "probe not qualified for <host> v<version>; CI results for v<...> are in
/// docs/INSTALLERS.md". `version` is the host's, as its version line gave
/// it; the caller escapes the line for display.
pub fn not_qualified_line(host: Host, version: &str, q: &Qualification) -> String {
    let versions: Vec<String> = q
        .qualified_versions()
        .iter()
        .map(|v| format!("v{v}"))
        .collect();
    let ci = if versions.is_empty() {
        "no CI results for it are published".to_owned()
    } else {
        format!(
            "CI results for {} are in docs/INSTALLERS.md",
            versions.join(" and ")
        )
    };
    format!(
        "probe not qualified for {} v{version}; {ci}",
        host_name(host)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_tables_versions_are_qualified() {
        for q in QUALIFIED {
            let host = Host::from_id(q.host).unwrap();
            assert_eq!(qualify(host, q.version), Qualification::Qualified);
            // The same version with anything around it is another one.
            for other in [
                format!("{}.1", q.version),
                format!("v{}", q.version),
                format!("{} ", q.version),
                String::new(),
            ] {
                assert!(!qualify(host, &other).is_qualified(), "{other:?}");
            }
        }
        let q = qualify(Host::ClaudeCode, "2.1.999");
        assert_eq!(q.qualified_versions(), ["2.1.280"]);
        assert_eq!(
            not_qualified_line(Host::ClaudeCode, "2.1.999", &q),
            "probe not qualified for Claude Code v2.1.999; CI results for v2.1.280 are in \
             docs/INSTALLERS.md"
        );
        let q = qualify(Host::Codex, "0.160.0");
        assert_eq!(
            not_qualified_line(Host::Codex, "0.160.0", &q),
            "probe not qualified for Codex v0.160.0; CI results for v0.159.2 are in \
             docs/INSTALLERS.md"
        );
    }
}
