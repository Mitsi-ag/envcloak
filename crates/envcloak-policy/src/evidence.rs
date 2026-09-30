//! Caller evidence (SPEC §10a "Caller identity", §10b "Root selection" and
//! "Match" rules 3 and 4; gates 25 and 26).
//!
//! [`gather`] walks the connected peer's ancestry from the kernel
//! ([`envcloak_sys::ancestry`], re-validated after the walk and walked
//! again when it changed), classifies each process of the caller's uid
//! with the [`AgentCatalog`], and adds the caller's own claims. The result,
//! [`SubjectEvidence`], answers three questions:
//!
//! - **Root** ([`SubjectEvidence::root`]), the process instance a grant for
//!   this caller is scoped to:
//!   1. the known agent nearest the caller;
//!   2. otherwise the caller's session leader, when it is in the verified
//!      chain (so alive, with its start time checked);
//!   3. otherwise the topmost ancestor still in the caller's session: the
//!      session leader is dead, or the caller left its tree (a double fork,
//!      `nohup` and an exiting shell).
//!
//!   `launchd` or `init` (pid 1) is never a root, and never a session
//!   leader for this purpose: every process descends from it, and GUI apps
//!   on macOS run in its session. A known agent that is pid 1 (a container
//!   whose entrypoint execs one) is still an agent for the kind, the
//!   barrier and proofs, and rules 2 and 3 pick the root.
//!
//!   Rule 1 may pick an agent above the caller's session, as it must:
//!   Claude Code and Codex run each command in a session of its own. Only
//!   a builtin match on the agent's executable or signature may do that
//!   ([`AgentLabel::may_root_above_session`]). An agent matched only on
//!   what it says about itself (`argv[0]`, its script, its command name,
//!   all of which a process sets) or only through a user extension is the
//!   root only at or below the point rule 2 or 3 would pick; above it,
//!   rules 2 and 3 apply. A root never widens past the caller's own
//!   session that way (review finding F-37).
//! - **Kind** ([`SubjectEvidence::kind`]), in this order:
//!   1. a known agent in the ancestry: [`SubjectKind::Agent`];
//!   2. no session leader in the chain, so the ancestry is lost (an
//!      orphan, an escaped process) or never had one (pid 1's session), or
//!      a chain cut at [`MAX_ANCESTRY`] processes, above which an agent
//!      may hide: [`SubjectKind::Unknown`], whatever the claims say;
//!   3. agent markers in the claims: [`SubjectKind::Agent`];
//!   4. a session without a controlling terminal (`setsid`, a service, a
//!      job launched by `launchd` or `systemd`): [`SubjectKind::Unknown`];
//!   5. otherwise [`SubjectKind::Terminal`], which never proves a person is
//!      there (SPEC §10a: "a human typed this" cannot be claimed).
//! - **Coverage** ([`SubjectEvidence::covered_by`]): whether a grant rooted
//!   at a given instance may cover this caller: the root is in the chain
//!   with its pid and start time (a recycled pid never matches), no known
//!   agent sits between the root and the caller unless the root is that
//!   agent, a grant approved for a terminal subject never covers an agent
//!   or unknown one, and a root above the caller's session is an agent
//!   that could have been picked there (see Root). Any other root covers
//!   only callers in its own session run, on every system alike: the same
//!   rule that roots a GUI app's helper at the whole app (rule 3, below
//!   pid 1 on macOS) or at the desktop shell leading its session (rule 2,
//!   on Linux), and a `tmux` server's own jobs at the server, keeps that
//!   grant from the sessions the app, the shell or the server starts (an
//!   IDE's integrated terminals, the commands an agent the catalog does
//!   not know runs in sessions of their own, the other panes).
//!
//! What a caller says only tightens. The claims (environment markers the
//! CLI found in its own environment, SPEC §10a "caller-asserted") can turn
//! a terminal subject into an agent, never the reverse, and never change
//! the chain or the root. A process's `argv[0]`, script and command name
//! are its own word too: through classification they can make a caller an
//! agent, and never root a grant above its session. A process that is not
//! recognized gains nothing, because the kind then comes from the
//! session, and escaping the tree loses every grant rooted in it.
//!
//! A chain longer than [`MAX_ANCESTRY`] is cut ([`ChainEnd::Cut`]), and
//! what is above the cut is not seen: an agent could run its commands
//! under enough nested shells, with `env -i`, to put itself there. So a
//! cut chain fails closed: without a known agent below the cut its kind is
//! [`SubjectKind::Unknown`] (no terminal grant covers it), and
//! [`SubjectEvidence::agent_involved`] is true (its proofs are refused).
//! So does an orphan ([`SubjectEvidence::orphaned`]): a command that
//! double-forks out of an agent's tree keeps the terminal it had, and must
//! not give a proof there that it may not give from inside.
//!
//! **Proofs** ([`SubjectEvidence::proof_refusal`]) are taken only from a
//! terminal subject. A process that left an agent's tree through a service
//! manager or `setsid` is neither an agent nor an orphan, but it has no
//! terminal, so no person could have typed its proof.
//!
//! The Linux CLI makes itself non-dumpable, so its own `exe` is hidden
//! from the daemon; its `stat` and `cmdline` are not, and the walk starts
//! there. Arguments are read only for processes whose executable is hidden
//! or that run an interpreter, into wiped storage ([`envcloak_sys::Argv`]),
//! which the catalog borrows to compare and which is dropped after
//! classification: the evidence keeps pids, start times, executables and
//! labels, never arguments. On macOS they can include environment strings
//! of a process that rewrote its argument area (review finding F-38; see
//! `envcloak_sys`'s `proc` module).

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use envcloak_sys::{
    AncestryError, ExeIdentity, LiveProcesses, MAX_ANCESTRY, PeerIdentity, ProcInfo, ProcessTable,
    StartTime, ancestry_in, reaches_top,
};

use crate::agents::{AgentCatalog, AgentLabel};
use crate::effective::SubjectKind;
use crate::names::EnvName;

/// How many times [`gather`] walks when the ancestry keeps changing under
/// it.
pub const GATHER_ATTEMPTS: usize = 3;

/// One process instance: a pid and the start time that tells it from any
/// later process with that pid (SPEC §10b `ProcessInstance`).
///
/// `==` and `Hash` compare the pid and the start time only, so a process
/// is one key (for the per-root bounds of SPEC §10a) whatever its
/// executable's path reads now (renamed, or removed on Linux) and whether
/// its pid version is known. [`ProcessInstance::same`], which coverage
/// uses, also compares pid versions when both are known.
#[derive(Debug, Clone)]
pub struct ProcessInstance {
    pub pid: i32,
    pub start_time: StartTime,
    /// macOS: the audit token's pid version, known only for the direct
    /// peer.
    pub pidversion: Option<i32>,
    /// Display and audit only; matching never uses it.
    pub exe: Option<ExeIdentity>,
}

impl PartialEq for ProcessInstance {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid && self.start_time == other.start_time
    }
}

impl Eq for ProcessInstance {}

impl std::hash::Hash for ProcessInstance {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.start_time.hash(state);
    }
}

impl ProcessInstance {
    /// Whether `other` is the same process: the same pid and start time,
    /// and the same pid version when both know one.
    pub fn same(&self, other: &ProcessInstance) -> bool {
        self.pid == other.pid
            && self.start_time == other.start_time
            && match (self.pidversion, other.pidversion) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

/// Whether a caller's chain reaches the top of the process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainEnd {
    /// The last process's parent is 0: `launchd`, `init`, or the top of a
    /// pid namespace.
    Top,
    /// The walk stopped at [`MAX_ANCESTRY`] processes; what is above is
    /// not seen, and the evidence fails closed (see the module
    /// documentation).
    Cut,
}

/// One process in the caller's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub instance: ProcessInstance,
    /// Its session id.
    pub sid: Option<i32>,
    /// The agent it is, if the catalog knows it.
    pub agent: Option<AgentLabel>,
}

/// What the caller says about itself: the names of the agent markers set
/// in its environment (`CLAUDECODE`, ...), never their values. Caller
/// assertions only tighten (SPEC §10a).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Claims {
    /// Sorted, without duplicates.
    markers: Vec<String>,
}

/// Why claims from the wire were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimsError {
    /// More than [`Claims::MAX_MARKERS`].
    TooMany,
    /// Not an environment variable name.
    InvalidMarker,
}

impl core::fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ClaimsError::TooMany => "too many agent markers",
            ClaimsError::InvalidMarker => "an agent marker is not a variable name",
        })
    }
}

impl std::error::Error for ClaimsError {}

impl Claims {
    /// The most markers a caller may claim.
    pub const MAX_MARKERS: usize = 16;

    /// No claims.
    pub fn none() -> Self {
        Claims::default()
    }

    /// Claims as the daemon receives them: marker names, each an
    /// environment variable name ([`EnvName`]). A name the catalog does not
    /// know still claims an agent.
    ///
    /// # Errors
    /// More than [`Claims::MAX_MARKERS`] names, or a name that is not a
    /// variable name. The error holds neither.
    pub fn from_markers<I, S>(names: I) -> Result<Self, ClaimsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut markers = Vec::new();
        for n in names {
            let n = n.as_ref();
            if markers.len() >= Self::MAX_MARKERS {
                return Err(ClaimsError::TooMany);
            }
            if !EnvName::valid(n.as_bytes()) {
                return Err(ClaimsError::InvalidMarker);
            }
            markers.push(n.to_owned());
        }
        markers.sort();
        markers.dedup();
        Ok(Claims { markers })
    }

    /// The CLI's claims: which of the catalog's markers are set in this
    /// process's environment. Only names are read and kept.
    pub fn from_env(cat: &AgentCatalog) -> Self {
        Self::from_vars(std::env::vars_os().map(|(k, _)| k), cat)
    }

    /// The claims for an environment holding the variables `names`: the
    /// catalog markers among them.
    pub fn from_vars(names: impl IntoIterator<Item = OsString>, cat: &AgentCatalog) -> Self {
        let known: Vec<&str> = cat.markers().collect();
        let mut markers: Vec<String> = names
            .into_iter()
            .filter_map(|n| {
                known
                    .iter()
                    .find(|m| m.as_bytes() == n.as_bytes())
                    .map(|m| (*m).to_owned())
            })
            .collect();
        markers.sort();
        markers.dedup();
        markers.truncate(Self::MAX_MARKERS);
        Claims { markers }
    }

    /// The marker names claimed.
    pub fn markers(&self) -> &[String] {
        &self.markers
    }

    /// Whether the caller claims to run under an agent.
    pub fn claims_agent(&self) -> bool {
        !self.markers.is_empty()
    }
}

/// Why a caller may not give a proof ([`SubjectEvidence::proof_refusal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofRefusal {
    /// A known agent in the ancestry, or agent markers in the claims.
    Agent,
    /// The chain was cut at [`MAX_ANCESTRY`]: an agent may be above it.
    ChainCut,
    /// The caller lost its ancestry ([`SubjectEvidence::orphaned`]).
    Orphaned,
    /// Not a terminal session: no controlling terminal, or a session whose
    /// leader is pid 1.
    NoTerminal,
}

impl ProofRefusal {
    /// The stable token, for the audit log.
    pub fn token(self) -> &'static str {
        match self {
            ProofRefusal::Agent => "agent",
            ProofRefusal::ChainCut => "chain_cut",
            ProofRefusal::Orphaned => "orphaned",
            ProofRefusal::NoTerminal => "no_terminal",
        }
    }
}

/// Why no evidence could be gathered. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceError {
    /// The caller exited, or its pid now belongs to another process.
    CallerGone,
    /// The ancestry kept changing while it was read.
    Changed,
    /// A process in the ancestry is hidden from the daemon: on Linux,
    /// `/proc` mounted with `hidepid` hides other users' processes. See
    /// docs/AGENTS.md "Limits".
    Hidden,
    /// The kernel refused a read.
    Io(std::io::ErrorKind),
}

impl EvidenceError {
    /// The stable token for clients.
    pub fn token(self) -> &'static str {
        match self {
            EvidenceError::CallerGone => "caller_gone",
            EvidenceError::Changed => "ancestry_changed",
            EvidenceError::Hidden => "ancestry_hidden",
            EvidenceError::Io(_) => "ancestry_unreadable",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            EvidenceError::CallerGone => "the caller exited before its ancestry could be read",
            EvidenceError::Changed => "the caller's ancestry kept changing while it was read",
            EvidenceError::Hidden => {
                "a process in the caller's ancestry is hidden from the daemon (Linux: /proc \
                 mounted with hidepid)"
            }
            EvidenceError::Io(_) => "the caller's ancestry could not be read",
        }
    }
}

impl From<AncestryError> for EvidenceError {
    fn from(e: AncestryError) -> Self {
        match e {
            AncestryError::PeerGone => EvidenceError::CallerGone,
            AncestryError::Changed => EvidenceError::Changed,
            AncestryError::Hidden => EvidenceError::Hidden,
            AncestryError::Io(k) => EvidenceError::Io(k),
        }
    }
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())?;
        if let EvidenceError::Io(k) = self {
            write!(f, " ({k})")?;
        }
        Ok(())
    }
}

impl std::error::Error for EvidenceError {}

/// Everything the daemon knows about a caller. See the module
/// documentation for how the root, the kind and coverage follow from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectEvidence {
    chain: Vec<Ancestor>,
    cut: bool,
    terminal: bool,
    claims: Claims,
    claimed: Option<AgentLabel>,
    nearest_agent: Option<usize>,
    session_leader: Option<usize>,
    /// The session leader's index, or else the topmost one in the
    /// caller's session: the widest root rules 2 and 3 give.
    limit: usize,
    root: usize,
}

impl SubjectEvidence {
    /// Evidence from a verified chain, the caller first, whether it
    /// reaches the top of the tree, and whether the caller's session has a
    /// controlling terminal. `claimed` labels the claims, when the catalog
    /// knows one of their markers. `None` for an empty chain.
    ///
    /// [`gather`] builds evidence from the kernel; tests build it from
    /// synthetic chains. pid 1 is never the root, whatever its label.
    pub fn from_chain(
        chain: Vec<Ancestor>,
        end: ChainEnd,
        terminal: bool,
        claims: Claims,
        claimed: Option<AgentLabel>,
    ) -> Option<SubjectEvidence> {
        let first = chain.first()?;
        let sid = first.sid;
        // The leading run of the chain in the caller's session, stopping
        // below pid 1.
        let in_session = match sid {
            Some(s) => chain
                .iter()
                .take_while(|a| a.sid == Some(s) && a.instance.pid != 1)
                .count()
                .max(1),
            None => 1,
        };
        let session_leader =
            sid.and_then(|s| (0..in_session).find(|&j| chain[j].instance.pid == s));
        let limit = session_leader.unwrap_or(in_session - 1);
        let nearest_agent = chain.iter().position(|a| a.agent.is_some());
        // A known agent that is pid 1 (a container's entrypoint) makes the
        // caller an agent subject, but pid 1 is never a root.
        let may_root =
            |n: usize| chain[n].instance.pid != 1 && (n <= limit || roots_above_session(&chain[n]));
        let root = match nearest_agent {
            Some(n) if may_root(n) => n,
            _ => limit,
        };
        Some(SubjectEvidence {
            chain,
            cut: end == ChainEnd::Cut,
            terminal,
            claims,
            claimed,
            nearest_agent,
            session_leader,
            limit,
            root,
        })
    }

    /// The chain, the caller first, up to the top of the tree (or
    /// [`MAX_ANCESTRY`] processes).
    pub fn chain(&self) -> &[Ancestor] {
        &self.chain
    }

    /// Whether the chain was cut at [`MAX_ANCESTRY`] processes: an agent
    /// may be above the cut. See the module documentation.
    pub fn cut(&self) -> bool {
        self.cut
    }

    /// The caller: the process that connected.
    pub fn caller(&self) -> &ProcessInstance {
        &self.chain[0].instance
    }

    /// The known agent nearest the caller: its index in the chain and its
    /// label.
    pub fn nearest_agent(&self) -> Option<(usize, &AgentLabel)> {
        let n = self.nearest_agent?;
        Some((n, self.chain[n].agent.as_ref()?))
    }

    /// The caller's session leader, when it is in the verified chain.
    pub fn session_leader(&self) -> Option<&ProcessInstance> {
        self.session_leader.map(|j| &self.chain[j].instance)
    }

    /// Whether the caller's session has a controlling terminal.
    pub fn terminal(&self) -> bool {
        self.terminal
    }

    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The root's index in the chain.
    pub fn root_index(&self) -> usize {
        self.root
    }

    /// The instance a grant for this caller is rooted at (SPEC §10b "Root
    /// selection"). Always a live, start-time-verified process of the
    /// chain, never pid 1.
    pub fn root(&self) -> ProcessInstance {
        self.chain[self.root].instance.clone()
    }

    /// The subject's kind. See the module documentation.
    pub fn kind(&self) -> SubjectKind {
        if self.nearest_agent.is_some() {
            SubjectKind::Agent
        } else if self.cut || self.session_leader.is_none() {
            SubjectKind::Unknown
        } else if self.claims.claims_agent() {
            SubjectKind::Agent
        } else if !self.terminal {
            SubjectKind::Unknown
        } else {
            SubjectKind::Terminal
        }
    }

    /// The agent to show: the nearest one in the ancestry, else the one
    /// the claims name.
    pub fn label(&self) -> Option<&AgentLabel> {
        self.nearest_agent()
            .map(|(_, l)| l)
            .or(self.claimed.as_ref())
    }

    /// Whether the caller has lost its ancestry: its chain no longer
    /// reaches its session's leader, as after a double fork or `nohup`
    /// out of a terminal, or the leader's death. Whatever ran it is no
    /// longer seen. pid 1's session without a controlling terminal, where
    /// GUI apps and `launchd` jobs run on macOS, is not counted: pid 1
    /// leads it and is in every chain. With a terminal (a container whose
    /// init is a shell) it is, as a process there may have been
    /// reparented to it.
    pub fn orphaned(&self) -> bool {
        self.session_leader.is_none() && (self.chain[0].sid != Some(1) || self.terminal)
    }

    /// Whether an agent is or may be involved by any evidence: one in the
    /// ancestry, markers in the claims, an orphan's lost ancestry
    /// ([`SubjectEvidence::orphaned`]) or a chain cut at [`MAX_ANCESTRY`]
    /// (an agent may be above the cut). An orphan that keeps its terminal
    /// could otherwise prompt on it for a proof that the same command, run
    /// inside its agent's tree, may not give. Proofs are refused on this
    /// and more: see [`SubjectEvidence::proof_refusal`].
    pub fn agent_involved(&self) -> bool {
        self.nearest_agent.is_some() || self.claims.claims_agent() || self.cut || self.orphaned()
    }

    /// Why this caller may not give a proof (approve, unlock, rotate,
    /// remove, recover; SPEC §10b), or `None` when it may: only a terminal
    /// subject may ([`SubjectKind::Terminal`]: no agent by any evidence,
    /// its session leader alive in its chain, and a controlling terminal).
    ///
    /// Refusing only where an agent is involved
    /// ([`SubjectEvidence::agent_involved`]) is not enough. A job a service
    /// manager starts (`launchctl submit`, `systemd-run --user`), and a
    /// process that forked out and called `setsid`, leads a session of its
    /// own or runs in pid 1's: it is no orphan and no agent is seen above
    /// it, yet it came from wherever it was started, an agent's tree
    /// included. Without a terminal no person can type there, so its
    /// proof could only be a passphrase read from a descriptor, and one
    /// that an agent captured would work. A pseudo-terminal the escaped
    /// process opens itself (`script`, `tmux`) still makes a terminal
    /// subject: see docs/AGENTS.md "Limits".
    pub fn proof_refusal(&self) -> Option<ProofRefusal> {
        if self.nearest_agent.is_some() || self.claims.claims_agent() {
            Some(ProofRefusal::Agent)
        } else if self.cut {
            Some(ProofRefusal::ChainCut)
        } else if self.orphaned() {
            Some(ProofRefusal::Orphaned)
        } else if self.kind() != SubjectKind::Terminal {
            Some(ProofRefusal::NoTerminal)
        } else {
            None
        }
    }

    /// Whether a grant rooted at `root`, approved for a subject of kind
    /// `grant_kind`, may cover this caller (SPEC §10b "Match" rules 3 and
    /// 4, and the tightening by kind):
    /// - `root` is in the chain, pid and start time alike, and is not pid 1;
    /// - no known agent sits between `root` and the caller, the caller
    ///   included, unless `root` is that agent;
    /// - a terminal grant covers only a terminal subject;
    /// - a root above this caller's session (past the leading run of its
    ///   chain in the caller's session) is an agent a builtin entry matched
    ///   by its executable or signature. Any other root, an agent matched
    ///   only on its `argv[0]`, script or command name or only through a
    ///   user extension, or a process that is no agent, covers only callers
    ///   in its own session run: a GUI app, a desktop shell, a terminal
    ///   emulator or a `tmux` server never covers the sessions it starts,
    ///   whatever their session ids (see the module documentation).
    pub fn covered_by(&self, root: &ProcessInstance, grant_kind: SubjectKind) -> bool {
        if root.pid == 1 {
            return false;
        }
        let Some(k) = self.chain.iter().position(|a| a.instance.same(root)) else {
            return false;
        };
        if self.nearest_agent.is_some_and(|n| n < k) {
            return false;
        }
        if k > self.limit && !roots_above_session(&self.chain[k]) {
            return false;
        }
        !(grant_kind == SubjectKind::Terminal && self.kind() != SubjectKind::Terminal)
    }
}

/// Whether `a` is an agent that may be a root above the caller's session:
/// a builtin entry matched its executable or signature.
fn roots_above_session(a: &Ancestor) -> bool {
    a.agent
        .as_ref()
        .is_some_and(AgentLabel::may_root_above_session)
}

/// Gathers the evidence for `peer` from the live process table: see
/// [`gather_in`].
///
/// # Errors
/// As [`gather_in`].
pub fn gather(
    peer: &PeerIdentity,
    claims: Claims,
    cat: &AgentCatalog,
) -> Result<SubjectEvidence, EvidenceError> {
    gather_in(&mut LiveProcesses, peer, claims, cat)
}

/// Whether `p` may be classified as an agent: a process of the caller's
/// uid. pid 1 is one only in a container (the host's runs as root), where
/// it may be the agent the entrypoint started.
fn classifiable(p: &ProcInfo, uid: u32) -> bool {
    p.uid == uid
}

/// Walks `peer`'s ancestry in `table` (up to [`GATHER_ATTEMPTS`] times
/// while it changes under the walk), classifies it with `cat`, and adds
/// `claims`.
///
/// # Errors
/// [`EvidenceError::CallerGone`] when the peer is no longer the process
/// that connected, [`EvidenceError::Changed`] when every walk saw a
/// change, [`EvidenceError::Hidden`] when the kernel hides an ancestor,
/// [`EvidenceError::Io`] when a read failed.
pub fn gather_in(
    table: &mut dyn ProcessTable,
    peer: &PeerIdentity,
    claims: Claims,
    cat: &AgentCatalog,
) -> Result<SubjectEvidence, EvidenceError> {
    let want_argv = |p: &ProcInfo| classifiable(p, peer.uid) && cat.needs_argv(p);
    let mut procs = None;
    for _ in 0..GATHER_ATTEMPTS {
        match ancestry_in(table, peer, MAX_ANCESTRY, &want_argv) {
            Ok(p) => {
                procs = Some(p);
                break;
            }
            Err(AncestryError::Changed) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let procs = procs.ok_or(EvidenceError::Changed)?;
    let end = if reaches_top(&procs) {
        ChainEnd::Top
    } else {
        ChainEnd::Cut
    };
    let terminal = procs.first().is_some_and(|p| p.controlling_tty);
    let chain: Vec<Ancestor> = procs
        .into_iter()
        .enumerate()
        .map(|(k, p)| {
            let agent = if classifiable(&p, peer.uid) {
                cat.classify(&p)
            } else {
                None
            };
            // The arguments go with `p` here; the evidence never holds any.
            Ancestor {
                agent,
                sid: p.sid,
                instance: ProcessInstance {
                    pid: p.pid,
                    start_time: p.start_time,
                    pidversion: if k == 0 { peer.pidversion } else { None },
                    exe: p.exe,
                },
            }
        })
        .collect();
    let claimed = claims
        .markers()
        .iter()
        .find_map(|m| cat.agent_for_marker(m));
    SubjectEvidence::from_chain(chain, end, terminal, claims, claimed)
        .ok_or(EvidenceError::CallerGone)
}
