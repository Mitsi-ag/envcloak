//! Managed MCP servers' registered launches, the parts that are pure (M2
//! plan D-05, D-18, D-33; task M2-27; SPEC §6.6): what a launch
//! declaration may hold, how its argv is classed, how an update changes
//! it, the environment a server starts with, the update statement a
//! person approves, and the sentences a launch receipt carries. The daemon
//! resolves a declaration against the file system (`launch_check` there)
//! and keeps the result sealed in the vault (`ManagedServer`).
//!
//! - [`check_declaration`]: a declaration's bounds, its variables' names,
//!   and the refusals of SPEC §6.6: a variable that selects code
//!   ([`is_code_selecting`]: `LD_*`, `DYLD_*`, `NODE_OPTIONS` and the rest
//!   of [`CODE_SELECTING`]) or an interpreter option that loads other code
//!   ([`is_code_loading_option`]) is [`DeclError::CodeSelecting`], and the
//!   server is reported as manual. The names are compared as the dynamic
//!   loader and the interpreters read them, byte for byte; case matters,
//!   as it does to them.
//! - [`classify_argv`]: a package runner (`npx`, `pnpm dlx`, `yarn dlx`,
//!   `bunx`, `uvx`, `pipx run`, and the forms that do the same:
//!   `npm exec`, `bun x`, `uv tool run`), an interpreter with an absolute
//!   entry file as its first argument that is not an option, or a program
//!   whose own file decides its class. An interpreter without such an
//!   entry file (code from standard input, a relative path) is refused:
//!   nothing of what it runs could be checked.
//! - [`apply_changes`]: the declaration stored in the record with the
//!   person's explicit changes (CR-2): never a host config, which after
//!   migration holds only the bridge.
//! - [`launch_environment`]: the server's whole environment: cleared, then
//!   [`PASSTHROUGH`] (and `LC_*`) from the runner's own environment, the
//!   recorded `PATH` and variables, and the bindings last. Nothing else
//!   the caller, the bridge or the daemon had reaches it, and no variable
//!   that selects code does, whatever any of them held.
//! - [`update_statement`] and its digest: the old and the new launch, as
//!   the person approves them with `managed.update`.
//! - [`receipt_sentences`]: what a launch receipt and the adoption
//!   statement say a class and a strength bind, and do not.

use envcloak_core::vault::{
    BindingStrength, CodeDigest, DirIdentity, FileIdentity, LaunchClass, LaunchDecl,
    RegisteredLaunch,
};
use sha2::{Digest, Sha256};

use crate::names::EnvName;

/// The variables a server's environment takes from the runner's own, as
/// SPEC §6.6 lists them, besides every `LC_*`.
pub const PASSTHROUGH: [&str; 6] = ["HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR"];

/// The variables that select the code a program runs (SPEC §6.6), refused
/// in a declaration and never passed to a server, besides every `LD_*`
/// and `DYLD_*` ([`is_code_selecting`]).
pub const CODE_SELECTING: [&str; 16] = [
    "NODE_OPTIONS",
    "NODE_PATH",
    "BUN_OPTIONS",
    "BUN_BE_BUN",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
];

/// The prefixes of the dynamic loaders' variables, every one of which
/// selects code (SPEC §6.6: `LD_*`, `DYLD_*`).
pub const LOADER_PREFIXES: [&str; 2] = ["LD_", "DYLD_"];

/// Whether `name` is a variable that selects code: a loader variable or
/// one of [`CODE_SELECTING`].
pub fn is_code_selecting(name: &str) -> bool {
    LOADER_PREFIXES.iter().any(|p| name.starts_with(p)) || CODE_SELECTING.contains(&name)
}

/// The interpreters whose first argument that is not an option names the
/// script they run (SPEC §6.6 lists `node`, `python3`, `bun`, `deno`,
/// `ruby`, `perl`, `sh` and `bash`; their common other names are taken
/// too, so none passes as a native program running code nothing checks).
const INTERPRETERS: [&str; 14] = [
    "node", "nodejs", "python", "python3", "bun", "deno", "ruby", "perl", "sh", "bash", "dash",
    "zsh", "ksh", "fish",
];

/// The interpreter options that load other code (SPEC §6.6: `-e`, `-c`,
/// `-m`, `-r`, `--require`, `--import`, `--loader`), with the forms the
/// same interpreters take for the same thing (an evaluated or printed
/// expression, a preloaded or included module). A short one also counts
/// with its value attached (`-eCODE`, `-Mstrict`), and a long one with
/// `=value`.
const CODE_LOADING_SHORT: [&str; 8] = ["-e", "-E", "-c", "-m", "-M", "-r", "-I", "-p"];
const CODE_LOADING_LONG: [&str; 9] = [
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--eval",
    "--print",
    "--preload",
    "--command",
    "--module",
];

/// Whether `arg` is an interpreter option that loads other code.
pub fn is_code_loading_option(arg: &str) -> bool {
    if let Some(long) = arg.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or(long);
        return CODE_LOADING_LONG
            .iter()
            .any(|o| o.strip_prefix("--") == Some(name));
    }
    CODE_LOADING_SHORT
        .iter()
        .any(|o| arg == *o || (arg.len() > 2 && arg.starts_with(o)))
}

/// Why a declaration, or a change to one, is refused. Carries no byte of
/// what was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclError {
    /// A variable that selects code, or an interpreter option that loads
    /// other code (`code_selecting_env`): the server is reported manual.
    CodeSelecting(CodeSelecting),
    /// No argv, or an empty argument.
    Empty,
    /// A text over [`MAX_TEXT`] bytes, a list over [`MAX_LIST`] entries, a
    /// NUL byte, or a control character in a path.
    TooLarge,
    /// A variable name that is not one, or a variable set twice.
    BadName,
    /// A relative path where an absolute one is needed (the working
    /// directory, an `argv[0]` with a `/`, an interpreter's entry file).
    NotAbsolute,
    /// An interpreter without an absolute entry file: what it runs could
    /// not be checked.
    NoEntry,
}

/// Which of the two refusals of `code_selecting_env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeSelecting {
    Variable,
    InterpreterOption,
}

impl DeclError {
    /// The reason token the refusal carries.
    pub fn token(self) -> &'static str {
        match self {
            DeclError::CodeSelecting(CodeSelecting::Variable) => "code_selecting_variable",
            DeclError::CodeSelecting(CodeSelecting::InterpreterOption) => "interpreter_option",
            DeclError::Empty => "empty_argv",
            DeclError::TooLarge => "too_large",
            DeclError::BadName => "invalid_env_name",
            DeclError::NotAbsolute => "not_absolute",
            DeclError::NoEntry => "no_entry_file",
        }
    }
}

/// The longest text one field of a declaration holds, in bytes (as the
/// record keeps it, docs/VAULT.md "Policy records").
pub const MAX_TEXT: usize = 4096;
/// The most entries one list of a declaration holds.
pub const MAX_LIST: usize = 256;

fn text_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TEXT && !s.contains('\0')
}

fn path_ok(s: &str) -> bool {
    text_ok(s) && !s.chars().any(char::is_control)
}

/// Checks a declaration as SPEC §6.6 and the record's bounds require (see
/// the module documentation): argv present and each argument a text of
/// at most [`MAX_TEXT`] bytes without NUL, at most [`MAX_LIST`] of them;
/// variables named as variables are, each once, none that selects code;
/// a working directory that is absolute; an interpreter's options
/// loading no other code.
///
/// # Errors
/// The first [`DeclError`] found.
pub fn check_declaration(d: &LaunchDecl) -> Result<(), DeclError> {
    if d.argv.is_empty() {
        return Err(DeclError::Empty);
    }
    if d.argv.len() > MAX_LIST || d.env.len() > MAX_LIST {
        return Err(DeclError::TooLarge);
    }
    for a in &d.argv {
        if a.is_empty() {
            return Err(DeclError::Empty);
        }
        if !text_ok(a) {
            return Err(DeclError::TooLarge);
        }
    }
    if let Some(cwd) = &d.cwd {
        if !path_ok(cwd) {
            return Err(DeclError::TooLarge);
        }
        if !cwd.starts_with('/') {
            return Err(DeclError::NotAbsolute);
        }
    }
    if let Some(path) = &d.path_env
        && (path.len() > MAX_TEXT || path.contains('\0'))
    {
        return Err(DeclError::TooLarge);
    }
    let mut seen: Vec<&str> = Vec::with_capacity(d.env.len());
    for (name, value) in &d.env {
        if EnvName::new(name).is_err() || seen.contains(&name.as_str()) || name == "PATH" {
            return Err(DeclError::BadName);
        }
        if is_code_selecting(name) {
            return Err(DeclError::CodeSelecting(CodeSelecting::Variable));
        }
        if value.len() > MAX_TEXT || value.contains('\0') {
            return Err(DeclError::TooLarge);
        }
        seen.push(name);
    }
    classify_argv(&d.argv).map(|_| ())
}

/// How an argv is classed before its program's file is read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgvClass {
    /// A package runner (`npx`, ...): only the runner itself can be
    /// checked; `label` names it as the receipt does (`npx`, `pnpm dlx`).
    PackageRunner { label: String },
    /// An interpreter running the absolute file `argv[entry]`.
    Interpreter { entry: usize },
    /// A program whose own file decides the class: native, or a `#!`
    /// script.
    Program,
}

/// The last component of a path.
fn base(arg: &str) -> &str {
    arg.rsplit('/').next().unwrap_or(arg)
}

/// Whether `name` is an interpreter's (`python3.12` is `python3`'s).
fn interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name)
        || name
            .strip_prefix("python")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// Classes `argv` (see the module documentation).
///
/// # Errors
/// [`DeclError::Empty`] without argv; [`DeclError::CodeSelecting`] for an
/// interpreter or runner option that loads other code before the entry
/// file; [`DeclError::NoEntry`] for an interpreter whose first argument
/// that is not an option is missing; [`DeclError::NotAbsolute`] when it
/// is not an absolute path.
pub fn classify_argv(argv: &[String]) -> Result<ArgvClass, DeclError> {
    let first = argv.first().ok_or(DeclError::Empty)?;
    let name = base(first);
    let sub = argv.get(1).map(String::as_str);
    let runner = match (name, sub) {
        ("npx" | "bunx" | "uvx", _) => Some(name.to_owned()),
        ("pnpm" | "yarn", Some("dlx")) => Some(format!("{name} dlx")),
        ("pipx", Some("run")) => Some("pipx run".to_owned()),
        ("npm", Some("exec" | "x")) => Some("npm exec".to_owned()),
        ("bun", Some("x")) => Some("bun x".to_owned()),
        ("uv", Some("tool")) if argv.get(2).map(String::as_str) == Some("run") => {
            Some("uv tool run".to_owned())
        }
        _ => None,
    };
    if let Some(label) = runner {
        // A runner's own options that run other code (`npx -c`, `--call`).
        let skip = if label.contains(' ') {
            label.matches(' ').count() + 1
        } else {
            1
        };
        for a in argv.iter().skip(skip) {
            if a == "--" || !a.starts_with('-') {
                break;
            }
            if is_code_loading_option(a) || a == "--call" || a.starts_with("--call=") {
                return Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
            }
        }
        return Ok(ArgvClass::PackageRunner { label });
    }
    if !interpreter(name) {
        return Ok(ArgvClass::Program);
    }
    // `deno run x.ts` and `bun run x.ts` name their entry after a
    // subcommand.
    let mut i = 1;
    if matches!(name, "deno" | "bun") && argv.get(1).map(String::as_str) == Some("run") {
        i = 2;
    }
    while let Some(a) = argv.get(i) {
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        if is_code_loading_option(a) {
            return Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
        }
        i += 1;
    }
    let entry = argv.get(i).ok_or(DeclError::NoEntry)?;
    if entry == "-" {
        return Err(DeclError::NoEntry);
    }
    if !entry.starts_with('/') {
        return Err(DeclError::NotAbsolute);
    }
    Ok(ArgvClass::Interpreter { entry: i })
}

/// The changes `managed.update` applies to the declaration stored in the
/// record (CR-2): each given part replaces the stored one, `set_env` sets
/// or replaces variables and `unset_env` removes them. Its `Debug` shows
/// counts and names, never a value.
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchChanges {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_env: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_env: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_env: Option<String>,
}

impl core::fmt::Debug for LaunchChanges {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let set: Vec<&str> = self.set_env.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("LaunchChanges")
            .field("argv", &self.argv.as_ref().map(Vec::len))
            .field("cwd", &self.cwd.is_some())
            .field("set_env", &set)
            .field("unset_env", &self.unset_env)
            .field("path_env", &self.path_env.is_some())
            .finish()
    }
}

/// The declaration `stored` with `changes` applied, checked as a new one
/// is ([`check_declaration`]).
///
/// # Errors
/// [`DeclError`], as [`check_declaration`]; a variable both set and unset,
/// or unset that is not there, is [`DeclError::BadName`].
pub fn apply_changes(
    stored: &LaunchDecl,
    changes: &LaunchChanges,
) -> Result<LaunchDecl, DeclError> {
    let mut d = stored.clone();
    if let Some(argv) = &changes.argv {
        d.argv.clone_from(argv);
    }
    if let Some(cwd) = &changes.cwd {
        d.cwd = Some(cwd.clone());
    }
    if let Some(path) = &changes.path_env {
        d.path_env = Some(path.clone());
    }
    for name in &changes.unset_env {
        if changes.set_env.iter().any(|(n, _)| n == name) {
            return Err(DeclError::BadName);
        }
        let before = d.env.len();
        d.env.retain(|(n, _)| n != name);
        if d.env.len() == before {
            return Err(DeclError::BadName);
        }
    }
    for (name, value) in &changes.set_env {
        if changes.set_env.iter().filter(|(n, _)| n == name).count() > 1 {
            return Err(DeclError::BadName);
        }
        match d.env.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1.clone_from(value),
            None => d.env.push((name.clone(), value.clone())),
        }
    }
    check_declaration(&d)?;
    Ok(d)
}

/// Whether `name` passes from the runner's environment to the server's.
pub fn passes_through(name: &str) -> bool {
    !is_code_selecting(name) && (PASSTHROUGH.contains(&name) || name.starts_with("LC_"))
}

/// The server's whole environment (see the module documentation), in
/// order: [`PASSTHROUGH`] and `LC_*` from `inherited` (the runner's own
/// environment, which the daemon gave it), the recorded `PATH`, the
/// recorded variables, then the bindings; a later entry replaces an
/// earlier one of its name. A name that selects code is dropped wherever
/// it comes from; a recorded variable cannot be one (the record refuses
/// it), and an inherited one is not on the list. Values are bytes; the
/// bindings' are the released values.
pub fn launch_environment<'a>(
    inherited: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    path_env: &[u8],
    vars: &[(String, String)],
    bindings: &[(&'a str, &'a [u8])],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut put = |name: &[u8], value: &[u8]| {
        let Ok(n) = std::str::from_utf8(name) else {
            return;
        };
        if is_code_selecting(n) || EnvName::new(n).is_err() {
            return;
        }
        out.retain(|(k, _)| k.as_slice() != name);
        out.push((name.to_vec(), value.to_vec()));
    };
    for (name, value) in inherited {
        if std::str::from_utf8(name).is_ok_and(passes_through) {
            put(name, value);
        }
    }
    put(b"PATH", path_env);
    for (name, value) in vars {
        if name != "PATH" {
            put(name.as_bytes(), value.as_bytes());
        }
    }
    for (name, value) in bindings {
        put(name.as_bytes(), value);
    }
    out
}

/// A launch id as it is shown and sent: 26 Crockford base32 characters
/// (16 random bytes, as a grant id is written).
pub fn launch_id_text(id: &[u8; 16]) -> String {
    crate::ids::encode(id, 26)
}

/// A launch id from its 26-character form, in either case.
pub fn parse_launch_id(s: &str) -> Option<[u8; 16]> {
    let mut b = [0u8; 16];
    crate::ids::decode(s, 26, &mut b)?;
    Some(b)
}

/// A new launch id: 16 random bytes.
pub fn new_launch_id() -> [u8; 16] {
    crate::ids::random::<16>()
}

/// The first line of an update statement (docs/IPC.md "Statement
/// domains").
pub const UPDATE_DOMAIN: &[u8] = b"envcloak-managed-update/1\n";

struct Enc(Vec<u8>);

impl Enc {
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(&b[..len as usize]);
        self
    }

    fn num(&mut self, n: u64) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    fn flag(&mut self, b: bool) -> &mut Self {
        self.0.push(u8::from(b));
        self
    }
}

fn file(e: &mut Enc, f: &FileIdentity) {
    e.bytes(&f.path).num(f.dev).num(f.ino);
    match &f.digest {
        CodeDigest::Sha256(d) => {
            e.bytes(b"sha256").bytes(d);
        }
        CodeDigest::CdHash {
            cdhash,
            team,
            identifier,
        } => {
            e.bytes(b"cdhash").bytes(cdhash);
            e.flag(team.is_some())
                .bytes(team.as_deref().unwrap_or("").as_bytes());
            e.flag(identifier.is_some())
                .bytes(identifier.as_deref().unwrap_or("").as_bytes());
        }
    }
}

fn dir(e: &mut Enc, d: &DirIdentity) {
    e.bytes(&d.path).num(d.dev).num(d.ino);
}

fn launch(e: &mut Enc, l: &RegisteredLaunch) {
    e.num(l.revision)
        .bytes(class_word(l.class).as_bytes())
        .bytes(strength_word(l.strength).as_bytes());
    file(e, &l.executable);
    e.num(l.argv.len() as u64);
    for a in &l.argv {
        e.bytes(a);
    }
    dir(e, &l.cwd);
    e.bytes(&l.env.path_env).num(l.env.vars.len() as u64);
    for (n, v) in &l.env.vars {
        e.bytes(n.as_bytes()).bytes(v.as_bytes());
    }
    e.num(l.env.binding_names.len() as u64);
    for n in &l.env.binding_names {
        e.bytes(n.as_bytes());
    }
    e.flag(l.entry.is_some());
    if let Some(entry) = &l.entry {
        file(e, entry);
    }
    let d = &l.declaration;
    e.num(d.argv.len() as u64);
    for a in &d.argv {
        e.bytes(a.as_bytes());
    }
    e.flag(d.cwd.is_some())
        .bytes(d.cwd.as_deref().unwrap_or("").as_bytes());
    e.num(d.env.len() as u64);
    for (n, v) in &d.env {
        e.bytes(n.as_bytes()).bytes(v.as_bytes());
    }
    e.flag(d.path_env.is_some())
        .bytes(d.path_env.as_deref().unwrap_or("").as_bytes());
}

/// The canonical bytes of the update from `old` to `new` of the launch
/// `launch_id` (`new` is the next revision): every field of both, the
/// declarations and the variables' values included, under
/// [`UPDATE_DOMAIN`], so a statement whose launch changed between plan
/// and update has another digest (`statement_mismatch`).
pub fn update_statement(
    launch_id: &[u8; 16],
    old: &RegisteredLaunch,
    new: &RegisteredLaunch,
) -> Vec<u8> {
    let mut e = Enc(Vec::with_capacity(1024));
    e.0.extend_from_slice(UPDATE_DOMAIN);
    e.bytes(launch_id);
    launch(&mut e, old);
    launch(&mut e, new);
    e.0
}

/// SHA-256 of [`update_statement`].
pub fn update_digest(
    launch_id: &[u8; 16],
    old: &RegisteredLaunch,
    new: &RegisteredLaunch,
) -> [u8; 32] {
    Sha256::digest(update_statement(launch_id, old, new)).into()
}

/// A class's word, as the receipt and the record's display show it.
pub fn class_word(c: LaunchClass) -> &'static str {
    match c {
        LaunchClass::Native => "native",
        LaunchClass::Script => "script",
        LaunchClass::PackageRunner => "package_runner",
    }
}

/// A binding strength's word.
pub fn strength_word(s: BindingStrength) -> &'static str {
    match s {
        BindingStrength::Bound => "bound",
        BindingStrength::CheckedAtRest => "checked_at_rest",
    }
}

/// What every receipt of a managed server says it does not stop (D-05;
/// SPEC §6.6 "What it does not stop"), with the agent's name in it.
pub fn residual_sentence(agent: &str) -> String {
    format!(
        "only this server's exact command can receive its key, but any program {agent} runs can \
         start that command and read the key from its environment"
    )
}

/// The sentences a launch receipt carries for `class` and `strength`
/// (SPEC §6.6, D-33): what is bound and what is not. `runner` names a
/// package runner as the receipt does.
pub fn receipt_sentences(
    class: LaunchClass,
    strength: BindingStrength,
    runner: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    match (class, strength) {
        (LaunchClass::Native, BindingStrength::Bound) => out.push(
            "bound: the program that runs is the checked executable (on Linux a sealed copy of \
             it, on macOS only once the started program's code directory hash matches)"
                .to_owned(),
        ),
        (LaunchClass::Native, BindingStrength::CheckedAtRest) => out.push(
            "checked_at_rest: EnvCloak checks the executable before launch; a change made \
             between that check and the start is not caught, and this launch cannot have a \
             standing approval"
                .to_owned(),
        ),
        (LaunchClass::Script, _) => out.push(
            "checked_at_rest: EnvCloak checks the interpreter and the entry script before \
             launch, not the modules it loads or a change made during launch"
                .to_owned(),
        ),
        (LaunchClass::PackageRunner, _) => {
            let r = runner.unwrap_or("the package runner");
            out.push(format!(
                "checked_at_rest: the code that runs is chosen by {r} at launch; to pin it, \
                 install the package and register its entry file"
            ));
        }
    }
    out.push(
        "the guarantee covers the server's main executable only, not its dynamic loader, the \
         shared libraries it loads or anything they load"
            .to_owned(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(argv: &[&str]) -> LaunchDecl {
        LaunchDecl {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: None,
            env: Vec::new(),
            path_env: None,
        }
    }

    /// Every variable SPEC §6.6 names selects code, with every loader
    /// variable; ordinary ones and near misses do not.
    #[test]
    fn the_code_selecting_variables_are_exactly_the_specs() {
        for n in CODE_SELECTING {
            assert!(is_code_selecting(n), "{n}");
        }
        for n in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_X",
        ] {
            assert!(is_code_selecting(n), "{n}");
        }
        for n in [
            "PATH",
            "HOME",
            "NODE_ENV",
            "OPENAI_API_KEY",
            "LDFLAGS",
            "XLD_PRELOAD",
            "env",
        ] {
            assert!(!is_code_selecting(n), "{n}");
        }
    }

    /// A declared variable that selects code, and an interpreter option
    /// that loads code before the entry file, are `code_selecting_env`;
    /// the same text after the entry file is the script's own argument.
    #[test]
    fn code_selecting_declarations_are_refused() {
        let mut d = decl(&["/usr/bin/server"]);
        d.env
            .push(("NODE_OPTIONS".into(), "--require /tmp/x.js".into()));
        assert_eq!(
            check_declaration(&d),
            Err(DeclError::CodeSelecting(CodeSelecting::Variable))
        );
        for argv in [
            &["node", "-r", "x.js", "/srv/server.js"][..],
            &["node", "--require=x.js", "/srv/server.js"],
            &["node", "--import", "x.mjs", "/srv/server.js"],
            &["node", "--loader", "x.mjs", "/srv/server.js"],
            &["node", "-e", "require('x')"],
            &["python3", "-c", "import x"],
            &["python3", "-m", "server"],
            &["ruby", "-Ilib", "/srv/s.rb"],
            &["perl", "-Mstrict", "/srv/s.pl"],
            &["bun", "--preload", "x.ts", "/srv/s.ts"],
            &["npx", "-c", "echo"],
        ] {
            assert_eq!(
                classify_argv(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()),
                Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                "{argv:?}"
            );
        }
        assert_eq!(
            classify_argv(&["node".into(), "/srv/s.js".into(), "-e".into()]),
            Ok(ArgvClass::Interpreter { entry: 1 })
        );
    }

    #[test]
    fn argv_classes() {
        let c = |a: &[&str]| classify_argv(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(
            c(&["/opt/srv/bin/server", "--port", "1"]),
            Ok(ArgvClass::Program)
        );
        assert_eq!(c(&["server"]), Ok(ArgvClass::Program));
        assert_eq!(
            c(&["node", "/srv/server.js"]),
            Ok(ArgvClass::Interpreter { entry: 1 })
        );
        assert_eq!(
            c(&["/usr/bin/python3.12", "-u", "/srv/s.py"]),
            Ok(ArgvClass::Interpreter { entry: 2 })
        );
        assert_eq!(
            c(&["deno", "run", "/srv/s.ts"]),
            Ok(ArgvClass::Interpreter { entry: 2 })
        );
        assert_eq!(c(&["node", "server.js"]), Err(DeclError::NotAbsolute));
        assert_eq!(c(&["node"]), Err(DeclError::NoEntry));
        assert_eq!(c(&["bash", "-"]), Err(DeclError::NoEntry));
        for (argv, label) in [
            (&["npx", "-y", "pkg"][..], "npx"),
            (&["/usr/local/bin/bunx", "pkg"], "bunx"),
            (&["uvx", "pkg"], "uvx"),
            (&["pnpm", "dlx", "pkg"], "pnpm dlx"),
            (&["yarn", "dlx", "pkg"], "yarn dlx"),
            (&["pipx", "run", "pkg"], "pipx run"),
            (&["npm", "exec", "pkg"], "npm exec"),
            (&["uv", "tool", "run", "pkg"], "uv tool run"),
        ] {
            assert_eq!(
                c(argv),
                Ok(ArgvClass::PackageRunner {
                    label: label.to_owned()
                }),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn bounds_and_names() {
        assert_eq!(check_declaration(&decl(&[])), Err(DeclError::Empty));
        assert_eq!(check_declaration(&decl(&["/a", ""])), Err(DeclError::Empty));
        assert_eq!(
            check_declaration(&decl(&["/a\0b"])),
            Err(DeclError::TooLarge)
        );
        let long = "x".repeat(MAX_TEXT + 1);
        assert_eq!(
            check_declaration(&decl(&["/a", &long])),
            Err(DeclError::TooLarge)
        );
        let mut d = decl(&["/a"]);
        d.cwd = Some("relative/dir".into());
        assert_eq!(check_declaration(&d), Err(DeclError::NotAbsolute));
        let mut d = decl(&["/a"]);
        d.env = vec![("1BAD".into(), "x".into())];
        assert_eq!(check_declaration(&d), Err(DeclError::BadName));
        d.env = vec![("A".into(), "x".into()), ("A".into(), "y".into())];
        assert_eq!(check_declaration(&d), Err(DeclError::BadName));
        d.env = vec![("PATH".into(), "/bin".into())];
        assert_eq!(check_declaration(&d), Err(DeclError::BadName));
    }

    /// An update starts from the stored declaration and changes only what
    /// is given; a changed variable that selects code is refused.
    #[test]
    fn changes_apply_to_the_stored_declaration() {
        let mut stored = decl(&["/srv/server", "--a"]);
        stored.env = vec![("MODE".into(), "x".into()), ("GONE".into(), "y".into())];
        stored.cwd = Some("/srv".into());
        let ch = LaunchChanges {
            argv: Some(vec!["/srv/server2".into()]),
            cwd: Some("/srv2".into()),
            set_env: vec![("MODE".into(), "z".into()), ("NEW".into(), "w".into())],
            unset_env: vec!["GONE".into()],
            path_env: Some("/bin".into()),
        };
        let d = apply_changes(&stored, &ch).unwrap();
        assert_eq!(d.argv, vec!["/srv/server2"]);
        assert_eq!(d.cwd.as_deref(), Some("/srv2"));
        assert_eq!(
            d.env,
            vec![
                ("MODE".to_owned(), "z".to_owned()),
                ("NEW".to_owned(), "w".to_owned())
            ]
        );
        assert_eq!(d.path_env.as_deref(), Some("/bin"));
        assert_eq!(
            apply_changes(&stored, &LaunchChanges::default()).unwrap(),
            stored
        );
        let bad = LaunchChanges {
            set_env: vec![("NODE_OPTIONS".into(), "--require x".into())],
            ..LaunchChanges::default()
        };
        assert_eq!(
            apply_changes(&stored, &bad),
            Err(DeclError::CodeSelecting(CodeSelecting::Variable))
        );
        let missing = LaunchChanges {
            unset_env: vec!["NOPE".into()],
            ..LaunchChanges::default()
        };
        assert_eq!(apply_changes(&stored, &missing), Err(DeclError::BadName));
        assert!(!format!("{ch:?}").contains('z'), "Debug shows no value");
    }

    /// The environment builder: whatever the runner's environment holds
    /// (every loader and interpreter variable SPEC §6.6 names, set by the
    /// bridge or the daemon), the server gets the passthrough list, the
    /// recorded PATH and variables and the bindings, and nothing else.
    #[test]
    fn the_server_environment_drops_everything_else_and_every_code_selecting_variable() {
        let mut inherited: Vec<(String, String)> = vec![
            ("HOME".into(), "/home/p".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C".into()),
            ("TMPDIR".into(), "/tmp/x".into()),
            ("PATH".into(), "/evil/bin".into()),
            ("SHELL".into(), "/bin/zsh".into()),
            ("SECRET_FROM_BRIDGE".into(), "nope".into()),
            ("LC_LD_PRELOAD".into(), "fine".into()),
        ];
        for n in CODE_SELECTING {
            inherited.push((n.into(), "x".into()));
        }
        for n in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ] {
            inherited.push((n.into(), "/tmp/evil.so".into()));
        }
        let vars = vec![("MODE".to_owned(), "prod".to_owned())];
        let env = launch_environment(
            inherited.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())),
            b"/usr/bin:/bin",
            &vars,
            &[("API_KEY", b"value-bytes")],
        );
        let names: Vec<&str> = env
            .iter()
            .map(|(n, _)| std::str::from_utf8(n).unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "HOME",
                "LANG",
                "LC_ALL",
                "TMPDIR",
                "LC_LD_PRELOAD",
                "PATH",
                "MODE",
                "API_KEY"
            ]
        );
        let get = |n: &str| {
            env.iter()
                .find(|(k, _)| k == n.as_bytes())
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("PATH").unwrap(), b"/usr/bin:/bin");
        assert_eq!(get("API_KEY").unwrap(), b"value-bytes");
        for (n, _) in &env {
            assert!(!is_code_selecting(std::str::from_utf8(n).unwrap()));
        }
    }

    #[test]
    fn receipts_name_what_is_not_bound() {
        let s = receipt_sentences(
            LaunchClass::PackageRunner,
            BindingStrength::CheckedAtRest,
            Some("npx"),
        );
        assert!(s[0].contains("chosen by npx at launch"));
        assert!(s.iter().any(|x| x.contains("main executable only")));
        let s = receipt_sentences(LaunchClass::Script, BindingStrength::CheckedAtRest, None);
        assert!(s[0].contains("interpreter and the entry script"));
        assert!(residual_sentence("Claude Code").contains("any program Claude Code runs"));
    }
}
