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
//!   as it does to them. npm configuration names are case insensitive.
//! - [`classify_argv`]: a package runner or another launcher whose code is
//!   chosen when it starts ([`PACKAGE_RUNNERS`]: `npx`, `uv`, `docker`,
//!   `java` and the rest, in any of their forms: `uv --directory d run`,
//!   `npm start`, `docker run`, `java -jar`), an interpreter with an
//!   absolute entry file as its first argument that is not an option
//!   ([`INTERPRETERS`], by name with any version: `python3.12`, `node22`,
//!   `ruby3.2`, `perl5.34`), or a program whose own file decides its
//!   class. An interpreter without such an entry file (code from standard
//!   input or an argument, a relative path) is refused, and so is a
//!   program that starts another one its arguments name ([`WRAPPERS`]:
//!   `env`, `nice`, `stdbuf`, a dynamic loader run as a program):
//!   nothing of what they run could be checked. [`refuse_disguised`]
//!   refuses a launcher known by another name (a link named `server` to
//!   `node`), by the name of the file `argv[0]` resolves to. None of these
//!   passes as a native program, whose class binds what runs.
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
/// and `DYLD_*` and the Lua variables of [`CODE_SELECTING_PREFIXES`]
/// ([`is_code_selecting`]). Beyond SPEC's list, each interpreter of
/// [`INTERPRETERS`] has its own here: a module or library path, a file run
/// at start, a debugger, an ini or gem directory, a cache of compiled code,
/// a configuration directory a shell reads. And the variables that name a
/// native library or plug-in a program loads by its own choice (OpenSSL's
/// configuration and its engines and providers, GIO, Qt, GStreamer and GTK
/// modules): a `bound` server would load what they name.
pub const CODE_SELECTING: &[&str] = &[
    "NODE_OPTIONS",
    "NODE_PATH",
    "BUN_OPTIONS",
    "BUN_BE_BUN",
    "DENO_DIR",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHON_PRESITE",
    "PYTHONWARNINGS",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PYTHONBREAKPOINT",
    "PYTHONPYCACHEPREFIX",
    "PYTHONPLATLIBDIR",
    "PERL5LIB",
    "PERLLIB",
    "PERL5OPT",
    "PERL5DB",
    "PERLIO",
    "RUBYLIB",
    "RUBYOPT",
    "GEM_PATH",
    "GEM_HOME",
    "BUNDLE_GEMFILE",
    "PHPRC",
    "PHP_INI_SCAN_DIR",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_DIRS",
    "GCONV_PATH",
    "LUA_INIT",
    "LUA_PATH",
    "OPENSSL_CONF",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "GIO_MODULE_DIR",
    "GIO_EXTRA_MODULES",
    "QT_PLUGIN_PATH",
    "GST_PLUGIN_PATH",
    "GST_PLUGIN_SYSTEM_PATH",
    "GTK_PATH",
    "GTK_MODULES",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "R_LIBS",
    "R_LIBS_USER",
    "JULIA_LOAD_PATH",
    "JULIA_DEPOT_PATH",
    "JULIA_PROJECT",
    "ERL_LIBS",
    "ERL_FLAGS",
    "ERL_AFLAGS",
    "ERL_ZFLAGS",
    "ELIXIR_ERL_OPTIONS",
    "TCLLIBPATH",
    "RAKULIB",
    "PERL6LIB",
    "GUILE_LOAD_PATH",
    "GUILE_LOAD_COMPILED_PATH",
    "PLTCOLLECTS",
    "PLTUSERHOME",
    "PSModulePath",
    "AWKPATH",
    "MAKEFILES",
];

/// The prefixes of the dynamic loaders' variables, every one of which
/// selects code (SPEC §6.6: `LD_*`, `DYLD_*`).
pub const LOADER_PREFIXES: [&str; 2] = ["LD_", "DYLD_"];

/// The prefixes of other variables that select code under a versioned
/// name too (`LUA_INIT_5_4`, `LUA_PATH_5_4`, `LUA_CPATH`).
pub const CODE_SELECTING_PREFIXES: [&str; 3] = ["LUA_INIT", "LUA_PATH", "LUA_CPATH"];

/// Whether `name` is a variable that selects code: a loader variable, one
/// of [`CODE_SELECTING`], or one of [`CODE_SELECTING_PREFIXES`] in any
/// version.
pub fn is_code_selecting(name: &str) -> bool {
    // npm normalizes both the prefix and the key without regard to case.
    // Unknown configuration may select code in a newer npm release.
    if let Some(key) = name.get(11..).filter(|_| {
        name.get(..11)
            .is_some_and(|p| p.eq_ignore_ascii_case("npm_config_"))
    }) {
        return !["registry", "cache", "fund", "audit", "update_notifier"]
            .iter()
            .any(|allowed| key.eq_ignore_ascii_case(allowed));
    }
    LOADER_PREFIXES
        .iter()
        .chain(CODE_SELECTING_PREFIXES.iter())
        .any(|p| name.starts_with(p))
        || CODE_SELECTING.contains(&name)
}

/// The interpreters whose first argument that is not an option names the
/// script they run (SPEC §6.6 lists `node`, `python3`, `bun`, `deno`,
/// `ruby`, `perl`, `sh` and `bash`; their common other names are taken
/// too, so none passes as a native program running code nothing checks).
/// [`VERSIONED`] ones count with a version after the name (`python3.12`,
/// `node22`, `ruby3.2`, `perl5.34`).
///
/// Beyond SPEC's list, the other common programs that run a script file
/// their first argument names (`Rscript`, `julia`, `tclsh`, `pwsh`,
/// `osascript`, `swift` and the rest): classed as interpreters, each runs
/// as a `script` launch whose entry file is checked, never as a native
/// program whose class would bind it.
pub const INTERPRETERS: &[&str] = &[
    "node",
    "nodejs",
    "python",
    "pypy",
    "graalpy",
    "micropython",
    "truffleruby",
    "bun",
    "deno",
    "ruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "fish",
    "Rscript",
    "julia",
    "tclsh",
    "wish",
    "pwsh",
    "raku",
    "rakudo",
    "guile",
    "racket",
    "elixir",
    "escript",
    "osascript",
    "swift",
];

/// The interpreters known by their name with a version after it.
const VERSIONED: &[&str] = &[
    "node",
    "nodejs",
    "python",
    "pypy",
    "bun",
    "deno",
    "ruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "guile",
    "graalpy",
    "micropython",
    "truffleruby",
];

/// The launchers whose code is chosen when they start, from a package, a
/// project, an image or a class path that EnvCloak does not check: each is
/// a package runner in any form (`uv run`, `uv --directory d run`, `npm
/// start`, `docker run`, `java -jar`), checked at rest, its label naming
/// the form. The programs whose arguments name the code they run in a way
/// EnvCloak does not read (an `awk` program or its `-f` files, a `make`
/// target, an `erl` module, `R CMD`) are classed with them: their code is
/// checked at rest, never bound.
pub const PACKAGE_RUNNERS: &[&str] = &[
    "npx", "pnpx", "bunx", "uvx", "pipx", "uv", "npm", "pnpm", "yarn", "poetry", "pdm", "hatch",
    "pipenv", "rye", "conda", "mamba", "docker", "podman", "nerdctl", "java", "go", "cargo",
    "dotnet", "mvn", "awk", "gawk", "mawk", "nawk", "make", "gmake", "erl", "R",
];

/// The programs that start another one their arguments name, with
/// arguments or an environment of their own (`env FOO=1 node x.js`,
/// `nice node x.js`), and the dynamic loaders run as programs: what they
/// start could not be checked, so a declaration naming one is refused.
pub const WRAPPERS: &[&str] = &[
    "env",
    "nice",
    "nohup",
    "stdbuf",
    "timeout",
    "time",
    "xargs",
    "sudo",
    "doas",
    "su",
    "runuser",
    "setsid",
    "chrt",
    "ionice",
    "taskset",
    "caffeinate",
    "arch",
    "unbuffer",
    "flock",
    "chroot",
    "script",
    "dyld",
    "busybox",
];

/// Whether `name` is a dynamic loader's file run as a program (`ld.so`,
/// `ld-linux-x86-64.so.2`, `ld-musl-aarch64.so.1`).
fn dynamic_loader(name: &str) -> bool {
    name == "ld.so" || name.starts_with("ld-linux") || name.starts_with("ld-musl")
}

/// The [`WRAPPERS`] GNU's packages for macOS install with a `g` before
/// their name, beside the system's own (Homebrew's `coreutils`,
/// `findutils` and `gnu-time`: `gtimeout`, `genv`, `gxargs`, `gtime`).
const GNU_PREFIXED: &[&str] = &[
    "env", "nice", "nohup", "stdbuf", "timeout", "time", "xargs", "chroot",
];

/// Whether `name` starts another program its arguments name
/// ([`WRAPPERS`], and [`GNU_PREFIXED`] ones with their `g`).
pub fn is_wrapper(name: &str) -> bool {
    WRAPPERS.contains(&name)
        || name
            .strip_prefix('g')
            .is_some_and(|n| GNU_PREFIXED.contains(&n))
        || dynamic_loader(name)
}

/// The interpreter options that load other code (SPEC §6.6: `-e`, `-c`,
/// `-m`, `-r`, `--require`, `--import`, `--loader`), with the forms the
/// same interpreters take for the same thing (an evaluated or printed
/// expression, a preloaded or included module). A short one counts
/// anywhere in a cluster of short options (`-ec`, `-we`, `-Bc`, `-xc`), so
/// also with its value attached (`-eCODE`, `-Mstrict`); a long one also
/// with `=value`.
const CODE_LOADING_SHORT: [char; 8] = ['e', 'E', 'c', 'm', 'M', 'r', 'I', 'p'];
/// The short options that, before an interpreter's entry file, load code
/// or take it from elsewhere besides [`CODE_LOADING_SHORT`]: an
/// interactive session or commands from standard input (`-i`, `sh -s`),
/// a debugger or an ini setting (`perl -d:Mod`, `php -d`), a library
/// (`lua -l`), an extension (`php -z`), resolution conditions (`node -C`),
/// a file loaded first or a library directory (`julia -L`, `guile -L`,
/// `swift -L`). Some are harmless to one interpreter and load code in
/// another; each is refused for all.
const INTERPRETER_LOADING_SHORT: [char; 7] = ['i', 's', 'd', 'l', 'z', 'C', 'L'];

/// The short options of one interpreter family that load code besides
/// [`CODE_LOADING_SHORT`] and [`INTERPRETER_LOADING_SHORT`]: a system
/// image (`julia -J`), a file required or loaded (`racket -t`, `-f`,
/// `-u`, `-k`), a script found on `PATH` (`elixir -S`), a framework
/// directory (`swift -F`), an extension (`guile -x`).
fn stem_loading_short(stem: &str) -> &'static [char] {
    match stem {
        "julia" => &['J'],
        "php" => &['f', 'F', 'B', 'R', 'S', 'a'],
        "racket" => &['t', 'f', 'u', 'k'],
        "elixir" => &['S'],
        "swift" => &['F'],
        "guile" => &['x'],
        _ => &[],
    }
}

const CODE_LOADING_LONG: [&str; 31] = [
    "--inspect",
    "--inspect-brk",
    "--inspect-wait",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--eval",
    "--print",
    "--preload",
    "--command",
    "--module",
    "--interactive",
    "--conditions",
    "--env-file",
    "--env-file-if-exists",
    "--experimental-config-file",
    "--experimental-default-config-file",
    "--config",
    "--import-map",
    "--rcfile",
    "--init-file",
    "--experimental-policy",
    "--snapshot-blob",
    "--build-snapshot",
    "--openssl-config",
    "--experimental-sea-config",
    "--run",
    "--test",
    "--watch-path",
    "--login",
];

/// The long interpreter options that take a value attached with `=` and
/// load no code (`node --max-old-space-size=512`, `deno run
/// --allow-net=host`, `ruby --encoding=utf-8`). Any other long option
/// with `=value` is refused as one that may load code: which options of
/// which interpreter read a file of code (`node --snapshot-blob=`,
/// `--openssl-config=`) is not a list EnvCloak can keep complete, so the
/// list kept is of the harmless ones.
const VALUE_LONG: [&str; 14] = [
    "--max-old-space-size",
    "--max-semi-space-size",
    "--stack-size",
    "--title",
    "--unhandled-rejections",
    "--dns-result-order",
    "--max-http-header-size",
    "--stack-trace-limit",
    "--encoding",
    "--external-encoding",
    "--internal-encoding",
    "--threads",
    "--optimize",
    "--color",
];

/// The prefixes of long interpreter options that may take a value with
/// `=` and load no code (deno's permission flags: `--allow-net=host`).
const VALUE_LONG_PREFIXES: [&str; 2] = ["--allow-", "--deny-"];

/// The long options of interpreter family `stem` that take no value, and
/// so may stand before the entry file without `=`, exactly and by prefix.
/// Any other long option without `=` may take the next argument as its
/// value (`node --title /a /b.js` runs `/b.js`), so which argument is the
/// entry file is not known. Each family's list is its own, measured on
/// that interpreter: an option or a prefix that takes no value in one
/// takes one in another (review of M2-27: Node's `--allow-fs-read`,
/// `--allow-fs-write`, `--disable-warning` and `--disable-proto` take the
/// next argument, so `node --allow-fs-read /a -e code` runs `code`, while
/// deno's `--allow-read` takes a value only after `=`). A prefix stands
/// only where every option it matches was measured, as a sweep of the
/// interpreter's own option table: Node 26.7.0 has none (its `--no-print`
/// still evaluates, so each negation is listed), Bun 1.3.13 runs the
/// first file after any `--no-` form, `--no-print` and `--no-eval`
/// included, Ruby 2.6, Deno 2.9.7 (its oracle sweeps every `--allow-`,
/// `--deny-` and `--no-` option of `deno run`), `/bin/bash` 3.2
/// and `/bin/zsh` on macOS (every zsh option's `--no-` form). TruffleRuby
/// was never measured and has none.
fn boolean_long(stem: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match stem {
        "node" | "nodejs" => (
            &[
                "--trace-warnings",
                "--trace-deprecation",
                "--trace-uncaught",
                "--enable-source-maps",
                "--expose-gc",
                "--pending-deprecation",
                "--throw-deprecation",
                "--preserve-symlinks",
                "--allow-addons",
                "--allow-child-process",
                "--allow-wasi",
                "--allow-worker",
                "--allow-net",
                "--allow-ffi",
                "--allow-inspector",
                "--allow-openssl-store",
                "--disable-sigusr1",
                "--disable-wasm-trap-handler",
                "--enable-fips",
                "--permission",
                "--permission-audit",
                // Node takes `--no-` before a boolean option only, but
                // `--print` is one, and `--no-print` still turns on eval
                // mode (review of M2-27: `node --no-print <file>` evaluates
                // the file's name as code). So each negation is listed:
                // each turns off a feature, none names a mode, and each
                // was measured to run the first file on Node 26.7.0.
                "--no-warnings",
                "--no-deprecation",
                "--no-addons",
                "--no-global-search-paths",
                "--no-experimental-websocket",
                "--no-experimental-global-navigator",
                "--no-experimental-require-module",
                "--no-require-module",
                "--no-experimental-detect-module",
                "--no-experimental-strip-types",
                "--no-strip-types",
                "--no-experimental-sqlite",
                "--no-experimental-webstorage",
                "--no-webstorage",
                "--no-experimental-eventsource",
                "--no-network-family-autoselection",
                "--no-enable-network-family-autoselection",
                "--no-extra-info-on-fatal-exception",
                "--no-force-async-hooks-checks",
                "--no-trace-warnings",
                "--no-trace-deprecation",
                "--no-trace-uncaught",
                "--no-enable-source-maps",
                "--no-pending-deprecation",
                "--no-throw-deprecation",
                "--no-preserve-symlinks",
                "--no-preserve-symlinks-main",
                "--no-insecure-http-parser",
                "--no-use-env-proxy",
                "--no-use-system-ca",
                "--no-use-openssl-ca",
                "--no-use-bundled-ca",
                "--no-async-context-frame",
                "--no-frozen-intrinsics",
                "--no-zero-fill-buffers",
                "--no-abort-on-uncaught-exception",
                "--no-expose-gc",
            ],
            &[],
        ),
        "deno" => (&["--quiet"], &["--no-", "--allow-", "--deny-"]),
        "bun" => (&["--smol"], &["--no-"]),
        "ruby" => (
            &["--verbose", "--jit", "--yjit"],
            &["--enable-", "--disable-"],
        ),
        "bash" => (&["--norc", "--noprofile", "--posix", "--verbose"], &[]),
        "zsh" => (&[], &["--no-"]),
        _ => (&[], &[]),
    }
}

/// The short options of an interpreter family whose value is the whole
/// rest of their cluster, or, when nothing is attached, may be the next
/// argument (`python -W ignore`, `python -X dev`, `php -t /root`, `julia
/// -t 4`; `ruby -F:` takes the rest and never the next one, so a bare
/// `-F` is refused as [`DeclError::NoEntry`] too). Each parser listed here
/// was read to consume the rest of the cluster as the value: an option
/// whose parser reads a short value and then goes on reading the rest of
/// the cluster as more options (ruby's `-W`, `-K`; review of M2-27:
/// `ruby -We'code'` runs the code) is not one of these, and is handled
/// in [`interpreter_option`] letter by letter.
fn value_short(stem: &str) -> &'static [char] {
    match stem {
        "python" | "pypy" => &['W', 'X'],
        "ruby" => &['F'],
        "php" => &['t'],
        "julia" => &['t', 'p', 'O', 'g'],
        _ => &[],
    }
}

/// The short options of a shell that set a shell option by name (`-o`,
/// `-O`). Shells disagree on where the name is: bash and dash take the
/// next argument whatever follows in the cluster (`bash -oposix /s.sh`
/// reads `/s.sh` as the option's name and then `p`, `o`, `s`, `i`, `x` as
/// more options; `bash -Oc extglob 'code'` runs `code`), zsh and ksh the
/// rest of the cluster. Which argument is the entry file is not known
/// either way: [`DeclError::NoEntry`], attached or not (measured with
/// `/bin/bash` 3.2, `/bin/dash`, `/bin/zsh` and `/bin/ksh` on macOS).
fn shell_named_option(stem: &str, c: char) -> bool {
    matches!(
        stem,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "fish"
    ) && matches!(c, 'o' | 'O')
}

/// Whether `category` is what ruby's `-W:` takes (`-W:no-deprecated`,
/// `-W:exp`): an optional `no-` and a leading part of one of its warning
/// categories. Ruby reads the whole rest of the cluster as the category,
/// so nothing after it is an option; anything else is refused all the
/// same rather than trusted to be harmless.
fn ruby_warning_category(category: &str) -> bool {
    let name = category.strip_prefix("no-").unwrap_or(category);
    !name.is_empty()
        && [
            "deprecated",
            "experimental",
            "performance",
            "strict_unused_block",
        ]
        .iter()
        .any(|c| c.starts_with(name))
}

/// The short options of interpreter family `stem` known to load no code
/// and to take no value (`python -u`, `bash -x`, `deno -A`, `perl -w`).
/// Any other letter before the entry file is refused as one that may load
/// code: which letters of which interpreter load a module is not a list
/// EnvCloak can keep complete (review of M2-27: `luajit -jv` and `luajit
/// -b` load `jit.v` and `jit.bcsave` through the search path, whose first
/// entry is `./?.lua`, before the entry file runs), so, as for long
/// options with a value ([`VALUE_LONG`]), the list kept is of the
/// harmless ones. A family not named here takes no short option.
fn harmless_short(stem: &str) -> &'static [char] {
    match stem {
        "python" | "pypy" => &['u', 'B', 'O', 'q', 'S', 'b', 'v', 'R', 'P'],
        "ruby" => &['w', 'v', 'U'],
        "perl" => &['w', 'W', 'X', 'T', 't', 'U'],
        "php" => &['n', 'q', 'H'],
        "lua" => &['v', 'W'],
        "luajit" => &['v'],
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "fish" => &['x', 'v', 'u', 'f', 'a', 'n'],
        "julia" => &['q'],
        "deno" => &['A', 'q'],
        _ => &[],
    }
}

/// The short options of interpreter family `stem` whose value, if any, is
/// the whole rest of their argument and never the next argument, and
/// loads no code: an optimisation setting (`luajit -O3`, `luajit
/// -O+fold`; LuaJIT hands the whole argument after `-O` to `jit.opt`).
/// Ruby's `-W` is not one: it reads one digit and goes on reading the rest
/// as options ([`interpreter_option`]).
fn attached_short(stem: &str) -> &'static [char] {
    match stem {
        "luajit" => &['O'],
        _ => &[],
    }
}

/// Whether `arg` is an option that loads other code: a long one of
/// [`CODE_LOADING_LONG`] (with or without `=value`), or a cluster of short
/// ones holding any of [`CODE_LOADING_SHORT`].
pub fn is_code_loading_option(arg: &str) -> bool {
    if let Some(long) = arg.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or(long);
        return CODE_LOADING_LONG
            .iter()
            .any(|o| o.strip_prefix("--") == Some(name));
    }
    arg.strip_prefix('-')
        .is_some_and(|cluster| cluster.chars().any(|c| CODE_LOADING_SHORT.contains(&c)))
}

/// One option of interpreter family `stem` before its entry file: an
/// error when it loads code ([`is_code_loading_option`], a short one of
/// [`INTERPRETER_LOADING_SHORT`] or [`stem_loading_short`] in its cluster
/// before any value, a short one not of [`harmless_short`],
/// [`attached_short`] or [`value_short`], or a long one with `=value` not
/// of [`VALUE_LONG`]), or when
/// it may take the next argument as its value (a short one of
/// [`value_short`] ending its cluster, a long one without `=` that is not
/// known to take none): which argument is the entry file is then not
/// known, [`DeclError::NoEntry`].
fn interpreter_option(stem: &str, long_family: &str, arg: &str) -> Result<(), DeclError> {
    let loads = Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
    if arg.starts_with("--") {
        if is_code_loading_option(arg) {
            return loads;
        }
        if let Some((name, _)) = arg.split_once('=') {
            // A value attached: only to an option known to load nothing.
            let known = VALUE_LONG.contains(&name)
                || VALUE_LONG_PREFIXES.iter().any(|p| name.starts_with(p));
            return if known { Ok(()) } else { loads };
        }
        let (exact, prefixes) = boolean_long(long_family);
        if exact.contains(&arg)
            || prefixes
                .iter()
                .any(|p| arg.len() > p.len() && arg.starts_with(p))
        {
            return Ok(());
        }
        return Err(DeclError::NoEntry);
    }
    let cluster = arg.strip_prefix('-').unwrap_or(arg);
    let values = value_short(stem);
    let own = stem_loading_short(stem);
    let mut letters = cluster.chars().peekable();
    while let Some(c) = letters.next() {
        if CODE_LOADING_SHORT.contains(&c)
            || INTERPRETER_LOADING_SHORT.contains(&c)
            || own.contains(&c)
        {
            return loads;
        }
        if shell_named_option(stem, c) {
            return Err(DeclError::NoEntry);
        }
        if stem == "ruby" && matches!(c, 'W' | 'K') {
            // Ruby reads a short value and then the rest of the cluster
            // as more options (its `reswitch`): `-We'code'`, `-W1e'code'`
            // and `-KUe'code'` run the code. Take the value as ruby does
            // and go on checking the letters after it.
            match (c, letters.peek().copied()) {
                ('W', Some(':')) => {
                    // `-W:category`: the rest is the category, whole.
                    letters.next();
                    let category: String = letters.collect();
                    return if ruby_warning_category(&category) {
                        Ok(())
                    } else {
                        loads
                    };
                }
                ('W', Some('0'..='2')) => {
                    letters.next();
                }
                ('K', Some(k)) => {
                    if !"EeSsUuNnAa".contains(k) {
                        return loads;
                    }
                    letters.next();
                }
                _ => {}
            }
            continue;
        }
        if values.contains(&c) {
            // The rest of the cluster is the value; none, and the next
            // argument is.
            let value: String = letters.collect();
            if value.is_empty() {
                return Err(DeclError::NoEntry);
            }
            // Python's -X may import presite code; a dotted -W category
            // imports its module. Accept only these fixed harmless forms.
            let safe = match (stem, c) {
                ("python" | "pypy", 'X') => {
                    matches!(value.as_str(), "dev" | "utf8" | "utf8=0" | "utf8=1")
                }
                ("python" | "pypy", 'W') => matches!(
                    value.as_str(),
                    "default" | "error" | "ignore" | "always" | "module" | "once"
                ),
                _ => true,
            };
            return if safe { Ok(()) } else { loads };
        }
        if attached_short(stem).contains(&c) {
            // The rest of the cluster is its value, or there is none.
            return Ok(());
        }
        if !harmless_short(stem).contains(&c) {
            return loads;
        }
    }
    Ok(())
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
    /// A program that starts another one its arguments name
    /// ([`WRAPPERS`]): what it starts could not be checked.
    Wrapper,
    /// A program named as one thing whose file is an interpreter, a
    /// package runner or a wrapper ([`refuse_disguised`]).
    Disguised,
}

/// Which of the two refusals of `code_selecting_env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeSelecting {
    Variable,
    InterpreterOption,
}

impl DeclError {
    /// A word for the refusal (the protocol's reason for the two
    /// `code_selecting_env` cases).
    pub fn word(self) -> &'static str {
        match self {
            DeclError::CodeSelecting(CodeSelecting::Variable) => "code_selecting_variable",
            DeclError::CodeSelecting(CodeSelecting::InterpreterOption) => "interpreter_option",
            DeclError::Empty => "empty_argv",
            DeclError::TooLarge => "too_large",
            DeclError::BadName => "invalid_env_name",
            DeclError::NotAbsolute => "not_absolute",
            DeclError::NoEntry => "no_entry_file",
            DeclError::Wrapper => "wrapper_program",
            DeclError::Disguised => "disguised_launcher",
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
    if d.path_env
        .as_ref()
        .is_some_and(|path| path.len() > MAX_TEXT || path.contains('\0'))
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

/// The interpreter family `name` is, by its name: one of [`INTERPRETERS`],
/// or one of [`VERSIONED`] with a version after it (`python3.12`,
/// `node22`, `node-22`, `luajit-2.1`), ignoring ASCII case, which may end in CPython's ABI flags (for example
/// `python3.14t`, a free-threaded build; `python3.13d`, a debug build;
/// `python3.13td`; `python3.7m`) and in Debian's `-dbg`
/// (`python3.12-dbg`). Architecture suffixes, pythonw, alternate Python
/// and Ruby implementations, and PHP SAPI launchers use the same policy.
/// Once a version starts, unknown build suffixes also count. The match leans towards
/// an interpreter: a name it missed would pass as a native program, whose
/// class binds what runs, while the interpreter's code is chosen by its
/// arguments (review of M2-27: `python3.14t` was a program).
fn interpreter_family(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let name = lower.as_str();
    let versioned = |version: &str| {
        version
            .strip_prefix('-')
            .unwrap_or(version)
            .starts_with(|c: char| c.is_ascii_digit())
    };
    let name = ["-intel64", "-arm64", "-universal2", "-x86_64"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
    let name = name.strip_suffix("-dbg").unwrap_or(name);
    // PHP distributions put the SAPI name on either side of the version.
    let name = name
        .strip_suffix("-cgi")
        .or_else(|| name.strip_suffix("-fpm"))
        .filter(|n| n.starts_with("php"))
        .unwrap_or(name);
    for (alias, family) in [
        ("pythonw", "python"),
        ("php-cgi", "php"),
        ("php-fpm", "php"),
        ("graalpy", "python"),
        ("micropython", "python"),
        ("truffleruby", "ruby"),
    ] {
        if let Some(version) = name.strip_prefix(alias) {
            if version.is_empty() || versioned(version) {
                return Some(family);
            }
        }
    }
    if let Some(stem) = INTERPRETERS
        .iter()
        .find(|stem| stem.eq_ignore_ascii_case(name))
    {
        return Some(stem);
    }
    VERSIONED
        .iter()
        .copied()
        .find(|stem| name.strip_prefix(stem).is_some_and(versioned))
}

/// The first argument of `argv` after `from` that is not an option. For
/// a Node package runner ([`NODE_RUNNERS`]), only when it is surely not
/// an option's value: every option before it carries its value after
/// `=`. After an option without one, which may take the next argument
/// (`npm --cache /c exec`), the word is not known: `None`, and the label
/// names the runner alone, never the value as its subcommand.
fn first_word<'a>(name: &str, argv: &'a [String], from: usize) -> Option<&'a str> {
    let strict = NODE_RUNNERS.contains(&name);
    for a in argv.iter().skip(from).map(String::as_str) {
        if strict && a == "--" {
            return None;
        }
        if !a.starts_with('-') {
            return Some(a);
        }
        if strict && !a.contains('=') {
            return None;
        }
    }
    None
}

/// The Node package runners, whose own options may run other code.
const NODE_RUNNERS: [&str; 6] = ["npx", "pnpx", "bunx", "npm", "pnpm", "yarn"];

/// The options of a Node package runner that run other code or choose
/// it, besides [`is_code_loading_option`]: a command to run (`--call`),
/// Node's options (`--node-options`), the shell that runs scripts
/// (`--script-shell`, npx's `--shell`) and a configuration file that may
/// set any of these (`--userconfig`, `--globalconfig`; the same
/// configuration as the `npm_config_*` variables [`is_code_selecting`]
/// refuses).
const RUNNER_LOADING_LONG: [&str; 6] = [
    "--call",
    "--node-options",
    "--script-shell",
    "--shell",
    "--userconfig",
    "--globalconfig",
];

/// The options npx takes without a value (npm 11.19.0's `npx-cli.js`: its
/// `switches`, npm's boolean configuration, and `-y`, which it expands to
/// `--yes`). Each one is measured: an option here that npx gave a value
/// would let that value pass for the package.
const NPX_SWITCHES: [&str; 8] = [
    "yes",
    "y",
    "quiet",
    "q",
    "prefer-offline",
    "offline",
    "prefer-online",
    "no-install",
];

/// The options npx always gives a value: the next argument, when none is
/// attached with `=` (npm 11.19.0's `npx-cli.js`: its `opts`).
const NPX_VALUED: [&str; 10] = [
    "package",
    "p",
    "cache",
    "userconfig",
    "call",
    "c",
    "shell",
    "npm",
    "node-arg",
    "n",
];

/// Where a Node package runner's own options end in `argv`: the index of
/// `--`, of npx's package, or the end. npx (npm 11.19.0's `npx-cli.js`)
/// stops at its first argument that is neither an option nor an option's
/// value; an option it does not know as a switch takes the next argument
/// as its value unless that one starts with `-`. `npm` reads options on
/// either side of its words until `--` (`npm exec pkg --call c` runs `c`),
/// and the other runners are taken as `npm` is, never measured to stop
/// sooner. An option value is never the package (Codex review of M2-27:
/// `npx --package foo --call c` and `npx --cache /c --node-options=...`
/// passed, the scan having stopped at `foo` and `/c`).
fn runner_options_end(name: &str, argv: &[String]) -> usize {
    let end = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    if name != "npx" {
        return end;
    }
    let mut i = 1;
    while i < end {
        let a = argv[i].as_str();
        if !a.starts_with('-') {
            return i;
        }
        let (key, attached) = match a.trim_start_matches('-').split_once('=') {
            Some((k, _)) => (k, true),
            None => (a.trim_start_matches('-'), false),
        };
        let next_is_option = argv.get(i + 1).is_some_and(|n| n.starts_with('-'));
        if !attached
            && !NPX_SWITCHES.contains(&key)
            && (NPX_VALUED.contains(&key) || !next_is_option)
        {
            i += 1;
        }
        i += 1;
    }
    end
}

/// Whether the runner's option `a` runs other code or chooses it
/// ([`is_code_loading_option`], [`RUNNER_LOADING_LONG`]).
fn runner_option_loads(a: &str) -> bool {
    is_code_loading_option(a)
        || RUNNER_LOADING_LONG
            .iter()
            .any(|o| a == *o || a.strip_prefix(o).is_some_and(|r| r.starts_with('=')))
}

/// The label of a package runner `name` with `argv` (see
/// [`PACKAGE_RUNNERS`]), or `None` when `name` is not one.
fn runner_label(name: &str, argv: &[String]) -> Option<String> {
    let has = |w: &str| argv.iter().skip(1).any(|a| a == w);
    let sub = |n: &str| match first_word(name, argv, 1) {
        Some(w) => format!("{n} {w}"),
        None => n.to_owned(),
    };
    Some(match name {
        "npx" | "pnpx" | "bunx" | "uvx" => name.to_owned(),
        "npm" => match first_word(name, argv, 1) {
            Some("exec" | "x") => "npm exec".to_owned(),
            _ => sub("npm"),
        },
        "uv" if argv.get(1).map(String::as_str) == Some("tool") && has("run") => {
            "uv tool run".to_owned()
        }
        "uv" | "pipx" | "poetry" | "pdm" | "hatch" | "pipenv" | "rye" | "conda" | "mamba"
            if has("run") =>
        {
            format!("{name} run")
        }
        "java" if has("-jar") => "java -jar".to_owned(),
        _ if PACKAGE_RUNNERS.contains(&name) => sub(name),
        _ => return None,
    })
}

/// Classes `argv` (see the module documentation), by the name of its
/// `argv[0]`.
///
/// # Errors
/// [`DeclError::Empty`] without argv; [`DeclError::Wrapper`] for a program
/// that starts another one; [`DeclError::CodeSelecting`] for an
/// interpreter or runner option that loads other code before the entry
/// file; [`DeclError::NoEntry`] for an interpreter whose first argument
/// that is not an option is missing; [`DeclError::NotAbsolute`] when it
/// is not an absolute path.
pub fn classify_argv(argv: &[String]) -> Result<ArgvClass, DeclError> {
    let first = argv.first().ok_or(DeclError::Empty)?;
    classify_named(argv, base(first))
}

/// Refuses a launcher known by another name: `argv` whose `argv[0]` is a
/// program by its own name, but whose file, `resolved` (its canonical
/// path), is named as an interpreter, a package runner or a wrapper (a
/// link named `server` to `node`, to `uv` or to `env`). Such a launch
/// would pass as a native program running code nothing checks.
///
/// # Errors
/// [`DeclError::Disguised`]; [`classify_argv`]'s for `argv` itself.
pub fn refuse_disguised(argv: &[String], resolved: &str) -> Result<ArgvClass, DeclError> {
    let own = classify_argv(argv)?;
    if own == ArgvClass::Program && classify_named(argv, base(resolved)) != Ok(ArgvClass::Program) {
        return Err(DeclError::Disguised);
    }
    Ok(own)
}

/// The argv the kernel would build for a `#!` file, made explicit so the
/// interpreter the daemon checked is the one that runs: `interp` (as the
/// `#!` line names it, or as `env` found it), the line's one option if
/// any, the file `script` (its canonical path, the entry file checked) and
/// the declaration's own arguments `args`. `resolved` is the interpreter's
/// canonical path. The option is checked as the interpreter's own would
/// be ([`classify_argv`]): one that loads code is
/// [`DeclError::CodeSelecting`], and so is a line whose interpreter runs
/// another program ([`DeclError::Wrapper`], [`DeclError::Disguised`]). The
/// script must be the entry file that classification finds; an option
/// that is not one, or any option to an interpreter EnvCloak does not
/// know, leaves what runs unknown: [`DeclError::NoEntry`].
///
/// # Errors
/// As above.
pub fn shebang_argv(
    interp: &str,
    opt: Option<&str>,
    script: &str,
    args: &[String],
    resolved: &str,
) -> Result<Vec<String>, DeclError> {
    if opt.is_some_and(|o| !o.starts_with('-') || o == "-" || o == "--") {
        return Err(DeclError::NoEntry);
    }
    let mut argv = vec![interp.to_owned()];
    argv.extend(opt.map(str::to_owned));
    let at = argv.len();
    argv.push(script.to_owned());
    argv.extend(args.iter().cloned());
    match refuse_disguised(&argv, resolved)? {
        ArgvClass::Interpreter { entry } if entry == at => Ok(argv),
        ArgvClass::Program if opt.is_none() => Ok(argv),
        ArgvClass::PackageRunner { .. } => Err(DeclError::Wrapper),
        _ => Err(DeclError::NoEntry),
    }
}

fn classify_named(argv: &[String], name: &str) -> Result<ArgvClass, DeclError> {
    if is_wrapper(name) {
        return Err(DeclError::Wrapper);
    }
    if let Some(label) = runner_label(name, argv) {
        // A Node package runner's own options that run other code (`npx
        // -c`, `--call`, `--node-options`), wherever the runner reads
        // them: every argument up to the end of its options, option
        // values included (a value that is an option is refused too).
        if NODE_RUNNERS.contains(&name)
            && argv[1..runner_options_end(name, argv)]
                .iter()
                .any(|a| runner_option_loads(a))
        {
            return Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
        }
        return Ok(ArgvClass::PackageRunner { label });
    }
    let Some(stem) = interpreter_family(name) else {
        return Ok(ArgvClass::Program);
    };
    // `deno run x.ts` and `bun run x.ts` name their entry after a
    // subcommand; any other subcommand of theirs (`bun x`, `deno task`)
    // runs a package or a task: a package runner.
    // TruffleRuby takes Ruby's short options, but its long ones were never
    // measured: none is taken as one without a value.
    let long_family = if name.to_ascii_lowercase().starts_with("truffleruby") {
        "truffleruby"
    } else {
        stem
    };
    let mut i = 1;
    if matches!(stem, "deno" | "bun") {
        match argv.get(1).map(String::as_str) {
            Some("run") => i = 2,
            Some(w) if !w.starts_with('-') && !w.starts_with('/') => {
                return Ok(ArgvClass::PackageRunner {
                    label: format!("{name} {w}"),
                });
            }
            _ => {}
        }
    }
    while let Some(a) = argv.get(i) {
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        interpreter_option(stem, long_family, a)?;
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
pub const UPDATE_DOMAIN: &[u8] = b"envcloak-update-statement/1\n";

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

/// SHA-256 of a registered launch's canonical encoding (every field, as
/// [`update_statement`] encodes each side), under its own domain: what an
/// audit entry names a launch by, never its contents.
pub fn launch_digest(l: &RegisteredLaunch) -> [u8; 32] {
    let mut e = Enc(Vec::with_capacity(512));
    e.0.extend_from_slice(b"envcloak-launch/1\n");
    e.bytes(&l.launch_id);
    launch(&mut e, l);
    Sha256::digest(&e.0).into()
}

/// The suffix of every binding name of a bridged server's managed
/// manifest (D-18): `_O` and the first 16 hex digits, upper case, of the
/// SHA-256 of the origin, so the origin is part of each binding's
/// identity and an edited origin is a new binding, which prompts.
pub fn bridge_binding_suffix(origin: &str) -> String {
    let d = Sha256::digest(origin.as_bytes());
    let mut s = String::from("_O");
    for b in &d[..8] {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// The binding that carries header `header` of a bridged server at
/// `origin` (D-18): the header's name upper-cased, each `-` written `_`,
/// then [`bridge_binding_suffix`] (`Authorization` at an origin is
/// `AUTHORIZATION_O<16 hex digits>`). This is how the relay knows which
/// released value goes in which header, and it is fixed by the record's
/// header names and origin alone. `None` for a header whose name is not
/// made of ASCII letters, digits, `-` and `_`, or does not start with a
/// letter: such a header cannot be bridged.
pub fn bridge_binding_name(header: &str, origin: &str) -> Option<String> {
    let first = header.chars().next()?;
    if !first.is_ascii_alphabetic()
        || !header
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    let mut name: String = header
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    name.push_str(&bridge_binding_suffix(origin));
    EnvName::new(&name).ok().map(|_| name)
}

/// The header each binding of a bridged server goes in: for each of
/// `header_names`, in order, the header and its binding
/// ([`bridge_binding_name`]). `None` when a header cannot be bridged or two
/// headers would share one binding (`X-Key` and `x_key`).
pub fn bridge_headers(header_names: &[String], origin: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(header_names.len());
    for h in header_names {
        let b = bridge_binding_name(h, origin)?;
        if out.iter().any(|(_, seen)| *seen == b) {
            return None;
        }
        out.push((h.clone(), b));
    }
    Some(out)
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
            "LUA_INIT",
            "LUA_INIT_5_4",
            "LUA_PATH",
            "LUA_PATH_5_4",
            "LUA_CPATH",
            "LUA_CPATH_5_3",
            "PHPRC",
            "PHP_INI_SCAN_DIR",
            "GEM_PATH",
            "GEM_HOME",
            "PERL5DB",
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
    /// A code-loading letter counts anywhere in a cluster (`-ec`, `-we`,
    /// `-Bc`, `-xc`), and an option that may take the next argument as its
    /// value leaves the entry file unknown (`no_entry_file`); options that
    /// take none, or have it attached, are the positive controls.
    ///
    /// Mutations checked: a short option matched only exactly or with its
    /// value attached (the previous `is_code_loading_option`): `sh -ec`
    /// classes `/srv/;id` as the entry file and this fails; a long option
    /// without `=` taken as one that takes no value: `node --title
    /// /srv/other.js /srv/s.js` checks `/srv/other.js` and this fails; the
    /// Lua, PHP, gem and Perl debugger variables left out of
    /// `CODE_SELECTING`: their declarations register and this fails; a
    /// Node package runner's scan stopped at its first word that is not an
    /// option (the r4 rule, which took an option's value for the package):
    /// `npx --package foo --call c` registers and this fails.
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
            // A code-loading letter anywhere in a cluster of short options.
            &["sh", "-ec", "/srv/;id", "/srv/s.sh"],
            &["perl", "-we", "print 1", "/srv/s.pl"],
            &["ruby", "-we", "p 1", "/srv/s.rb"],
            &["python3", "-Bc", "import x", "/srv/s.py"],
            &["bash", "-xc", "id", "/srv/s.sh"],
            &["npx", "-yc", "echo"],
            &["npx", "--node-options=--require=/x.js", "pkg"],
            &["npm", "--node-options", "--require=/x.js", "exec", "pkg"],
            // After an option's value, which is never the package (Codex
            // review of M2-27), and wherever npm reads its options.
            &["npx", "--package", "foo", "--call", "echo CONTROL"],
            &["npx", "-p", "foo", "--call", "echo CONTROL"],
            &[
                "npx",
                "--cache",
                "/tmp/cache",
                "--node-options=--require=/tmp/prelude.js",
                "pkg",
            ],
            &[
                "npx",
                "--registry",
                "https://r.example",
                "-c",
                "echo",
                "pkg",
            ],
            &["npx", "--loglevel", "warn", "--call=echo", "pkg"],
            &["npm", "exec", "pkg", "--call", "echo CONTROL"],
            &[
                "npm",
                "--cache",
                "/tmp/cache",
                "exec",
                "pkg",
                "--node-options=--require=/x.js",
            ],
            &["pnpm", "dlx", "pkg", "--node-options=--require=/x.js"],
            &["yarn", "dlx", "pkg", "--call", "echo"],
            &["bunx", "pkg", "-e", "code"],
            // The shell that runs scripts, and configuration files.
            &["npx", "--shell", "/tmp/sh", "pkg"],
            &["npm", "--script-shell=/tmp/sh", "start"],
            &["npm", "--userconfig", "/tmp/npmrc", "start"],
            &["npx", "--globalconfig=/tmp/npmrc", "pkg"],
            // An interpreter's own way of taking code from elsewhere.
            &["python3", "-i", "/srv/s.py"],
            &["sh", "-s", "/srv/s.sh"],
            &["perl", "-d:Trace", "/srv/s.pl"],
            &["lua", "-l", "mod", "/srv/s.lua"],
            &["php", "-d", "auto_prepend_file=/x.php", "/srv/s.php"],
            &["php", "-f", "/srv/s.php"],
            &["node", "-C", "dev", "/srv/s.js"],
            &["node", "--env-file", "/srv/.env", "/srv/s.js"],
            &["deno", "run", "--config", "/srv/c.json", "/srv/s.ts"],
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
        // An option that may take the next argument as its value: which
        // argument is the entry file is not known.
        for argv in [
            &["python3", "-X", "/srv/other.py", "/srv/s.py"][..],
            &["python3", "-uW", "/srv/other.py", "/srv/s.py"],
            &["node", "--title", "/srv/other.js", "/srv/s.js"],
            &["bash", "-o", "/srv/other.sh", "/srv/s.sh"],
            &["ruby", "--encoding", "/srv/other.rb", "/srv/s.rb"],
        ] {
            assert_eq!(
                classify_argv(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()),
                Err(DeclError::NoEntry),
                "{argv:?}"
            );
        }
        // The positive controls: options that take no value, or have it
        // attached, before the entry file.
        for (argv, entry) in [
            (&["python3", "-u", "-B", "/srv/s.py"][..], 3),
            (&["python3", "-Wignore", "-Xdev", "/srv/s.py"], 3),
            (
                &[
                    "node",
                    "--no-warnings",
                    "--max-old-space-size=512",
                    "/srv/s.js",
                ],
                3,
            ),
            (&["bash", "-x", "/srv/s.sh"], 2),
            (&["python3", "-OO", "/srv/s.py"], 2),
            (&["deno", "run", "--allow-env", "-A", "/srv/s.ts"], 4),
            (&["ruby", "-W", "--disable-gems", "/srv/s.rb"], 3),
        ] {
            assert_eq!(
                classify_argv(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()),
                Ok(ArgvClass::Interpreter { entry }),
                "{argv:?}"
            );
        }
        for name in [
            "LUA_INIT",
            "LUA_PATH_5_4",
            "PHPRC",
            "GEM_PATH",
            "PERL5DB",
            "npm_config_node_options",
        ] {
            let mut d = decl(&["/usr/bin/server"]);
            d.env.push((name.into(), "x".into()));
            assert_eq!(
                check_declaration(&d),
                Err(DeclError::CodeSelecting(CodeSelecting::Variable)),
                "{name}"
            );
        }
    }

    /// A long option registers bare before the entry file only when its
    /// own interpreter takes no value for it. Node's `--allow-fs-read`,
    /// `--allow-fs-write`, `--disable-warning` and `--disable-proto` take
    /// the next argument, so `node --allow-fs-read /a -e code` runs `code`
    /// with `/a` checked as the entry (measured with Node 26.7.0 in
    /// `tests/managed_interpreter_oracle.rs`); a prefix that takes no value
    /// in one family (deno's `--allow-`, ruby's `--disable-`) is no
    /// evidence for another. The refusal holds for a declaration, an
    /// update and a `#!` line; the daemon's stored-record check classes the
    /// same argv. The measured booleans of each family are the controls.
    ///
    /// Mutation checked: one prefix list for every family (the previous
    /// `BOOLEAN_LONG_PREFIXES`, `--no-`, `--allow-`, `--deny-`,
    /// `--enable-`, `--disable-`): `node --allow-fs-read /srv/other.js -e
    /// code` registers with `/srv/other.js` as its entry and this fails;
    /// Node's `--no-` prefix restored (the r4 rule): `node --no-print
    /// /abs/x.js` registers, and Node evaluates the path, and this fails;
    /// TruffleRuby given Ruby's long options: `truffleruby --disable-gems`
    /// registers and this fails.
    #[test]
    fn long_options_take_values_as_their_own_interpreter_does() {
        let v = |argv: &[&str]| argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for argv in [
            &["node", "--allow-fs-read", "/srv/other.js", "-e", "code"][..],
            &[
                "node",
                "--allow-fs-read",
                "/srv/other.js",
                "--permission",
                "-e",
                "code",
            ],
            &["node", "--allow-fs-write", "/srv/other.js", "/srv/s.js"],
            &["node", "--disable-warning", "/srv/other.js", "/srv/s.js"],
            &["node", "--disable-proto", "/srv/other.js", "/srv/s.js"],
            &["nodejs22", "--allow-fs-read", "/srv/other.js", "/srv/s.js"],
            &["node", "--allow-some-future", "/srv/other.js", "/srv/s.js"],
            &["node", "--enable-some-future", "/srv/other.js", "/srv/s.js"],
            &["node", "--no-", "/srv/other.js", "/srv/s.js"],
            // `--no-print` still turns on eval mode: Node evaluates the
            // name of the file checked as the entry (review of M2-27).
            &["node", "--no-print", "/abs/x.js"],
            &["node", "--no-print", "/srv/other.js", "/srv/s.js"],
            &["nodejs22", "--no-eval", "/srv/other.js", "/srv/s.js"],
            &["node", "--no-some-future", "/srv/other.js", "/srv/s.js"],
            // TruffleRuby's long options were never measured.
            &[
                "truffleruby",
                "--disable-gems",
                "/srv/other.rb",
                "/srv/s.rb",
            ],
            &["truffleruby24.1", "--verbose", "/srv/other.rb", "/srv/s.rb"],
            &["bun", "--allow-fs-read", "/srv/other.js", "/srv/s.js"],
            &["bun", "--disable-x", "/srv/other.js", "/srv/s.js"],
            &["deno", "run", "--enable-x", "/srv/other.ts", "/srv/s.ts"],
            &["python3", "--no-x", "/srv/other.py", "/srv/s.py"],
            &["python3", "--allow-x", "/srv/other.py", "/srv/s.py"],
            &["ruby", "--allow-x", "/srv/other.rb", "/srv/s.rb"],
            &["ruby", "--no-x", "/srv/other.rb", "/srv/s.rb"],
            &["perl", "--verbose", "/srv/other.pl", "/srv/s.pl"],
            &["php", "--no-x", "/srv/other.php", "/srv/s.php"],
            &["fish", "--no-x", "/srv/other.fish", "/srv/s.fish"],
            &["julia", "--quiet", "/srv/other.jl", "/srv/s.jl"],
            &["zsh", "--norc", "/srv/other.sh", "/srv/s.sh"],
        ] {
            let argv = v(argv);
            assert_eq!(classify_argv(&argv), Err(DeclError::NoEntry), "{argv:?}");
            assert_eq!(
                check_declaration(&LaunchDecl {
                    argv: argv.clone(),
                    ..decl(&[])
                }),
                Err(DeclError::NoEntry),
                "{argv:?}"
            );
            assert!(
                matches!(
                    apply_changes(
                        &decl(&["/srv/s.js"]),
                        &LaunchChanges {
                            argv: Some(argv.clone()),
                            ..LaunchChanges::default()
                        }
                    ),
                    Err(DeclError::NoEntry)
                ),
                "{argv:?}"
            );
            // A `#!` line naming the interpreter with the option.
            if argv[1].starts_with("--") {
                assert_eq!(
                    shebang_argv(&argv[0], Some(&argv[1]), "/srv/s", &[], &argv[0]),
                    Err(DeclError::NoEntry),
                    "{argv:?}"
                );
            }
        }
        for (argv, entry) in [
            (
                &[
                    "node",
                    "--allow-child-process",
                    "--allow-addons",
                    "/srv/s.js",
                ][..],
                3,
            ),
            (
                &["node", "--no-warnings", "--enable-source-maps", "/srv/s.js"],
                3,
            ),
            (
                &["node", "--allow-fs-read=/srv", "--permission", "/srv/s.js"],
                3,
            ),
            (
                &["node", "--disable-sigusr1", "--enable-fips", "/srv/s.js"],
                3,
            ),
            (
                &["deno", "run", "--allow-read", "--no-check", "/srv/s.ts"],
                4,
            ),
            (&["bun", "--smol", "--no-install", "/srv/s.ts"], 3),
            (
                &[
                    "ruby",
                    "--disable-gems",
                    "--enable-yjit",
                    "--verbose",
                    "/srv/s.rb",
                ],
                4,
            ),
            (&["bash", "--noprofile", "--norc", "/srv/s.sh"], 3),
            (&["zsh", "--no-rcs", "/srv/s.sh"], 2),
        ] {
            let argv = v(argv);
            assert_eq!(
                classify_argv(&argv),
                Ok(ArgvClass::Interpreter { entry }),
                "{argv:?}"
            );
            assert!(
                check_declaration(&LaunchDecl {
                    argv: argv.clone(),
                    ..decl(&[])
                })
                .is_ok(),
                "{argv:?}"
            );
        }
    }

    /// A short interpreter option registers only when it is known to load
    /// nothing; any other letter may load a module before the entry file.
    /// `luajit -jv` loads `jit.v` and `luajit -b` loads `jit.bcsave`
    /// through `./?.lua` (measured with a pinned LuaJIT in
    /// `tests/managed_interpreter_oracle.rs`). The refusal holds for a
    /// declaration, an update, a `#!` line and a stored record alike, which
    /// all class the argv here.
    ///
    /// Mutation checked: the `harmless_short` check removed (the previous
    /// rule, refusing only listed letters): `luajit -jv /srv/s.lua`
    /// registers, and this fails.
    #[test]
    fn short_options_register_only_when_known_harmless() {
        let loads = DeclError::CodeSelecting(CodeSelecting::InterpreterOption);
        for (name, option) in [
            ("luajit", "-jv"),
            ("luajit", "-jdump"),
            ("luajit", "-jp"),
            ("luajit", "-j"),
            ("luajit", "-b"),
            ("luajit", "-vj"),
            ("luajit-2.1", "-jv"),
            ("lua", "-jv"),
            ("node", "-x"),
            ("bun", "-j"),
            ("python3", "-J"),
            ("ruby", "-y"),
            ("perl", "-0"),
            ("tclsh", "-z"),
            ("pwsh", "-NoProfile"),
        ] {
            let d = decl(&[name, option, "/srv/s.lua"]);
            assert_eq!(classify_argv(&d.argv), Err(loads), "{name} {option}");
            assert_eq!(check_declaration(&d), Err(loads), "{name} {option}");
            assert!(
                matches!(
                    apply_changes(
                        &decl(&["/bin/server"]),
                        &LaunchChanges {
                            argv: Some(d.argv.clone()),
                            ..LaunchChanges::default()
                        }
                    ),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
                ),
                "{name} {option}"
            );
            let path = format!("/usr/bin/{name}");
            assert_eq!(
                shebang_argv(&path, Some(option), "/srv/s.lua", &[], &path),
                Err(loads),
                "{name} {option}"
            );
        }
        // The positive controls: letters known to load nothing.
        for (name, option) in [
            ("luajit", "-v"),
            ("luajit", "-O3"),
            ("luajit", "-O+fold"),
            ("luajit", "-O"),
            ("lua", "-W"),
            ("python3", "-uB"),
            ("ruby", "-W2"),
            ("ruby", "-w"),
            ("perl", "-wT"),
            ("php", "-n"),
            ("bash", "-xv"),
            ("deno", "-A"),
        ] {
            let argv = decl(&[name, option, "/srv/s"]).argv;
            assert_eq!(
                classify_argv(&argv),
                Ok(ArgvClass::Interpreter { entry: 2 }),
                "{name} {option}"
            );
        }
    }

    /// Mutation: accept every attached short value without checking its meaning.
    #[test]
    fn attached_values_cannot_select_unchecked_code() {
        for (name, option) in [
            ("php", "-f/other.php"),
            ("php", "-nf/other.php"),
            ("php", "-F/other.php"),
            ("php", "-Bprint(1);"),
            ("php", "-Rprint(1);"),
            ("php", "-S127.0.0.1:0"),
            ("php", "-a"),
            ("php", "-na"),
            ("python3", "-Xpresite=observer"),
            ("python3", "-uXpresite=observer"),
            ("python3", "-Xfuture_option=x"),
            ("python3", "-Wignore::observer.Warning"),
        ] {
            assert_eq!(
                classify_argv(&decl(&[name, option, "/srv/entry"]).argv),
                Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                "{name} {option}"
            );
        }
        for (name, option) in [
            ("python3", "-Xdev"),
            ("python3", "-Xutf8=1"),
            ("python3", "-Wignore"),
            ("ruby", "-F:"),
            ("julia", "-O2"),
        ] {
            assert_eq!(
                classify_argv(&decl(&[name, option, "/srv/entry"]).argv),
                Ok(ArgvClass::Interpreter { entry: 2 }),
                "{name} {option}"
            );
        }
    }

    /// Ruby's `-W` and `-K` read a short value (one digit, one encoding
    /// letter) and then the rest of the cluster as more options, so the
    /// letters after the value are checked like any others; `-T` is not a
    /// known harmless letter. Measured with ruby 2.6 and the pinned 3.4 in
    /// `tests/managed_interpreter_oracle.rs`: `ruby -We'code' /s.rb` and
    /// `ruby -KUe'code' /s.rb` run the code. The refusal holds for a
    /// declaration, an update and a `#!` line (the stored record's case is
    /// in the daemon's `launch_check` tests).
    ///
    /// Mutation checked: ruby's `W` and `K` returning `Ok` at their letter
    /// without checking the rest of the cluster (the previous rule, as an
    /// `attached_short` entry): `ruby -We'puts 1' /srv/s.rb` registers.
    #[test]
    fn ruby_short_values_do_not_end_the_cluster() {
        let loads = DeclError::CodeSelecting(CodeSelecting::InterpreterOption);
        for option in [
            "-We'puts 1'",
            "-Wrevil",
            "-WI.",
            "-W1e'puts 1'",
            "-W2r./evil",
            "-W:deprecated-e",
            "-W:",
            "-KUe'puts 1'",
            "-Kz",
            "-Kx",
            "-KUr./evil",
            "-Te'puts 1'",
            "-T",
            "-T1",
            "-wKUW0e1",
        ] {
            for name in ["ruby", "ruby3.4", "truffleruby"] {
                let d = decl(&[name, option, "/srv/s.rb"]);
                assert_eq!(classify_argv(&d.argv), Err(loads), "{name} {option}");
                assert_eq!(check_declaration(&d), Err(loads), "{name} {option}");
                assert!(
                    matches!(
                        apply_changes(
                            &decl(&["/bin/server"]),
                            &LaunchChanges {
                                argv: Some(d.argv.clone()),
                                ..LaunchChanges::default()
                            }
                        ),
                        Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
                    ),
                    "{name} {option}"
                );
                let path = format!("/usr/bin/{name}");
                assert_eq!(
                    shebang_argv(&path, Some(option), "/srv/s.rb", &[], &path),
                    Err(loads),
                    "{name} {option}"
                );
            }
        }
        // The positive controls: the value forms ruby reads, followed by
        // nothing or by harmless letters.
        for option in [
            "-W",
            "-W0",
            "-W1",
            "-W2",
            "-W:no-deprecated",
            "-W:exp",
            "-W:performance",
            "-KU",
            "-Ku",
            "-Kn",
            "-Ke",
            "-K",
            "-KUw",
            "-W2w",
            "-wW1",
            "-W0KU",
            "-F:",
        ] {
            let d = decl(&["ruby", option, "/srv/s.rb"]);
            assert_eq!(
                classify_argv(&d.argv),
                Ok(ArgvClass::Interpreter { entry: 2 }),
                "{option}"
            );
            assert_eq!(
                shebang_argv(
                    "/usr/bin/ruby",
                    Some(option),
                    "/srv/s.rb",
                    &[],
                    "/usr/bin/ruby"
                ),
                Ok(vec![
                    "/usr/bin/ruby".into(),
                    option.into(),
                    "/srv/s.rb".into()
                ]),
                "{option}"
            );
        }
    }

    /// A shell's `-o` and `-O` name a shell option: bash and dash take the
    /// next argument as the name whatever follows in the cluster (`bash
    /// -oposix /s.sh` reads `/s.sh` as the name; `bash -Oc extglob 'code'`
    /// runs `code`), zsh and ksh the rest of the cluster. Which argument
    /// is the entry file is not known, attached or not.
    ///
    /// Mutation checked: `o` and `O` back in `value_short` for the shells
    /// (the previous rule): `bash -oposix /srv/s.sh` registers with
    /// `/srv/s.sh` as its entry.
    #[test]
    fn shell_option_names_leave_the_entry_unknown() {
        for (name, option) in [
            ("bash", "-oposix"),
            ("bash", "-Oextglob"),
            ("bash", "-xo"),
            ("bash", "-Oc"),
            ("dash", "-oposix"),
            ("sh", "-o"),
            ("zsh", "-oshwordsplit"),
            ("ksh", "-oposix"),
        ] {
            let d = decl(&[name, option, "/srv/s.sh"]);
            assert_eq!(
                classify_argv(&d.argv),
                Err(DeclError::NoEntry),
                "{name} {option}"
            );
            assert_eq!(
                check_declaration(&d),
                Err(DeclError::NoEntry),
                "{name} {option}"
            );
            let path = format!("/bin/{name}");
            assert_eq!(
                shebang_argv(&path, Some(option), "/srv/s.sh", &[], &path),
                Err(DeclError::NoEntry),
                "{name} {option}"
            );
        }
        assert_eq!(
            classify_argv(&decl(&["bash", "-xv", "/srv/s.sh"]).argv),
            Ok(ArgvClass::Interpreter { entry: 2 })
        );
    }

    /// Mutation: omit alternate, architecture and build launcher names.
    #[test]
    fn native_interpreter_aliases_keep_interpreter_policy() {
        for name in [
            "python3.12-intel64",
            "python3-intel64",
            "python3.14t-arm64",
            "python3.13td-universal2",
            "python3.12-x86_64",
            "pythonw",
            "pythonw3",
            "pythonw3.12",
            "graalpy",
            "graalpy3.12",
            "micropython",
            "truffleruby",
            "truffleruby24.1",
            "php-cgi",
            "php-fpm",
            "php8.4-cgi",
            "php-cgi8.4",
            "php8.4-fpm",
            "php-fpm8.4",
            "pypy3.11-v7.3.19",
            "ruby3.4.0-preview1",
            "node22-nightly",
        ] {
            for option in ["-m", "-c"] {
                assert_eq!(
                    classify_argv(&decl(&[name, option, "module"]).argv),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                    "{name} {option}"
                );
            }
            assert_eq!(
                classify_argv(&decl(&[name, "/srv/entry"]).argv),
                Ok(ArgvClass::Interpreter { entry: 1 }),
                "{name}"
            );
            assert_eq!(
                refuse_disguised(
                    &decl(&["server", "/srv/entry"]).argv,
                    &format!("/opt/bin/{name}")
                ),
                Err(DeclError::Disguised),
                "{name}"
            );
        }
        for name in [
            "pythond",
            "python-server",
            "nodemon",
            "php-server",
            "pythonwrench",
        ] {
            assert_eq!(
                classify_argv(&decl(&[name]).argv),
                Ok(ArgvClass::Program),
                "{name}"
            );
        }
    }

    /// Mutations: case-sensitive families, or no hyphen-version match.
    #[test]
    fn interpreter_case_and_hyphen_versions_keep_code_loading_refusals() {
        for name in [
            "Python",
            "Python3",
            "PYTHON3.12",
            "luajit-2.1.1736781742",
            "node-22",
            "Node-22",
            "Pythonw-3",
            "PHP-CGI-8.4",
        ] {
            let path = format!("/x/{name}");
            for option in ["-m", "-e"] {
                let d = decl(&[&path, option, "server"]);
                let refused = Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
                assert_eq!(classify_argv(&d.argv), refused, "{name} {option}");
                assert_eq!(refuse_disguised(&d.argv, &path), refused, "{name}");
                assert_eq!(
                    check_declaration(&d),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
                );
                assert!(matches!(
                    apply_changes(
                        &decl(&["/bin/server"]),
                        &LaunchChanges {
                            argv: Some(d.argv),
                            ..LaunchChanges::default()
                        }
                    ),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
                ));
                assert_eq!(
                    shebang_argv(&path, Some(option), "/srv/entry", &[], &path),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
                );
                assert_eq!(
                    refuse_disguised(&decl(&["/bin/server", option, "server"]).argv, &path),
                    Err(DeclError::Disguised)
                );
            }
            assert_eq!(
                classify_argv(&decl(&[&path, "/srv/entry"]).argv),
                Ok(ArgvClass::Interpreter { entry: 1 })
            );
        }
        for name in [
            "python-server",
            "nodemon",
            "pythonwrench",
            "Python-server",
            "node-",
            "luajit-server",
        ] {
            assert_eq!(
                classify_argv(&decl(&[name, "-m", "server"]).argv),
                Ok(ArgvClass::Program),
                "{name}"
            );
        }
    }

    /// Mutation: compare npm configuration names only in the two exact cases.
    #[test]
    fn npm_configuration_is_case_insensitive_at_every_boundary() {
        for name in [
            "npm_config_node_options",
            "NpM_cOnFiG_NoDe_OpTiOnS",
            "npm_config_script_shell",
            "NPM_CONFIG_USERCONFIG",
            "Npm_Config_GlobalConfig",
            "npm_config_prefix",
            "npm_config_future_loader",
        ] {
            let mut d = decl(&["npx", "package"]);
            d.env.push((name.into(), "fixture".into()));
            assert_eq!(
                check_declaration(&d),
                Err(DeclError::CodeSelecting(CodeSelecting::Variable)),
                "{name}"
            );
            let changes = LaunchChanges {
                set_env: d.env.clone(),
                ..LaunchChanges::default()
            };
            assert_eq!(
                apply_changes(&decl(&["npx", "package"]), &changes),
                Err(DeclError::CodeSelecting(CodeSelecting::Variable)),
                "{name}"
            );
            assert!(
                launch_environment(
                    [(name.as_bytes(), b"fixture".as_slice())],
                    b"/bin",
                    &d.env,
                    &[(name, b"fixture")]
                )
                .iter()
                .all(|(n, _)| n != name.as_bytes())
            );
        }
        let d = decl(&["server"]);
        assert!(check_declaration(&d).is_ok());
        for name in [
            "NPM_CONFIG_REGISTRY",
            "npm_config_cache",
            "NpM_cOnFiG_FuNd",
            "npm_config_audit",
            "npm_config_update_notifier",
            "MY_npm_config_userconfig",
        ] {
            assert!(!is_code_selecting(name), "{name}");
        }
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
            // npx's package ends its options: what follows is the
            // package's (the controls for the refusals after an option's
            // value).
            (&["npx", "--yes", "pkg", "-c", "x", "--call", "y"], "npx"),
            (
                &["npx", "--package", "foo", "bar", "--config", "/c.json"],
                "npx",
            ),
            (&["npx", "-y", "pkg", "--", "--call"], "npx"),
            (&["npm", "exec", "pkg", "--", "--call", "x"], "npm exec"),
            // A word after an option without `=` may be its value: the
            // runner alone names the launch.
            (&["npm", "--cache", "/tmp/c", "exec", "pkg"], "npm"),
            (&["npm", "--cache=/tmp/c", "exec", "pkg"], "npm exec"),
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

    /// A Node package runner's option that runs other code is refused
    /// after an option's value as before one, for a declaration and an
    /// update (Codex review of M2-27): npm reads `--package foo` and
    /// `--cache /c` as option and value and goes on reading options, so
    /// `foo` and `/c` are not the package. Its package's own arguments
    /// (after npx's package, or after `--`) are the controls.
    ///
    /// Mutation checked: the scan stopped at the first word that is not
    /// an option (the r4 rule): these register and this fails.
    #[test]
    fn runner_options_after_an_option_value_are_still_the_runners() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let refused = Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
        let base = decl(&["npx", "-y", "pkg"]);
        assert!(check_declaration(&base).is_ok());
        for argv in [
            &["npx", "--package", "foo", "--call", "echo CONTROL"][..],
            &[
                "npx",
                "--cache",
                "/tmp/cache",
                "--node-options=--require=/tmp/p.js",
                "pkg",
            ],
            &["npx", "--prefer-offline", "--userconfig", "/tmp/rc", "pkg"],
            &["npm", "exec", "--package", "foo", "pkg", "--call", "echo"],
            &[
                "pnpm",
                "--dir",
                "/srv",
                "dlx",
                "pkg",
                "--node-options=--require=/x.js",
            ],
        ] {
            let argv = v(argv);
            assert_eq!(
                check_declaration(&LaunchDecl {
                    argv: argv.clone(),
                    ..base.clone()
                }),
                refused,
                "{argv:?}"
            );
            assert_eq!(
                apply_changes(
                    &base,
                    &LaunchChanges {
                        argv: Some(argv.clone()),
                        ..LaunchChanges::default()
                    }
                )
                .map(|_| ()),
                refused,
                "{argv:?}"
            );
        }
        for argv in [
            &["npx", "--package", "foo", "bar", "--call", "x"][..],
            &["npx", "--yes", "pkg", "--node-options=--require=/x.js"],
            &["npm", "exec", "pkg", "--", "--call", "x"],
        ] {
            let argv = v(argv);
            assert!(
                check_declaration(&LaunchDecl {
                    argv,
                    ..base.clone()
                })
                .is_ok()
            );
        }
    }

    /// No launcher whose code is chosen when it starts passes as a native
    /// program (whose class binds what runs): `uv run` in any form,
    /// `docker run`, `podman run`, `java -jar` and `npm start` are package
    /// runners; an interpreter with a version in its name (`ruby3.2`,
    /// `perl5.34`, `node22`) is an interpreter; a program that starts
    /// another one its arguments name (`env`, `nice`, a dynamic loader) is
    /// refused; and a link named as a program to an interpreter, a runner
    /// or a wrapper is refused by the name of its file. A native program,
    /// and an interpreter-like name that is not one (`nodemon-server`),
    /// stay programs (the positive controls).
    ///
    /// Mutation checked: the runner list cut back to `uv tool run` and the
    /// interpreter match to exact names and `pythonN.N` (the previous
    /// classification): `uv --directory /p run server.py` is a program,
    /// and this fails.
    #[test]
    fn launchers_in_every_form_are_never_native() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let c = |a: &[&str]| classify_argv(&v(a));
        for (argv, label) in [
            (&["uv", "run", "server.py"][..], "uv run"),
            (&["uv", "--directory", "/p", "run", "server.py"], "uv run"),
            (
                &["/usr/local/bin/uv", "run", "--with", "x", "s.py"],
                "uv run",
            ),
            (&["docker", "run", "-i", "--rm", "img"], "docker run"),
            (&["podman", "run", "img"], "podman run"),
            (&["java", "-jar", "/srv/s.jar"], "java -jar"),
            (&["npm", "start"], "npm start"),
            (&["npm", "x", "pkg"], "npm exec"),
            (&["poetry", "run", "server"], "poetry run"),
            (&["bun", "x", "pkg"], "bun x"),
            (&["go", "run", "."], "go run"),
        ] {
            assert_eq!(
                c(argv),
                Ok(ArgvClass::PackageRunner {
                    label: label.to_owned()
                }),
                "{argv:?}"
            );
        }
        for (argv, entry) in [
            (&["ruby3.2", "/srv/s.rb"][..], 1),
            (&["/usr/bin/perl5.34", "/srv/s.pl"], 1),
            (&["node22", "/srv/s.js"], 1),
            (&["python3", "/srv/s.py"], 1),
            (&["python3.12", "/srv/s.py"], 1),
            (&["php8.3", "/srv/s.php"], 1),
        ] {
            assert_eq!(c(argv), Ok(ArgvClass::Interpreter { entry }), "{argv:?}");
        }
        assert_eq!(c(&["ruby3.2", "s.rb"]), Err(DeclError::NotAbsolute));
        assert_eq!(
            c(&["node22", "--inspect=0.0.0.0:9229", "/srv/s.js"]),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
        assert_eq!(
            c(&["node", "--inspect-brk", "/srv/s.js"]),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
        for argv in [
            &["env", "FOO=1", "node", "/srv/s.js"][..],
            &["/usr/bin/env", "node", "/srv/s.js"],
            &["nice", "/srv/server"],
            &["stdbuf", "-o0", "/srv/server"],
            &["/lib64/ld-linux-x86-64.so.2", "/srv/server"],
            &["ld.so", "/srv/server"],
        ] {
            assert_eq!(c(argv), Err(DeclError::Wrapper), "{argv:?}");
        }
        // Known by another name: refused by the name of its file.
        for resolved in [
            "/usr/bin/node",
            "/opt/homebrew/bin/uv",
            "/usr/bin/env",
            "/usr/bin/ruby3.2",
        ] {
            assert_eq!(
                refuse_disguised(&v(&["/srv/bin/server", "/srv/s.js"]), resolved),
                Err(DeclError::Disguised),
                "{resolved}"
            );
        }
        // The positive controls.
        assert_eq!(c(&["/srv/bin/server"]), Ok(ArgvClass::Program));
        assert_eq!(c(&["nodemon-server"]), Ok(ArgvClass::Program));
        assert_eq!(c(&["node-v2"]), Ok(ArgvClass::Program));
        assert_eq!(
            refuse_disguised(&v(&["/srv/bin/server"]), "/srv/bin/server-1.2"),
            Ok(ArgvClass::Program)
        );
        assert_eq!(
            refuse_disguised(&v(&["node", "/srv/s.js"]), "/usr/bin/node22"),
            Ok(ArgvClass::Interpreter { entry: 1 })
        );
        // The variables beyond SPEC's list that select or load code.
        for n in [
            "PERLLIB",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "PYTHONUSERBASE",
            "ZDOTDIR",
        ] {
            assert!(is_code_selecting(n), "{n}");
        }
    }

    /// CPython's builds are installed under their version with ABI flags
    /// (`python3.14t` free-threaded, `python3.13d` debug, `python3.13td`,
    /// `python3.7m`, `python3t`) and Debian's debug build under `-dbg`:
    /// each is an interpreter of the `python` family, whose code-loading
    /// options are refused (`-c`, `-m`, `-ic`) and whose entry file is the
    /// first argument after its options (`-Xdev`; `-X dev` leaves it unknown,
    /// as for `python3`); a link
    /// named as a program to one is refused by its file's name. GNU's
    /// wrappers as Homebrew installs them (`gtimeout`, `genv`, `gnice`,
    /// `gxargs`) are wrappers. A native program whose name merely ends in
    /// those letters (`mytool`, `gserver`, `pythond`) stays a program (the
    /// positive controls).
    ///
    /// Mutations checked: the version match without the ABI flags (the
    /// previous `interpreter`): `python3.14t -c x` is a program and
    /// registers, and this fails; the `g` names left out of `is_wrapper`:
    /// `gtimeout 5 node /srv/s.js` is a program, and this fails.
    #[test]
    fn abi_flagged_interpreters_and_gnu_wrappers_are_never_native() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let c = |a: &[&str]| classify_argv(&v(a));
        for name in [
            "python3.14t",
            "/usr/local/bin/python3.14t",
            "python3.13d",
            "python3.13td",
            "python3.7m",
            "python3.7dm",
            "python3t",
            "python3.12-dbg",
            "pypy3.10",
        ] {
            assert_eq!(
                c(&[name, "/srv/s.py"]),
                Ok(ArgvClass::Interpreter { entry: 1 }),
                "{name}"
            );
            assert_eq!(
                c(&[name, "-Xdev", "/srv/s.py"]),
                Ok(ArgvClass::Interpreter { entry: 2 }),
                "{name}"
            );
            assert_eq!(
                c(&[name, "-X", "dev", "/srv/s.py"]),
                Err(DeclError::NoEntry),
                "{name}"
            );
            for loads in [&["-c", "import x"][..], &["-m", "server"], &["-ic", "x"]] {
                let mut argv = vec![name];
                argv.extend_from_slice(loads);
                assert_eq!(
                    c(&argv),
                    Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                    "{argv:?}"
                );
            }
            assert_eq!(c(&[name, "s.py"]), Err(DeclError::NotAbsolute), "{name}");
            assert_eq!(
                refuse_disguised(&v(&["/srv/bin/server"]), &format!("/usr/bin/{name}")),
                Err(DeclError::Disguised),
                "{name}"
            );
        }
        for name in [
            "gtimeout", "genv", "gnice", "gnohup", "gstdbuf", "gxargs", "gtime",
        ] {
            assert_eq!(
                c(&[name, "5", "node", "/srv/s.js"]),
                Err(DeclError::Wrapper),
                "{name}"
            );
        }
        for name in ["mytool", "gserver", "pythond", "python-server", "nodemon"] {
            assert_eq!(c(&[name, "--port", "1"]), Ok(ArgvClass::Program), "{name}");
        }
        assert_eq!(
            refuse_disguised(&v(&["python3.14t", "/srv/s.py"]), "/usr/bin/python3.14t"),
            Ok(ArgvClass::Interpreter { entry: 1 })
        );
    }

    /// The programs that run a script file their argument names are never
    /// native (whose class would bind them while the script changes):
    /// `Rscript`, `julia`, `tclsh`, `pwsh`, `osascript`, `swift` and the
    /// rest are interpreters whose entry file is checked; `awk`, `make`,
    /// `erl` and `R` are runners, checked at rest; `busybox` is a wrapper.
    /// Each family's own code-loading options are refused (`julia -L`,
    /// `racket -t`, `elixir -S`, `swift -F`). A long option with `=value`
    /// registers only when it is known to load nothing: `node
    /// --snapshot-blob=` and `--openssl-config=` restore or load code the
    /// entry file does not name, and an unknown one may too. OpenSSL's
    /// and the plug-in loaders' variables select code.
    ///
    /// Mutations checked: the interpreter list cut back to SPEC's
    /// (`Rscript /srv/s.R` is a program, and this fails); any long option
    /// with `=value` accepted (the previous rule: `node
    /// --snapshot-blob=/x.blob /srv/s.js` registers with `/srv/s.js` as its
    /// entry, and this fails); `OPENSSL_CONF` left out of `CODE_SELECTING`
    /// (it registers, and this fails).
    #[test]
    fn script_running_programs_and_valued_options_are_never_bound() {
        let c = |a: &[&str]| classify_argv(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        for argv in [
            &["Rscript", "/srv/s.R"][..],
            &["julia", "/srv/s.jl"],
            &["tclsh", "/srv/s.tcl"],
            &["tclsh8.6", "/srv/s.tcl"],
            &["wish", "/srv/s.tcl"],
            &["pwsh", "/srv/s.ps1"],
            &["raku", "/srv/s.raku"],
            &["guile", "/srv/s.scm"],
            &["racket", "/srv/s.rkt"],
            &["elixir", "/srv/s.exs"],
            &["escript", "/srv/s.erl"],
            &["osascript", "/srv/s.scpt"],
            &["swift", "/srv/s.swift"],
            &["luajit", "/srv/s.lua"],
        ] {
            assert_eq!(c(argv), Ok(ArgvClass::Interpreter { entry: 1 }), "{argv:?}");
        }
        for (argv, label) in [
            (&["awk", "-f", "/srv/s.awk"][..], "awk /srv/s.awk"),
            (&["gawk", "-f", "/srv/s.awk"], "gawk /srv/s.awk"),
            (&["make", "serve"], "make serve"),
            (&["erl", "-noshell", "-s", "server"], "erl server"),
            (&["R", "-f", "/srv/s.R"], "R /srv/s.R"),
        ] {
            assert_eq!(
                c(argv),
                Ok(ArgvClass::PackageRunner {
                    label: label.to_owned()
                }),
                "{argv:?}"
            );
        }
        assert_eq!(c(&["busybox", "sh", "/srv/s.sh"]), Err(DeclError::Wrapper));
        for argv in [
            &["julia", "-L", "/srv/pre.jl", "/srv/s.jl"][..],
            &["julia", "-J", "/srv/sys.so", "/srv/s.jl"],
            &["racket", "-t", "/srv/x.rkt", "/srv/s.rkt"],
            &["elixir", "-S", "mix", "/srv/s.exs"],
            &["swift", "-F", "/srv/fw", "/srv/s.swift"],
            &["guile", "-L", "/srv/lib", "/srv/s.scm"],
            &["node", "--snapshot-blob=/srv/x.blob", "/srv/s.js"],
            &["node", "--openssl-config=/srv/x.cnf", "/srv/s.js"],
            &["node", "--some-future-option=/srv/x", "/srv/s.js"],
            &["node", "--run", "start"],
            &["node", "--test", "/srv/s.js"],
            &["npx", "--snapshot-blob=/srv/x.blob", "pkg"],
        ] {
            assert_eq!(
                c(argv),
                Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                "{argv:?}"
            );
        }
        // The positive controls: values known to load nothing.
        for (argv, entry) in [
            (&["node", "--max-old-space-size=512", "/srv/s.js"][..], 2),
            (&["node", "--title=srv", "/srv/s.js"], 2),
            (&["deno", "run", "--allow-net=api.example", "/srv/s.ts"], 3),
            (&["ruby", "--encoding=utf-8", "/srv/s.rb"], 2),
            (&["julia", "-t4", "/srv/s.jl"], 2),
        ] {
            assert_eq!(c(argv), Ok(ArgvClass::Interpreter { entry }), "{argv:?}");
        }
        for n in [
            "OPENSSL_CONF",
            "OPENSSL_ENGINES",
            "OPENSSL_MODULES",
            "GIO_MODULE_DIR",
            "QT_PLUGIN_PATH",
            "GST_PLUGIN_PATH",
            "JULIA_LOAD_PATH",
            "R_PROFILE_USER",
            "ERL_LIBS",
        ] {
            let mut d = decl(&["/usr/bin/server"]);
            d.env.push((n.into(), "/srv/x".into()));
            assert_eq!(
                check_declaration(&d),
                Err(DeclError::CodeSelecting(CodeSelecting::Variable)),
                "{n}"
            );
        }
    }

    /// A `#!` file's argv made explicit: the interpreter, the line's
    /// option, the script, the declaration's arguments. The line's option
    /// is checked as the interpreter's own would be; an interpreter that
    /// runs another program is refused; an unknown interpreter with an
    /// option, or an option that is not one, leaves what runs unknown.
    ///
    /// Mutation checked: the option not checked (the previous `#!`
    /// handling, which ignored it): `#!/bin/sh -c` registers, and this
    /// fails.
    #[test]
    fn a_shebang_line_is_checked_as_an_argv() {
        let args = vec!["--port".to_owned(), "1".to_owned()];
        assert_eq!(
            shebang_argv("/bin/sh", None, "/srv/s.sh", &args, "/bin/dash").unwrap(),
            vec!["/bin/sh", "/srv/s.sh", "--port", "1"]
        );
        assert_eq!(
            shebang_argv(
                "/usr/bin/python3",
                Some("-u"),
                "/srv/s.py",
                &[],
                "/usr/bin/python3.12"
            )
            .unwrap(),
            vec!["/usr/bin/python3", "-u", "/srv/s.py"]
        );
        assert_eq!(
            shebang_argv("/opt/x/runtime", None, "/srv/s", &[], "/opt/x/runtime").unwrap(),
            vec!["/opt/x/runtime", "/srv/s"]
        );
        for (interp, opt, resolved, err) in [
            (
                "/bin/sh",
                Some("-c"),
                "/bin/sh",
                DeclError::CodeSelecting(CodeSelecting::InterpreterOption),
            ),
            (
                "/usr/bin/node",
                Some("--require=/x.js"),
                "/usr/bin/node",
                DeclError::CodeSelecting(CodeSelecting::InterpreterOption),
            ),
            (
                "/usr/bin/perl",
                Some("-Mstrict"),
                "/usr/bin/perl",
                DeclError::CodeSelecting(CodeSelecting::InterpreterOption),
            ),
            ("/usr/bin/nice", None, "/usr/bin/nice", DeclError::Wrapper),
            ("/usr/bin/npx", None, "/usr/bin/npx", DeclError::Wrapper),
            (
                "/opt/x/runtime",
                Some("-q"),
                "/opt/x/runtime",
                DeclError::NoEntry,
            ),
            ("/bin/sh", Some("x"), "/bin/sh", DeclError::NoEntry),
            ("/srv/server", None, "/usr/bin/node", DeclError::Disguised),
        ] {
            assert_eq!(
                shebang_argv(interp, opt, "/srv/s", &[], resolved),
                Err(err),
                "{interp} {opt:?}"
            );
        }
    }

    /// Each header of a bridged server has the one binding its name and
    /// the origin give; a header that cannot be named so, or two headers
    /// that would share a binding, cannot be bridged.
    #[test]
    fn each_bridged_header_has_its_own_binding() {
        let o = "https://api.example.test";
        let suffix = bridge_binding_suffix(o);
        let h = bridge_headers(&["Authorization".into(), "X-Api-Key".into()], o).unwrap();
        assert_eq!(
            h,
            vec![
                ("Authorization".to_owned(), format!("AUTHORIZATION{suffix}")),
                ("X-Api-Key".to_owned(), format!("X_API_KEY{suffix}")),
            ]
        );
        assert_ne!(
            bridge_binding_name("Authorization", o),
            bridge_binding_name("Authorization", "https://other.example.test")
        );
        assert_eq!(bridge_headers(&["X-Key".into(), "x_key".into()], o), None);
        assert_eq!(bridge_binding_name("1-Key", o), None);
        assert_eq!(bridge_binding_name("X.Key", o), None);
        assert_eq!(bridge_binding_name("", o), None);
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

    /// Change one field at a time on each side of the statement. This
    /// catches omitted fields even when launch-time checks still refuse
    /// the changed object. Mutation: omit the resolved cwd from `launch`.
    #[test]
    fn every_launch_field_changes_both_digests() {
        use envcloak_core::vault::LaunchEnv;

        let file = FileIdentity {
            path: b"/srv/interpreter".to_vec(),
            dev: 11,
            ino: 12,
            digest: CodeDigest::Sha256([13; 32]),
        };
        let base = RegisteredLaunch {
            launch_id: [1; 16],
            revision: 2,
            class: LaunchClass::Script,
            strength: BindingStrength::CheckedAtRest,
            executable: file.clone(),
            argv: vec![b"/srv/interpreter".to_vec(), b"/srv/entry".to_vec()],
            cwd: DirIdentity {
                path: b"/srv".to_vec(),
                dev: 21,
                ino: 22,
            },
            env: LaunchEnv {
                path_env: b"/usr/bin".to_vec(),
                vars: vec![("MODE".into(), "dev".into())],
                binding_names: vec!["TOKEN".into()],
            },
            entry: Some(FileIdentity {
                path: b"/srv/entry".to_vec(),
                ..file
            }),
            declaration: LaunchDecl {
                argv: vec!["interpreter".into(), "/srv/entry".into()],
                cwd: Some("/srv".into()),
                env: vec![("MODE".into(), "dev".into())],
                path_env: Some("/usr/bin".into()),
            },
        };
        let check = |name: &str, old: &RegisteredLaunch, changed: &RegisteredLaunch| {
            assert_ne!(old, changed, "{name}: fixture must change");
            assert_ne!(launch_digest(old), launch_digest(changed), "{name}: launch");
            let original = update_digest(&old.launch_id, old, old);
            assert_ne!(
                original,
                update_digest(&old.launch_id, old, changed),
                "{name}: new side"
            );
            assert_ne!(
                original,
                update_digest(&old.launch_id, changed, old),
                "{name}: old side"
            );
        };
        assert_eq!(launch_digest(&base), launch_digest(&base.clone()));
        assert_eq!(
            update_digest(&base.launch_id, &base, &base),
            update_digest(&base.launch_id, &base.clone(), &base.clone())
        );
        macro_rules! changed {
            ($name:literal, $l:ident, $change:expr) => {{
                let mut $l = base.clone();
                $change;
                check($name, &base, &$l);
            }};
        }
        changed!("revision", l, l.revision += 1);
        changed!("class native", l, l.class = LaunchClass::Native);
        changed!("class runner", l, l.class = LaunchClass::PackageRunner);
        changed!("strength", l, l.strength = BindingStrength::Bound);
        changed!("argv bytes", l, l.argv[1].push(0xff));
        changed!("argv length", l, l.argv.push(Vec::new()));
        changed!("argv order", l, l.argv.swap(0, 1));
        changed!("cwd path", l, l.cwd.path.push(0xff));
        changed!("cwd device", l, l.cwd.dev += 1);
        changed!("cwd inode", l, l.cwd.ino += 1);
        changed!("path_env", l, l.env.path_env.push(0xff));
        changed!("vars name", l, l.env.vars[0].0.push('X'));
        changed!("vars value", l, l.env.vars[0].1.push('X'));
        changed!(
            "vars length",
            l,
            l.env.vars.push(("MORE".into(), String::new()))
        );
        changed!("binding name", l, l.env.binding_names[0].push('X'));
        changed!("binding length", l, l.env.binding_names.push("MORE".into()));
        changed!("entry presence", l, l.entry = None);
        changed!("declaration argv", l, l.declaration.argv[0].push('X'));
        changed!(
            "declaration argv length",
            l,
            l.declaration.argv.push(String::new())
        );
        changed!("declaration argv order", l, l.declaration.argv.swap(0, 1));
        changed!(
            "declaration cwd",
            l,
            l.declaration.cwd = Some("/elsewhere".into())
        );
        changed!("declaration cwd presence", l, l.declaration.cwd = None);
        changed!("declaration env name", l, l.declaration.env[0].0.push('X'));
        changed!("declaration env value", l, l.declaration.env[0].1.push('X'));
        changed!(
            "declaration env length",
            l,
            l.declaration.env.push(("MORE".into(), String::new()))
        );
        changed!(
            "declaration path_env",
            l,
            l.declaration.path_env = Some("/bin".into())
        );
        changed!(
            "declaration path_env presence",
            l,
            l.declaration.path_env = None
        );

        // The statement encodes the common launch id once, outside both
        // revisions; the launch digest takes that id from its record.
        let mut id = base.clone();
        id.launch_id[0] += 1;
        assert_ne!(launch_digest(&base), launch_digest(&id));
        assert_ne!(
            update_digest(&base.launch_id, &base, &base),
            update_digest(&id.launch_id, &id, &id)
        );

        for entry in [false, true] {
            fn select(l: &mut RegisteredLaunch, entry: bool) -> &mut FileIdentity {
                if entry {
                    l.entry.as_mut().unwrap()
                } else {
                    &mut l.executable
                }
            }
            for field in [
                "path",
                "dev",
                "ino",
                "sha256",
                "kind",
                "cdhash",
                "team",
                "identifier",
                "team presence",
                "identifier presence",
            ] {
                let mut original = base.clone();
                if matches!(
                    field,
                    "cdhash" | "team" | "identifier" | "team presence" | "identifier presence"
                ) {
                    select(&mut original, entry).digest = CodeDigest::CdHash {
                        cdhash: vec![14; 20],
                        team: Some(String::new()),
                        identifier: Some(String::new()),
                    };
                }
                let mut changed = original.clone();
                let f = select(&mut changed, entry);
                match field {
                    "path" => f.path.push(0xff),
                    "dev" => f.dev += 1,
                    "ino" => f.ino += 1,
                    "sha256" => f.digest = CodeDigest::Sha256([14; 32]),
                    "kind" => {
                        f.digest = CodeDigest::CdHash {
                            cdhash: vec![13; 32],
                            team: None,
                            identifier: None,
                        }
                    }
                    _ => {
                        let CodeDigest::CdHash {
                            cdhash,
                            team,
                            identifier,
                        } = &mut f.digest
                        else {
                            unreachable!()
                        };
                        match field {
                            "cdhash" => cdhash[0] += 1,
                            "team" => *team = Some("fixture-team".into()),
                            "identifier" => *identifier = Some("fixture-id".into()),
                            "team presence" => *team = None,
                            "identifier presence" => *identifier = None,
                            _ => unreachable!(),
                        }
                    }
                }
                check(&format!("entry={entry} {field}"), &original, &changed);
            }
        }
    }

    /// Recorded variables and released bindings bypass the inherited
    /// allowlist, so test each input independently with allowed controls.
    /// Mutation: allow LD_/DYLD_ names through the builder's `put` filter.
    #[test]
    fn loader_names_are_filtered_from_recorded_vars_and_bindings() {
        for name in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "LD_FUTURE",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FUTURE",
        ]
        .into_iter()
        .chain(CODE_SELECTING.iter().copied())
        {
            for binding in [false, true] {
                let vars = if binding {
                    vec![]
                } else {
                    vec![(name.into(), "fixture".into())]
                };
                let bindings = if binding {
                    vec![(name, b"fixture".as_slice())]
                } else {
                    vec![]
                };
                let env = launch_environment([], b"/bin", &vars, &bindings);
                assert_eq!(
                    env,
                    vec![(b"PATH".to_vec(), b"/bin".to_vec())],
                    "{name}, binding={binding}"
                );
            }
        }
        for name in ["MODE", "LC_LD_PRELOAD", "LDX_PRELOAD", "DYLDX_PATH"] {
            let vars = vec![(name.into(), "recorded".into())];
            let env = launch_environment([], b"/bin", &vars, &[]);
            assert_eq!(env[1], (name.as_bytes().to_vec(), b"recorded".to_vec()));
            let env = launch_environment([], b"/bin", &[], &[(name, b"binding")]);
            assert_eq!(env[1], (name.as_bytes().to_vec(), b"binding".to_vec()));
        }
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
            inherited.push(((*n).into(), "x".into()));
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
