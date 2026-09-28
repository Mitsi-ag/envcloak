//! `envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]` (SPEC §7:
//! an agent that needs a key finds it with `envcloak ls` and references
//! it here): binds a variable to an item in the nearest `envcloak.toml`.
//! The manifest holds names only, so this reads and writes no value, and
//! needs no daemon; when one answers, it says whether the reference
//! resolves.
//!
//! The edit ([`edit_manifest_ref`]) keeps everything else as it was:
//! comments, order, spacing and quoting stay, and a binding that is
//! replaced keeps its comment. It is written atomically:
//! 1. the manifest is opened through its directory's descriptor, never
//!    through a symlink, and must be a regular file of this user, at most
//!    64 KiB, that parses; its device, inode, size and modification time
//!    are noted;
//! 2. the new text must parse too, with the binding in place;
//! 3. it is written to a new file beside the manifest (`O_EXCL`, mode 0600,
//!    then the manifest's own mode), and flushed to disk;
//! 4. the manifest is looked at again: when anything changed since step 1
//!    (another program wrote it), the new file is removed and nothing is
//!    replaced;
//! 5. the new file is renamed over the manifest, and the directory flushed.
//!
//! A crash at any point leaves the old manifest or the new one, never a
//! part of either. A binding written is a request for approval later, not
//! an approval: `envcloak run` still asks for the new binding.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_ipc::view::{RefChange, RefEditView};
use envcloak_policy::{
    Binding, MANIFEST_NAME, Manifest, ProfileName, Reference, find_manifest, parse_manifest,
};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use super::refuse_value_like;
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, USAGE, usage};
use crate::render::print;

const USAGE_TEXT: &str = "envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]";

/// What an edit did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEdit {
    pub change: RefChange,
    /// The reference the variable had, when replaced.
    pub previous: Option<Reference>,
}

/// Why the manifest was not edited. Every message is fixed text or a
/// value-free manifest error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The manifest, as found or as it would be, does not parse.
    Manifest(envcloak_policy::ManifestError),
    /// `envcloak.toml` is a symlink.
    Symlink,
    /// Not a regular file of this user.
    NotRegular,
    NotOwned,
    /// A variable in `[env]` has the profile's name.
    ProfileClash,
    /// The manifest changed while it was edited.
    Changed,
    /// The new text is over 64 KiB.
    TooLarge,
    /// Reading or writing failed.
    Io(std::io::ErrorKind),
}

impl From<EditError> for Failure {
    fn from(e: EditError) -> Self {
        let invalid = |m: &'static str| Failure::new("manifest_invalid", m);
        match e {
            EditError::Manifest(m) => Failure::new(
                "manifest_invalid",
                format!("envcloak.toml: {m}; nothing was changed"),
            ),
            EditError::Symlink => invalid("envcloak.toml is a symlink, which is never followed"),
            EditError::NotRegular => invalid("envcloak.toml is not a regular file"),
            EditError::NotOwned => invalid("envcloak.toml is owned by another user"),
            EditError::ProfileClash => invalid(
                "[env] binds a variable with the profile's name, so the profile cannot be \
                 written there",
            ),
            EditError::Changed => Failure::new(
                "manifest_changed",
                "envcloak.toml changed while it was edited, so nothing was written; run it again",
            ),
            EditError::TooLarge => invalid("the manifest would be larger than 64 KiB"),
            EditError::Io(_) => Failure::new(
                "io",
                "envcloak.toml could not be read or written; nothing was changed",
            ),
        }
    }
}

fn io(e: &std::io::Error) -> EditError {
    EditError::Io(e.kind())
}

/// What identifies the manifest's contents on disk: if any of these
/// changed, another program wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Stamp {
    fn of(m: &std::fs::Metadata) -> Self {
        Stamp {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
        }
    }
}

/// Opens the manifest `name` in `dir` without following a symlink, and
/// checks it is this user's regular file.
fn open_manifest(dir: &File) -> Result<(File, std::fs::Metadata), EditError> {
    let f = envcloak_sys::open_beneath(dir, OsStr::new(MANIFEST_NAME)).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            EditError::Symlink
        } else {
            io(&e)
        }
    })?;
    let m = f.metadata().map_err(|e| io(&e))?;
    if !m.file_type().is_file() {
        return Err(EditError::NotRegular);
    }
    if m.uid() != envcloak_sys::effective_uid() {
        return Err(EditError::NotOwned);
    }
    Ok((f, m))
}

/// The reference a binding item holds: `"<slug>[#field]"` or `{ ref, field
/// }`. `None` for anything else, which the parser has refused already.
fn reference_of(item: &Item) -> Option<Reference> {
    match item {
        Item::Value(Value::String(s)) => Reference::parse(s.value()).ok(),
        Item::Value(Value::InlineTable(t)) => {
            let slug = t.get("ref")?.as_str()?;
            let r = Reference::parse(slug).ok()?;
            let field = match t.get("field") {
                Some(f) => Some(envcloak_core::vault::FieldName::new(f.as_str()?).ok()?),
                None => None,
            };
            Some(Reference {
                slug: r.slug,
                field,
            })
        }
        _ => None,
    }
}

/// The text of `manifest` with `binding` set in `[env]`, or in
/// `[env.<profile>]`, and what changed. `None` text when nothing changes.
fn edited_text(
    manifest: &str,
    binding: &Binding,
    profile: Option<&ProfileName>,
) -> Result<(Option<String>, RefEdit), EditError> {
    let mut doc: DocumentMut = manifest
        .parse()
        .map_err(|_| EditError::Manifest(envcloak_policy::ManifestErrorKind::Syntax.into()))?;
    let root = doc.as_table_mut();
    if !root.contains_key("env") {
        root.insert("env", Item::Table(Table::new()));
    }
    let wrong = || EditError::Manifest(envcloak_policy::ManifestErrorKind::WrongType.into());
    let env = root.get_mut("env").ok_or_else(wrong)?;
    let table: &mut dyn TableLike = match (profile, env) {
        (None, env) => env.as_table_like_mut().ok_or_else(wrong)?,
        // A profile is a table of its own: `[env.<profile>]`.
        (Some(p), Item::Table(env)) => {
            if !env.contains_key(p.as_str()) {
                env.insert(p.as_str(), Item::Table(Table::new()));
            }
            match env.get_mut(p.as_str()) {
                Some(Item::Table(t)) => t,
                _ => return Err(EditError::ProfileClash),
            }
        }
        (Some(_), _) => return Err(wrong()),
    };
    let new_text = binding.reference.to_string();
    let name = binding.env_name.as_str();
    let edit = match table.get_mut(name) {
        Some(item) => {
            let previous = reference_of(item);
            if previous.as_ref() == Some(&binding.reference) {
                return Ok((
                    None,
                    RefEdit {
                        change: RefChange::Unchanged,
                        previous,
                    },
                ));
            }
            // The new value keeps the old one's surroundings: the space
            // before it and a comment after it.
            let decor = item.as_value().map(|v| v.decor().clone());
            let mut value = Value::from(new_text);
            if let Some(d) = decor {
                *value.decor_mut() = d;
            }
            *item = Item::Value(value);
            RefEdit {
                change: RefChange::Replaced,
                previous,
            }
        }
        None => {
            table.insert(name, toml_edit::value(new_text));
            RefEdit {
                change: RefChange::Added,
                previous: None,
            }
        }
    };
    Ok((Some(doc.to_string()), edit))
}

/// Binds `binding` in the manifest at `path` (in `[env]`, or in
/// `[env.<profile>]`), atomically and keeping the rest of the file as it
/// was. See the module documentation for the steps.
///
/// # Errors
/// An [`EditError`]; the manifest is then as it was.
pub fn edit_manifest_ref(
    path: &Path,
    binding: &Binding,
    profile: Option<&ProfileName>,
) -> Result<RefEdit, EditError> {
    edit_with(path, binding, profile, || {})
}

/// [`edit_manifest_ref`], with `before_replace` run just before the
/// manifest is looked at again (step 4), so a test can change it there.
fn edit_with(
    path: &Path,
    binding: &Binding,
    profile: Option<&ProfileName>,
    before_replace: impl FnOnce(),
) -> Result<RefEdit, EditError> {
    let parent = path
        .parent()
        .ok_or(EditError::Io(std::io::ErrorKind::NotFound))?;
    let dir_path = std::fs::canonicalize(parent).map_err(|e| io(&e))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&dir_path)
        .map_err(|e| io(&e))?;
    let dir_stamp = dir.metadata().map_err(|e| io(&e))?;
    let (mut file, meta) = open_manifest(&dir)?;
    if meta.len() > Manifest::MAX_LEN as u64 {
        return Err(EditError::Manifest(
            envcloak_policy::ManifestErrorKind::TooLarge.into(),
        ));
    }
    let stamp = Stamp::of(&meta);
    let mut bytes = Vec::new();
    (&mut file)
        .take(Manifest::MAX_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    drop(file);
    // The manifest as it is must parse: an edit never hides a problem.
    parse_manifest(&bytes).map_err(EditError::Manifest)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| EditError::Manifest(envcloak_policy::ManifestErrorKind::NotUtf8.into()))?;
    let (new_text, edit) = edited_text(text, binding, profile)?;
    let Some(new_text) = new_text else {
        return Ok(edit);
    };
    if new_text.len() > Manifest::MAX_LEN {
        return Err(EditError::TooLarge);
    }
    // The new manifest must parse, with the binding where it was put.
    let parsed = parse_manifest(new_text.as_bytes()).map_err(EditError::Manifest)?;
    let placed = match profile {
        None => Some(&parsed.env),
        Some(p) => parsed.profiles.get(p),
    };
    if !placed.is_some_and(|list| list.contains(binding)) {
        return Err(EditError::Manifest(
            envcloak_policy::ManifestErrorKind::WrongType.into(),
        ));
    }

    let temp = temp_path(&dir_path);
    let result = write_and_replace(
        &dir,
        &dir_path,
        &dir_stamp,
        &temp,
        new_text.as_bytes(),
        &meta,
        stamp,
        before_replace,
    );
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map(|()| edit)
}

/// A new name beside the manifest: `.envcloak.toml.<hex>.tmp`, from a
/// randomly keyed hash of the time and this process. Not secret; a clash
/// only makes `O_EXCL` fail, which fails the edit.
fn temp_path(dir: &Path) -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = RandomState::new().hash_one((nanos, std::process::id()));
    dir.join(format!(".{MANIFEST_NAME}.{h:016x}.tmp"))
}

#[allow(clippy::too_many_arguments)]
fn write_and_replace(
    dir: &File,
    dir_path: &Path,
    dir_stamp: &std::fs::Metadata,
    temp: &Path,
    bytes: &[u8],
    meta: &std::fs::Metadata,
    stamp: Stamp,
    before_replace: impl FnOnce(),
) -> Result<(), EditError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temp)
        .map_err(|e| io(&e))?;
    f.write_all(bytes).map_err(|e| io(&e))?;
    f.set_permissions(Permissions::from_mode(meta.mode() & 0o7777))
        .map_err(|e| io(&e))?;
    envcloak_sys::sync_file(&f).map_err(|e| io(&e))?;
    drop(f);
    before_replace();
    // Another program wrote the manifest meanwhile: keep its version.
    let (_, now) = open_manifest(dir)?;
    if Stamp::of(&now) != stamp {
        return Err(EditError::Changed);
    }
    // The path must still name the directory opened.
    let again = std::fs::metadata(dir_path).map_err(|e| io(&e))?;
    if (again.dev(), again.ino()) != (dir_stamp.dev(), dir_stamp.ino()) {
        return Err(EditError::Changed);
    }
    std::fs::rename(temp, dir_path.join(MANIFEST_NAME)).map_err(|e| io(&e))?;
    envcloak_sys::sync_file(dir).map_err(|e| io(&e))?;
    Ok(())
}

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
struct RefArgs {
    binding: Binding,
    profile: Option<ProfileName>,
    json: bool,
}

fn parse(args: &[&str]) -> Result<RefArgs, &'static str> {
    let mut binding = None;
    let mut profile = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !json => json = true,
            "--profile" if profile.is_none() => {
                let p = *it.next().ok_or("--profile needs a name")?;
                profile = Some(ProfileName::new(p).map_err(|_| "invalid profile name")?);
            }
            _ if arg.starts_with('-') => return Err("unknown or repeated option"),
            _ if binding.is_some() => return Err("ref takes one NAME=<slug>[#field]"),
            _ => binding = Some(arg),
        }
    }
    let text = binding.ok_or("ref needs NAME=<slug>[#field]")?;
    Ok(RefArgs {
        binding: Binding::parse_arg(text).map_err(|_| "ref needs NAME=<slug>[#field]")?,
        profile,
        json,
    })
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    // A value pasted as an argument is refused as one, before anything
    // about its grammar is said.
    let pieces: Vec<&str> = args
        .iter()
        .flat_map(|a| a.split(['=', '#']))
        .filter(|p| !p.is_empty())
        .collect();
    if let Err(f) = refuse_value_like(&pieces) {
        return f.report(USAGE);
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    edit(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn edit(a: RefArgs) -> Result<ExitCode, Failure> {
    let manifest = match find_manifest(Path::new(".")) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(Failure::new(
                "manifest_invalid",
                "no envcloak.toml in this directory or above it; run `envcloak init` first",
            ));
        }
        Err(_) => {
            return Err(Failure::new(
                "manifest_invalid",
                "the working directory could not be read while looking for envcloak.toml",
            ));
        }
    };
    let e = edit_manifest_ref(&manifest, &a.binding, a.profile.as_ref())?;
    // Whether the vault has the item: asked when a daemon answers, and
    // never a reason to fail.
    let text = format!("{}={}", a.binding.env_name, a.binding.reference);
    let resolves = connect()
        .ok()
        .and_then(|mut c| c.items_check(None, &[text]).ok())
        .and_then(|v| v.refs.first().copied());
    let view = RefEditView {
        manifest: manifest.to_string_lossy().into_owned(),
        profile: a.profile.map(|p| p.as_str().to_owned()),
        env_name: a.binding.env_name.as_str().to_owned(),
        reference: a.binding.reference.to_string(),
        change: e.change,
        previous: e.previous.map(|r| r.to_string()),
        resolves,
    };
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMENTED: &str = "# The acme-web project. Names only; no values here.
[project]
name = \"acme-web\" # shown in approvals

# Default profile.
[env]
OPENAI_API_KEY = \"openai/acme-web\"   # the main key
STRIPE_SECRET_KEY = { ref = \"stripe/acme-web\", field = \"value\" }

# Short-lived tokens.
[env.short]
SHORT_TOKEN = \"short/acme-web\"

[policy]
agents = \"approve\" # never allow
";

    fn binding(s: &str) -> Binding {
        Binding::parse_arg(s).unwrap()
    }

    fn manifest_in(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join(MANIFEST_NAME);
        std::fs::write(&p, text).unwrap();
        p
    }

    /// A new binding goes at the end of its table; everything else is
    /// kept byte for byte, comments included.
    #[test]
    fn adding_keeps_every_comment_and_line() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), COMMENTED);
        let e = edit_manifest_ref(&p, &binding("GITHUB_TOKEN=github/acme-web"), None).unwrap();
        assert_eq!(e.change, RefChange::Added);
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            COMMENTED.replace(
                "field = \"value\" }\n",
                "field = \"value\" }\nGITHUB_TOKEN = \"github/acme-web\"\n"
            )
        );
        let e = edit_manifest_ref(
            &p,
            &binding("OTHER=github/acme-web#value"),
            Some(&ProfileName::new("short").unwrap()),
        )
        .unwrap();
        assert_eq!(e.change, RefChange::Added);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("SHORT_TOKEN = \"short/acme-web\"\nOTHER = \"github/acme-web#value\"\n"),
            "{text}"
        );
        for comment in [
            "# The acme-web project. Names only; no values here.",
            "# shown in approvals",
            "# Default profile.",
            "# the main key",
            "# Short-lived tokens.",
            "# never allow",
        ] {
            assert!(text.contains(comment), "{comment}\n{text}");
        }
    }

    /// Replacing keeps the binding's own comment and the rest of the file;
    /// setting what is there already writes nothing.
    #[test]
    fn replacing_keeps_the_binding_comment_and_unchanged_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), COMMENTED);
        let e = edit_manifest_ref(&p, &binding("OPENAI_API_KEY=openai/work"), None).unwrap();
        assert_eq!(e.change, RefChange::Replaced);
        assert_eq!(
            e.previous,
            Some(Reference::parse("openai/acme-web").unwrap())
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            COMMENTED.replace(
                "OPENAI_API_KEY = \"openai/acme-web\"   # the main key",
                "OPENAI_API_KEY = \"openai/work\"   # the main key"
            )
        );
        // The inline-table form is compared by what it names.
        let before = std::fs::metadata(&p).unwrap();
        let e = edit_manifest_ref(
            &p,
            &binding("STRIPE_SECRET_KEY=stripe/acme-web#value"),
            None,
        )
        .unwrap();
        assert_eq!(e.change, RefChange::Unchanged);
        let after = std::fs::metadata(&p).unwrap();
        assert_eq!(Stamp::of(&before), Stamp::of(&after));
    }

    /// A manifest without `[env]` gets one; a new profile gets its table.
    #[test]
    fn missing_tables_are_made() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), "[project]\nname = \"x\"\n");
        edit_manifest_ref(&p, &binding("A=openai/x"), None).unwrap();
        edit_manifest_ref(
            &p,
            &binding("B=stripe/x"),
            Some(&ProfileName::new("ci").unwrap()),
        )
        .unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let m = parse_manifest(text.as_bytes()).unwrap();
        assert_eq!(m.env, vec![binding("A=openai/x")]);
        assert_eq!(
            m.profiles[&ProfileName::new("ci").unwrap()],
            vec![binding("B=stripe/x")]
        );
        assert!(text.starts_with("[project]\nname = \"x\"\n"), "{text}");
    }

    /// The edit replaces the file by a rename (a new inode, the old mode)
    /// and leaves no temporary file behind.
    #[test]
    fn the_file_is_replaced_whole_with_its_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), COMMENTED);
        std::fs::set_permissions(&p, Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&p).unwrap();
        // A reader that opened the old file keeps reading it whole.
        let mut held = File::open(&p).unwrap();
        edit_manifest_ref(&p, &binding("GITHUB_TOKEN=github/acme-web"), None).unwrap();
        let after = std::fs::metadata(&p).unwrap();
        assert_ne!(before.ino(), after.ino());
        assert_eq!(after.mode() & 0o7777, 0o640);
        let mut old = String::new();
        held.read_to_string(&mut old).unwrap();
        assert_eq!(old, COMMENTED);
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(MANIFEST_NAME)]);
    }

    /// A manifest another program changes during the edit is left as that
    /// program wrote it, and the new file is removed.
    #[test]
    fn a_concurrent_change_wins_and_nothing_is_replaced() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), COMMENTED);
        let theirs = format!("{COMMENTED}# edited meanwhile\n");
        let e = edit_with(&p, &binding("GITHUB_TOKEN=github/acme-web"), None, || {
            std::fs::write(&p, &theirs).unwrap();
        })
        .unwrap_err();
        assert_eq!(e, EditError::Changed);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), theirs);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    /// Refused, with the manifest untouched: a symlinked manifest (never
    /// followed), one that does not parse, a manifest that would stop
    /// parsing, and a profile named like a variable in `[env]`.
    #[test]
    fn unsafe_or_invalid_manifests_are_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("elsewhere.toml");
        std::fs::write(&target, COMMENTED).unwrap();
        let project = d.path().join("p");
        std::fs::create_dir(&project).unwrap();
        std::os::unix::fs::symlink(&target, project.join(MANIFEST_NAME)).unwrap();
        let e = edit_manifest_ref(&project.join(MANIFEST_NAME), &binding("A=b/c"), None);
        assert_eq!(e.unwrap_err(), EditError::Symlink);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), COMMENTED);

        for (text, profile) in [
            ("[env]\nA = \"not a reference\"\n", None),
            ("[policy]\nagents = \"allow\"\n", None),
            ("[env]\nci = \"openai/x\"\n", Some("ci")),
        ] {
            let q = tempfile::tempdir().unwrap();
            let p = manifest_in(q.path(), text);
            let profile = profile.map(|p| ProfileName::new(p).unwrap());
            assert!(
                edit_manifest_ref(&p, &binding("B=openai/y"), profile.as_ref()).is_err(),
                "{text}"
            );
            assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
            assert_eq!(std::fs::read_dir(q.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn arguments_are_one_binding_and_names() {
        let a = parse(&["OPENAI_API_KEY=openai/acme-web", "--profile", "short"]).unwrap();
        assert_eq!(a.binding, binding("OPENAI_API_KEY=openai/acme-web"));
        assert_eq!(a.profile, Some(ProfileName::new("short").unwrap()));
        for bad in [
            &[][..],
            &["A=b", "C=d"],
            &["A"],
            &["A=b", "--profile"],
            &["A=b", "--profile", "Bad"],
            &["A=b", "--value", "x"],
            &["=b"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
