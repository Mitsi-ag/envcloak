//! The manifest editor of `envcloak ref NAME=<slug>[#field]` (SPEC §7:
//! an agent that needs a key finds it with `envcloak ls` and references
//! it): [`edit_manifest_ref`] binds a variable to an item in an
//! `envcloak.toml`. The manifest holds names only, so this reads and
//! writes no value.
//!
//! The edit keeps everything else as it was:
//! comments, order, spacing and quoting stay, and a binding that is
//! replaced keeps its comment. It is written atomically:
//! 1. the manifest is opened through its directory's descriptor, never
//!    through a symlink, and must be a regular file of this user with no
//!    other hard link, at most 64 KiB, that parses; its device, inode,
//!    size and modification time are noted;
//! 2. the new text must parse too, to the old manifest with the binding
//!    set and nothing else changed: every other binding, in `[env]` and in
//!    each profile, stays. A variable named like a profile in `[env]` is
//!    refused, since writing it would replace the profile's table;
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

use envcloak_ipc::view::RefChange;
use envcloak_policy::{Binding, MANIFEST_NAME, Manifest, ProfileName, Reference, parse_manifest};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::fail::Failure;

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
    /// `[env]` has a profile with the variable's name.
    NameIsProfile,
    /// The manifest has another hard link.
    HardLinked,
    /// The new manifest would differ from the old one in more than the
    /// binding set.
    OthersChanged,
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
            EditError::NameIsProfile => invalid(
                "[env] has a profile with the variable's name, so the variable cannot be \
                 written there",
            ),
            EditError::HardLinked => invalid(
                "envcloak.toml has another hard link, which replacing it would split from it, \
                 so it is never replaced",
            ),
            EditError::OthersChanged => invalid(
                "the edit would have changed more than the one binding, so nothing was written",
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
/// checks it is this user's regular file, with no other hard link.
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
    // Replaced by a rename, a hard-linked file would split: its other name
    // would keep the old bindings (SPEC §6.4: reported, never modified).
    if m.nlink() > 1 {
        return Err(EditError::HardLinked);
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

/// Checks that `new_text` is the manifest `old` with `binding` set in
/// `[env]`, or in `[env.<profile>]`, and nothing else changed: every other
/// binding, in `[env]` and in every profile, the project name and the
/// policy are as they were. A text edit that went wrong is refused here
/// rather than written.
fn check_edit(
    old: &Manifest,
    new_text: &str,
    binding: &Binding,
    profile: Option<&ProfileName>,
) -> Result<(), EditError> {
    let new = parse_manifest(new_text.as_bytes()).map_err(EditError::Manifest)?;
    let mut expected = old.clone();
    let list = match profile {
        None => &mut expected.env,
        Some(p) => expected.profiles.entry(p.clone()).or_default(),
    };
    list.retain(|b| b.env_name != binding.env_name);
    list.push(binding.clone());
    list.sort();
    expected.sha256 = new.sha256;
    if new == expected {
        Ok(())
    } else {
        Err(EditError::OthersChanged)
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
        // Under `[env]`, a standard or dotted table of that name is a
        // profile, which a binding must never replace.
        Some(item) if !matches!(item, Item::Value(Value::String(_) | Value::InlineTable(_))) => {
            return Err(EditError::NameIsProfile);
        }
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
    let old = parse_manifest(&bytes).map_err(EditError::Manifest)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| EditError::Manifest(envcloak_policy::ManifestErrorKind::NotUtf8.into()))?;
    let (new_text, edit) = edited_text(text, binding, profile)?;
    let Some(new_text) = new_text else {
        return Ok(edit);
    };
    if new_text.len() > Manifest::MAX_LEN {
        return Err(EditError::TooLarge);
    }
    // The new manifest must parse, with the binding where it was put and
    // everything else as it was.
    check_edit(&old, &new_text, binding, profile)?;

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

    /// A variable named like a profile never replaces the profile's table,
    /// written as a table or with dotted keys: the edit is refused and the
    /// manifest keeps every binding. (It once overwrote `[env.short]` with
    /// `short = "x/y"`, dropping the profile's bindings, and said so as a
    /// success.)
    #[test]
    fn a_variable_named_like_a_profile_never_replaces_it() {
        for text in [
            "[env]\nA = \"a/b\"\n\n[env.short]\nS = \"s/t\"\nT = \"u/v\"\n",
            "[env]\nA = \"a/b\"\nshort.S = \"s/t\"\nshort.T = \"u/v\"\n",
            "env.A = \"a/b\"\nenv.short.S = \"s/t\"\n",
        ] {
            let d = tempfile::tempdir().unwrap();
            let p = manifest_in(d.path(), text);
            let e = edit_manifest_ref(&p, &binding("short=x/y"), None).unwrap_err();
            assert_eq!(e, EditError::NameIsProfile, "{text}");
            assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
            assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
            // The profile itself still takes new bindings.
            let short = ProfileName::new("short").unwrap();
            edit_manifest_ref(&p, &binding("U=x/y"), Some(&short)).unwrap();
            let m = parse_manifest(&std::fs::read(&p).unwrap()).unwrap();
            assert_eq!(m.env, vec![binding("A=a/b")], "{text}");
            assert!(m.profiles[&short].contains(&binding("S=s/t")), "{text}");
            assert!(m.profiles[&short].contains(&binding("U=x/y")), "{text}");
        }
    }

    /// Whatever the text edit did, the new manifest must be the old one
    /// with the one binding set: an edit that drops or changes any other
    /// binding, in `[env]` or in a profile, the project name or the policy
    /// is refused.
    #[test]
    fn an_edit_that_changes_anything_else_is_refused() {
        let old = parse_manifest(
            b"[project]\nname = \"p\"\n[env]\nA = \"a/b\"\n\n[env.short]\nS = \"s/t\"\n",
        )
        .unwrap();
        let short = ProfileName::new("short").unwrap();
        let ok = [
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\nB = \"c/d\"\n\n[env.short]\nS = \"s/t\"\n",
                "B=c/d",
                None,
            ),
            (
                "[project]\nname = \"p\"\n[env]\nA = \"x/y\"\n\n[env.short]\nS = \"s/t\"\n",
                "A=x/y",
                None,
            ),
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\n\n[env.short]\nS = \"x/y\"\n",
                "S=x/y",
                Some(&short),
            ),
        ];
        for (new, b, profile) in ok {
            assert_eq!(check_edit(&old, new, &binding(b), profile), Ok(()), "{new}");
        }
        let refused = [
            // What the edit wrote when a variable was named like a profile.
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\nshort= \"x/y\"\n",
                "short=x/y",
                None,
            ),
            // Another binding dropped or changed, in [env] or a profile.
            (
                "[project]\nname = \"p\"\n[env]\nB = \"c/d\"\n\n[env.short]\nS = \"s/t\"\n",
                "B=c/d",
                None,
            ),
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\nB = \"c/d\"\n\n[env.short]\nS = \"z/z\"\n",
                "B=c/d",
                None,
            ),
            // The binding put in the wrong table.
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\nS = \"x/y\"\n\n[env.short]\nS = \"s/t\"\n",
                "S=x/y",
                Some(&short),
            ),
            // The project name or the policy changed.
            (
                "[project]\nname = \"q\"\n[env]\nA = \"a/b\"\nB = \"c/d\"\n\n[env.short]\nS = \"s/t\"\n",
                "B=c/d",
                None,
            ),
            (
                "[project]\nname = \"p\"\n[env]\nA = \"a/b\"\nB = \"c/d\"\n\n[env.short]\nS = \"s/t\"\n\
                 [policy]\nagents = \"deny\"\n",
                "B=c/d",
                None,
            ),
        ];
        for (new, b, profile) in refused {
            assert_eq!(
                check_edit(&old, new, &binding(b), profile),
                Err(EditError::OthersChanged),
                "{new}"
            );
        }
    }

    /// A manifest with another hard link is never replaced: a rename would
    /// split the two names, and the other would keep the old bindings.
    #[test]
    fn a_hard_linked_manifest_is_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let p = manifest_in(d.path(), COMMENTED);
        let other = d.path().join("other-link.toml");
        std::fs::hard_link(&p, &other).unwrap();
        let e = edit_manifest_ref(&p, &binding("C=d/e"), None).unwrap_err();
        assert_eq!(e, EditError::HardLinked);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), COMMENTED);
        assert_eq!(std::fs::read_to_string(&other).unwrap(), COMMENTED);
        assert_eq!(
            std::fs::metadata(&p).unwrap().ino(),
            std::fs::metadata(&other).unwrap().ino()
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
        // Once the other name is gone, the edit goes ahead.
        std::fs::remove_file(&other).unwrap();
        edit_manifest_ref(&p, &binding("C=d/e"), None).unwrap();
    }
}
