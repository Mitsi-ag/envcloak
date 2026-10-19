//! Explicit vendor exports stay on disk. Only the normal daemon importer
//! decides acceptance, deduplication and the current plan at commit.
use super::*;
use envcloak_client::doctor_report::display_path;
use envcloak_client::render::{json_text, shown};
use envcloak_ipc::proto::{ImportCommit, ImportPlan, MachineScope, MachineSource, request_frame};
use envcloak_scan::formats::{self, FormatError, Kind};
use serde_json::json;

fn format_failure(error: FormatError) -> Failure {
    match error {
        FormatError::Limit => Failure::new(
            "import_too_large",
            "the export exceeds a parser limit; split it before importing",
        ),
        FormatError::Read => Failure::new(
            "io",
            "the export could not be read as a stable regular file",
        ),
        FormatError::Invalid | FormatError::Shape => Failure::new(
            "import",
            "the export is malformed or its format is unsupported",
        ),
    }
}
fn preflight(bundle: &ImportCommitParams) -> Result<(), Failure> {
    request_frame::<ImportPlan>(u64::MAX, &bundle.import).map_err(|_| {
        Failure::new(
            "import_too_large",
            "the export plan exceeds the IPC frame limit",
        )
    })?;
    request_frame::<ImportCommit>(u64::MAX, bundle).map_err(|_| {
        Failure::new(
            "import_too_large",
            "the export commit exceeds the IPC frame limit",
        )
    })?;
    Ok(())
}
const MAX_METADATA: usize = 256 << 10;
struct Collector {
    entries: Vec<ImportEntry>,
    metadata: usize,
    values: usize,
    manual: usize,
    rejected: bool,
}
impl Collector {
    fn new(claims: &[String]) -> Result<Self, Failure> {
        let metadata = claims
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.len()));
        if claims.len() > 64 || metadata.is_none_or(|n| n > MAX_METADATA) {
            return Err(Failure::new(
                "import_too_large",
                "the export claim budget was reached",
            ));
        }
        Ok(Self {
            entries: Vec::new(),
            metadata: metadata.unwrap_or(0),
            values: 0,
            manual: 0,
            rejected: false,
        })
    }
    fn push(&mut self, entry: formats::Entry, kind: Kind, display: &str) {
        if self.rejected {
            return;
        }
        let Some(name) = entry.env_name() else {
            self.manual += 1;
            return;
        };
        let metadata = self
            .metadata
            .checked_add(name.len())
            .and_then(|n| n.checked_add(display.len()))
            .and_then(|n| n.checked_add(kind.as_str().len()));
        let values = self.values.checked_add(entry.value.len());
        if self.entries.len() == formats::MAX_ENTRIES
            || metadata.is_none_or(|n| n > MAX_METADATA)
            || values.is_none_or(|n| n > formats::MAX_VALUES)
        {
            self.rejected = true;
            self.entries.clear();
            return;
        }
        self.metadata = metadata.unwrap_or(MAX_METADATA);
        self.values = values.unwrap_or(formats::MAX_VALUES);
        self.entries.push(ImportEntry {
            scope: ImportScope::Machine(MachineScope {
                source: MachineSource::Export,
                label: kind.as_str().into(),
            }),
            file: display.into(),
            line: entry.record,
            profile: None,
            name,
            value: WireSecret::new(entry.value),
        });
    }
}
pub(super) fn run(kind: Kind, path: &Path, options: &ImportArgs) -> Result<ExitCode, Failure> {
    envcloak_client::fail::refuse_if_traced()?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| Failure::new("io", "the working directory is unavailable"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| Failure::new("invalid_path", "name an export file"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| Failure::new("invalid_path", "name an export file"))?;
    let root = open_root(parent)
        .map_err(|_| Failure::new("scan_root", "the export directory could not be opened"))?;
    let display = display_path(&absolute);
    let claims = claims();
    let mut collector = Collector::new(&claims)?;
    let report = formats::parse_file(kind, &root, Path::new(name), &mut |entry| {
        collector.push(entry, kind, &display);
    })
    .map_err(format_failure)?;
    if collector.rejected {
        return Err(Failure::new(
            "import_too_large",
            "the adapted export budget was reached",
        ));
    }
    let manual = collector.manual;
    let mut bundle = ImportCommitParams {
        import: ImportParams {
            projects: Vec::new(),
            entries: collector.entries,
            claims,
        },
        digest: "0".repeat(64),
    };
    // Both full envelopes must fit before either request is sent. A commit
    // adds nesting and a digest to the plan's complete payload.
    preflight(&bundle)?;
    let mut plan = ImportPlanView {
        digest: String::new(),
        entries: Vec::new(),
        items: Vec::new(),
    };
    let mut committed = false;
    if !bundle.import.entries.is_empty() {
        let mut client = connect()?;
        require_unlocked(&mut client)?;
        plan = client.import_plan(&bundle.import).map_err(too_large)?;
        drop(client);
        pause_point("export_planned");
        if options.yes && plan.entries.iter().any(|e| e.item.is_some()) {
            bundle.digest = plan.digest.clone();
            plan = connect()?.import_commit(&bundle).map_err(too_large)?;
            committed = true;
        }
    }
    let accepted = plan.entries.iter().filter(|e| e.item.is_some()).count();
    let mut skipped = BTreeMap::<&str, usize>::new();
    for entry in &plan.entries {
        if let Some(reason) = entry.skipped {
            *skipped.entry(reason.token()).or_default() += 1;
        }
    }
    let complete = report.unsupported == 0 && report.manual + manual == 0 && skipped.is_empty();
    let items: Vec<_> = plan
        .items
        .iter()
        .map(|item| {
            json!({
                "slug":if looks_like_value(&item.slug) {HIDDEN.into()} else {shown(&item.slug)},
                "existing":item.existing,"provider":item.provider,"owning_account":"unknown",
                "entries":item.entries,"scope":"machine"
            })
        })
        .collect();
    let output = json!({"schema":"export_import.v1","format":kind.as_str(),"source":"export",
        "display_path":display,"source_retained":true,"plaintext_reminder":"This export is plaintext. Delete the named file yourself after verifying the import.",
        "coverage":"supplied_file_supported_fields","provenance":"unknown","upstream_total":null,
        "parsing_complete":true,"complete":complete,"committed":committed,
        "records":report.records,"candidates":report.candidates,"unsupported":report.unsupported,
        "manual":report.manual+manual,"skipped":skipped,"accepted_entries":accepted,
        "imported_entries":if committed {accepted}else{0},"items":items,
        "duplicates_merged":accepted.saturating_sub(plan.items.len())});
    if options.json {
        println!("{}", json_text(&output));
    } else {
        println!(
            "{} {} entries from {} ({} unsupported, {} manual).",
            if committed {
                "Imported"
            } else {
                "Would import"
            },
            accepted,
            display,
            report.unsupported,
            report.manual + manual
        );
        for (reason, count) in skipped {
            println!("Kept {count}: {reason}");
        }
        println!(
            "This export is plaintext: {display}. Delete it yourself after verifying the import."
        );
        if !complete {
            println!("Import incomplete: some fields were not imported.");
        }
    }
    Ok(if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(FAILURE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adapted_metadata_and_claim_caps_poison_the_entire_batch() {
        let candidate = || formats::Entry {
            record: 1,
            name: SecretBytes::copy_from(b"PASSWORD"),
            value: SecretBytes::copy_from(b"positive"),
        };
        assert!(Collector::new(&vec![String::new(); 65]).is_err());
        let mut c = Collector::new(&vec![String::new(); 64]).unwrap();
        c.push(candidate(), Kind::DopplerJson, "file");
        assert_eq!(c.entries.len(), 1);
        let long = "雪\"".repeat(MAX_METADATA / 4);
        c.push(candidate(), Kind::DopplerJson, &long);
        c.push(candidate(), Kind::DopplerJson, "file");
        assert!(c.rejected && c.entries.is_empty());
        let mut c = Collector::new(&[]).unwrap();
        let display = "p".repeat(MAX_METADATA / 2);
        c.push(candidate(), Kind::DopplerJson, &display);
        assert_eq!(c.entries.len(), 1);
        c.push(candidate(), Kind::DopplerJson, &display);
        assert!(c.rejected && c.entries.is_empty());
    }
    #[test]
    fn both_envelopes_must_fit_before_the_plan() {
        // A plan can fit while the extra commit envelope does not. Binary
        // search uses the actual frame encoder, independently of preflight.
        let mut bundle = ImportCommitParams {
            import: ImportParams {
                projects: vec![],
                entries: vec![],
                claims: vec![String::new()],
            },
            digest: "0".repeat(64),
        };
        let (mut low, mut high) = (0, envcloak_ipc::MAX_FRAME);
        while low + 1 < high {
            let mid = (low + high) / 2;
            bundle.import.claims[0] = "x".repeat(mid);
            if request_frame::<ImportPlan>(u64::MAX, &bundle.import).is_ok() {
                low = mid;
            } else {
                high = mid;
            }
        }
        bundle.import.claims[0] = "x".repeat(low);
        assert!(request_frame::<ImportPlan>(u64::MAX, &bundle.import).is_ok());
        assert!(preflight(&bundle).is_err());
        bundle.import.claims[0].truncate(low - 256);
        assert!(preflight(&bundle).is_ok());
    }
}
