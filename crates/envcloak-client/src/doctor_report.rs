//! Doctor's metadata-only report. No input bytes, ranges or object ids belong here.
use crate::render::{HIDDEN, json_text, looks_like_value, registry, shown};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct DoctorReport {
    items: Vec<Item>,
    unknown: Vec<Unknown>,
    not_scanned: Vec<NotScanned>,
    incomplete: Option<&'static str>,
}
#[derive(Debug, Serialize)]
struct Place {
    display_path: String,
    count: u64,
}
#[derive(Debug, Serialize)]
struct Item {
    slug: String,
    places: Vec<Place>,
    rotate_url: Option<String>,
}
#[derive(Debug, Serialize)]
struct Unknown {
    provider: String,
    places: Vec<Place>,
}
#[derive(Debug, Serialize)]
struct NotScanned {
    display_path: String,
    reason: &'static str,
}

fn name(s: &str) -> String {
    if looks_like_value(s) {
        HIDDEN.into()
    } else {
        shown(s)
    }
}
/// Mask each component before escaping controls, including non-UTF-8 names.
pub fn display_path(path: &Path) -> String {
    let Some(text) = path.to_str() else {
        return HIDDEN.into();
    };
    text.split('/').map(name).collect::<Vec<_>>().join("/")
}
fn place(places: &mut Vec<Place>, path: &Path, count: u64) {
    let path = display_path(path);
    if let Some(p) = places.iter_mut().find(|p| p.display_path == path) {
        p.count = p.count.saturating_add(count);
    } else {
        places.push(Place {
            display_path: path,
            count,
        });
    }
    places.sort_by(|a, b| a.display_path.cmp(&b.display_path));
}
impl DoctorReport {
    pub fn complete(&self) -> bool {
        self.incomplete.is_none()
    }
    pub fn fail(&mut self, reason: &'static str) {
        self.incomplete.get_or_insert(reason);
    }
    pub fn note(&mut self, path: &Path, reason: &'static str, incomplete: bool) {
        let path = display_path(path);
        if !self
            .not_scanned
            .iter()
            .any(|n| n.display_path == path && n.reason == reason)
        {
            self.not_scanned.push(NotScanned {
                display_path: path,
                reason,
            });
            self.not_scanned
                .sort_by(|a, b| (&a.display_path, a.reason).cmp(&(&b.display_path, b.reason)));
        }
        if incomplete {
            self.fail(reason);
        }
    }
    pub fn item(&mut self, slug: &str, provider: Option<&str>, path: &Path, count: u64) {
        let slug = name(slug);
        let index = self
            .items
            .iter()
            .position(|i| i.slug == slug)
            .unwrap_or_else(|| {
                // Only the embedded registry supplies URLs, never an item's mutable links.
                let rotate_url = provider.and_then(|p| registry()?.get(p)?.links.keys_page.clone());
                self.items.push(Item {
                    slug,
                    places: Vec::new(),
                    rotate_url,
                });
                self.items.len() - 1
            });
        place(&mut self.items[index].places, path, count);
        self.items.sort_by(|a, b| a.slug.cmp(&b.slug));
    }
    pub fn unknown(&mut self, provider: &str, path: &Path, count: u64) {
        let provider = name(provider);
        let index = self
            .unknown
            .iter()
            .position(|i| i.provider == provider)
            .unwrap_or_else(|| {
                self.unknown.push(Unknown {
                    provider,
                    places: Vec::new(),
                });
                self.unknown.len() - 1
            });
        place(&mut self.unknown[index].places, path, count);
        self.unknown.sort_by(|a, b| a.provider.cmp(&b.provider));
    }
    pub fn json(&self) -> String {
        json_text(self)
    }
    pub fn human(&self) -> String {
        let mut text = String::new();
        for item in &self.items {
            let _ = writeln!(text, "item {}", item.slug);
            for p in &item.places {
                let _ = writeln!(text, "  path {} count {}", p.display_path, p.count);
            }
            if let Some(url) = &item.rotate_url {
                let _ = writeln!(text, "rotate {url}");
            } else {
                let _ = writeln!(text, "rotate at provider key page");
            }
        }
        for item in &self.unknown {
            let _ = writeln!(text, "unknown {}", item.provider);
            for p in &item.places {
                let _ = writeln!(text, "  path {} count {}", p.display_path, p.count);
            }
        }
        // Rotation precedes scrub, including a pattern-only finding.
        let urls: BTreeMap<_, _> = self
            .unknown
            .iter()
            .filter_map(|u| {
                Some((
                    u.provider.as_str(),
                    registry()?.get(&u.provider)?.links.keys_page.as_deref()?,
                ))
            })
            .collect();
        for url in urls.values() {
            let _ = writeln!(text, "rotate {url}");
        }
        if !self.items.is_empty() || !self.unknown.is_empty() {
            text.push_str("envcloak scrub: encrypted backup before rewriting\n");
        }
        for n in &self.not_scanned {
            let _ = writeln!(text, "not_scanned {} {}", n.display_path, n.reason);
        }
        if let Some(reason) = self.incomplete {
            let _ = writeln!(text, "doctor: incomplete ({reason})");
        } else {
            text.push_str("doctor: complete\n");
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_masks_hostile_metadata_and_keeps_only_the_schema() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let v = std::str::from_utf8(
            envcloak_testkit::by_label(&cs, envcloak_testkit::labels::OPENAI_API_KEY).value(),
        )
        .expect("fixture");
        let mut r = DoctorReport::default();
        r.item(v, Some("openai"), &Path::new("/tmp").join(v), 2);
        r.note(Path::new("/tmp/\u{202e}\n"), "unreadable", true);
        for s in [r.human(), r.json(), format!("{r:?}")] {
            envcloak_testkit::assert_no_canary(s.as_bytes(), &cs);
            assert!(!s.contains('\u{202e}'));
        }
        let j: serde_json::Value = serde_json::from_str(&r.json()).expect("json");
        assert_eq!(j["items"][0]["places"][0]["count"], 2);
        assert_eq!(j["items"][0].as_object().expect("item").len(), 3);
        assert_eq!(
            j["items"][0]["places"][0].as_object().expect("place").len(),
            2
        );
        assert!(!r.complete());
    }
}
