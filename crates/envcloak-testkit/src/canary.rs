//! Runtime-generated fixture secrets.

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

/// Labels of the canaries [`canaries`] returns, in order.
pub mod labels {
    /// 64 bytes with an OpenAI project-key prefix.
    pub const OPENAI_API_KEY: &str = "OPENAI_API_KEY";
    /// Same shape as [`OPENAI_API_KEY`]: the value rotated in (story S7).
    pub const OPENAI_API_KEY_ROTATED: &str = "OPENAI_API_KEY_ROTATED";
    /// A Stripe test secret key shape.
    pub const STRIPE_SECRET_KEY: &str = "STRIPE_SECRET_KEY";
    /// A GitHub classic token shape.
    pub const GITHUB_TOKEN: &str = "GITHUB_TOKEN";
    /// A Postgres URL whose password contains `/`, `"`, `+`, a space and a
    /// non-ASCII character.
    pub const DATABASE_URL: &str = "DATABASE_URL";
    /// 10 bytes: under the 16-byte comfort length, over the 8-byte floor.
    pub const SHORT_TOKEN: &str = "SHORT_TOKEN";
    /// A vault passphrase with spaces.
    pub const VAULT_PASSPHRASE: &str = "VAULT_PASSPHRASE";
}

/// A fixture secret. Its `Debug` shows the label only, and the value is
/// wiped when the canary is dropped.
#[derive(Clone)]
pub struct Canary {
    /// Names the canary in reports and failure messages. Not secret.
    pub label: String,
    value: Zeroizing<String>,
}

impl Canary {
    /// A canary with a caller-chosen value, for fixtures [`canaries`] does
    /// not cover. Generate the value at test time.
    pub fn new(label: impl Into<String>, value: String) -> Self {
        Canary {
            label: label.into(),
            value: Zeroizing::new(value),
        }
    }

    /// The value, for injecting into the code under test.
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// The value as text; every canary is UTF-8.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for Canary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Canary")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// A seed that differs between runs and processes. Seeds are not secret:
/// printing one lets a failure be replayed with [`canaries`].
pub fn fresh_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    RandomState::new().hash_one((
        nanos,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// The fixture canaries for `seed`, labeled with [`labels`]. The same seed
/// always gives the same values; different seeds give unrelated ones.
pub fn canaries(seed: u64) -> Vec<Canary> {
    let mut rng = SplitMix64(seed ^ 0x656e_7663_6c6f_616b);
    // Prefixes are split so no key-shaped literal appears in the source.
    let openai = concat!("sk", "-proj-");
    let stripe = concat!("sk", "_test_");
    let github = concat!("gh", "p_");
    let openai_key = |rng: &mut SplitMix64| format!("{openai}{}", rng.string(KEY_CHARS, 56));
    let a = openai_key(&mut rng);
    let b = openai_key(&mut rng);
    let password = format!(
        "{}/{}\"{}+{} {}\u{e9}{}",
        rng.string(ALNUM, 5),
        rng.string(ALNUM, 4),
        rng.string(ALNUM, 4),
        rng.string(ALNUM, 3),
        rng.string(ALNUM, 3),
        rng.string(ALNUM, 4),
    );
    let words: Vec<String> = (0..4).map(|_| rng.string(LOWER, 6)).collect();
    vec![
        Canary::new(labels::OPENAI_API_KEY, a),
        Canary::new(labels::OPENAI_API_KEY_ROTATED, b),
        Canary::new(
            labels::STRIPE_SECRET_KEY,
            format!("{stripe}{}", rng.string(ALNUM, 32)),
        ),
        Canary::new(
            labels::GITHUB_TOKEN,
            format!("{github}{}", rng.string(ALNUM, 36)),
        ),
        Canary::new(
            labels::DATABASE_URL,
            format!("postgres://acme:{password}@db.acme.internal:5432/acme"),
        ),
        Canary::new(labels::SHORT_TOKEN, rng.string(ALNUM, 10)),
        Canary::new(labels::VAULT_PASSPHRASE, words.join(" ")),
    ]
}

/// The canary labeled `label`.
///
/// # Panics
/// When no canary has that label.
pub fn by_label<'a>(cs: &'a [Canary], label: &str) -> &'a Canary {
    match cs.iter().find(|c| c.label == label) {
        Some(c) => c,
        None => panic!("no canary labeled {label}"),
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// SplitMix64: small, deterministic, good enough for fixture values.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| {
                let i = (self.next() % alphabet.len() as u64) as usize;
                char::from(alphabet[i])
            })
            .collect()
    }
}
