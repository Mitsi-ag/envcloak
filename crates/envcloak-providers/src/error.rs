//! Registry loading errors. Every message is fixed text: a kind, the file
//! and a line, never the text that caused it. Registry files hold no
//! secrets, but the TOML and regex libraries' own messages quote their
//! input, and a value pasted into a provider file by mistake must not be
//! echoed.

/// What is wrong with a registry file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryErrorKind {
    /// Larger than 64 KiB.
    TooLarge,
    NotUtf8,
    /// Not TOML.
    Syntax,
    /// TOML defines a key twice.
    DuplicateKey,
    UnknownKey,
    MissingKey,
    WrongType,
    /// A list longer than the loader accepts.
    TooManyEntries,
    /// `id` is not 1 to 32 lowercase letters, digits and `-`, starting with
    /// a letter or digit.
    InvalidId,
    /// `id` differs from the file name without `.toml`.
    IdNotFileName,
    /// Two files give the same id.
    DuplicateId,
    InvalidName,
    /// Not a regular expression, or longer than 256 bytes.
    InvalidPattern,
    /// A key pattern that is not anchored at both ends (`^...$`), or a live
    /// or test pattern that is not anchored at the start.
    PatternNotAnchored,
    /// A capturing group: patterns keep no captures; use `(?:...)`.
    PatternHasCaptures,
    /// A key pattern that matches values shorter than 16 bytes.
    PatternTooShort,
    NoKeyPatterns,
    /// Not an uppercase environment variable name.
    InvalidEnvHint,
    /// Not a lowercase DNS name of two or more labels, or `*.` and one.
    InvalidHost,
    DuplicateHost,
    /// A wildcard over a whole top-level domain, such as `*.com`.
    WildcardTooBroad,
    /// A wildcard under a multi-tenant suffix, such as `*.vercel.app`.
    WildcardUnderMultiTenantSuffix,
    /// A URL that does not start with `https://`.
    NotHttps,
    InvalidUrl,
    /// A request URL whose host no allowed host matches.
    RequestHostNotAllowed,
    InvalidAuthSlot,
    DuplicateAuthSlot,
    /// A request puts the key in a slot the provider does not declare.
    AuthSlotNotDeclared,
    InvalidDeniedPath,
    /// A request method other than `GET`.
    InvalidMethod,
    InvalidJsonPath,
    /// A line of the multi-tenant suffix list that is not a lowercase DNS
    /// name of two or more labels.
    InvalidSuffix,
    /// A registry file is missing: the suffix list, or every provider.
    MissingFile,
    /// A file name other than `<id>.toml` or the suffix list.
    UnknownFile,
}

impl RegistryErrorKind {
    fn message(self) -> &'static str {
        use RegistryErrorKind as K;
        match self {
            K::TooLarge => "the file is larger than 64 KiB",
            K::NotUtf8 => "the file is not UTF-8",
            K::Syntax => "not valid TOML",
            K::DuplicateKey => "a key is defined twice",
            K::UnknownKey => "unknown key",
            K::MissingKey => "a required key is missing (id, name, key_patterns, allowed_hosts)",
            K::WrongType => "a value has the wrong type",
            K::TooManyEntries => "too many entries in a list (at most 64)",
            K::InvalidId => {
                "invalid id: 1 to 32 lowercase letters, digits and -, starting with a letter or \
                 digit"
            }
            K::IdNotFileName => "id must equal the file name without .toml",
            K::DuplicateId => "two files give the same id",
            K::InvalidName => {
                "invalid name: 1 to 64 bytes, without control or invisible characters"
            }
            K::InvalidPattern => "not a valid pattern of at most 256 printable ASCII bytes",
            K::PatternNotAnchored => {
                "key patterns must be anchored as ^...$, live and test patterns as ^..."
            }
            K::PatternHasCaptures => "patterns keep no captures: use (?:...) for groups",
            K::PatternTooShort => "a key pattern must not match values shorter than 16 bytes",
            K::NoKeyPatterns => "key_patterns is empty",
            K::InvalidEnvHint => "an env hint is not an uppercase variable name",
            K::InvalidHost => {
                "invalid host: a lowercase DNS name of two or more labels, or *. and one, with \
                 no port, IP address or trailing dot"
            }
            K::DuplicateHost => "a host is listed twice",
            K::WildcardTooBroad => "a wildcard host covers a whole top-level domain",
            K::WildcardUnderMultiTenantSuffix => {
                "a wildcard host under a multi-tenant suffix is refused; store tenant hosts on \
                 the item"
            }
            K::NotHttps => "URLs must start with https://",
            K::InvalidUrl => {
                "invalid URL: https:// and an allowed-form host, with no user name, port, \
                 spaces or backslashes (and no fragment in a request)"
            }
            K::RequestHostNotAllowed => "a request URL's host is not in allowed_hosts",
            K::InvalidAuthSlot => {
                "invalid auth slot: { header = \"<name>\", scheme = \"<scheme>\" }, { basic = \
                 \"user\" | \"password\" } or { query = \"<name>\" }"
            }
            K::DuplicateAuthSlot => "an auth slot is listed twice",
            K::AuthSlotNotDeclared => "a request's auth names no slot in auth",
            K::InvalidDeniedPath => {
                "invalid denied path: /, then segments of letters, digits and ._~- or a whole * \
                 segment, with no . or .. segment"
            }
            K::InvalidMethod => "a request method must be GET",
            K::InvalidJsonPath => "invalid JSON path: $ then .name or [index] segments",
            K::InvalidSuffix => "not a lowercase DNS name of two or more labels",
            K::MissingFile => "a registry file is missing",
            K::UnknownFile => "not a registry file name",
        }
    }
}

/// A registry file that failed to load: the kind, the file and, where the
/// parser recorded it, the line. Never the text that caused it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryError {
    kind: RegistryErrorKind,
    file: String,
    line: Option<u32>,
}

impl RegistryError {
    pub(crate) fn new(kind: RegistryErrorKind, file: &str, line: Option<u32>) -> Self {
        RegistryError {
            kind,
            file: file.to_owned(),
            line,
        }
    }

    pub fn kind(&self) -> RegistryErrorKind {
        self.kind
    }

    /// The file's name in `providers/`.
    pub fn file(&self) -> &str {
        &self.file
    }

    /// The line, from 1.
    pub fn line(&self) -> Option<u32> {
        self.line
    }
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "providers/{}", self.file)?;
        if let Some(line) = self.line {
            write!(f, " line {line}")?;
        }
        write!(f, ": {}", self.kind.message())
    }
}

impl std::error::Error for RegistryError {}
