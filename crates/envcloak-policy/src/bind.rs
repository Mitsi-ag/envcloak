//! Binding resolved references to the vault's items: the step that turns
//! `(variable, slug, field)` into `(variable, item id, field id)`, which is
//! what grants compare (SPEC §10b "Match" rule 6), and that refuses a
//! reference to anything but a secret (SPEC §5: a reference to a card or
//! an issuer credential fails; gate 17).

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{Classification, FieldId, ItemId, ItemMeta};

use crate::names::{Binding, EnvName};

/// A binding tied to one field of one secret item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundBinding {
    pub env_name: EnvName,
    pub item: ItemId,
    pub field: FieldId,
    /// The item's classification, for the live-key guard (SPEC §10b, M2).
    pub classification: Classification,
}

/// Why a binding could not be bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BindErrorKind {
    /// No item has the slug.
    UnknownItem,
    /// The item has no field of that name.
    UnknownField,
    /// No field was named and the item has more than one.
    AmbiguousField,
    /// No field was named and the item has none.
    NoField,
    /// The item is a card (SPEC §2a-bis): never resolvable for a run.
    CardReference,
    /// The item is an issuer credential: used only by the card module.
    IssuerCredentialReference,
    /// The item's class is not one this version resolves.
    UnknownItemClass,
}

impl BindErrorKind {
    /// The stable token, for the daemon's error reasons.
    pub fn token(self) -> &'static str {
        use BindErrorKind as K;
        match self {
            K::UnknownItem => "unknown_item",
            K::UnknownField => "unknown_field",
            K::AmbiguousField => "ambiguous_field",
            K::NoField => "no_field",
            K::CardReference => "card_reference",
            K::IssuerCredentialReference => "issuer_credential_reference",
            K::UnknownItemClass => "unknown_item_class",
        }
    }

    fn message(self) -> &'static str {
        use BindErrorKind as K;
        match self {
            K::UnknownItem => "no item has that slug",
            K::UnknownField => "the item has no field of that name",
            K::AmbiguousField => "the item has several fields: name one with <slug>#<field>",
            K::NoField => "the item has no fields",
            K::CardReference => "the reference names a card, which is never bound to a variable",
            K::IssuerCredentialReference => {
                "the reference names an issuer credential, which is never bound to a variable"
            }
            K::UnknownItemClass => "the reference names an item of a class that cannot be bound",
        }
    }
}

/// A binding that could not be bound: the variable and the kind. The
/// reference and the item are not repeated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindError {
    env_name: EnvName,
    kind: BindErrorKind,
}

impl BindError {
    pub fn kind(&self) -> BindErrorKind {
        self.kind
    }

    pub fn env_name(&self) -> &EnvName {
        &self.env_name
    }

    /// The stable token `envcloak run` prints (SPEC §6.1 step 9). A
    /// reference to an item of the wrong class makes the manifest invalid
    /// (SPEC §5); anything else leaves the binding unresolved.
    pub fn token(&self) -> &'static str {
        match self.kind {
            BindErrorKind::CardReference
            | BindErrorKind::IssuerCredentialReference
            | BindErrorKind::UnknownItemClass => "manifest_invalid",
            _ => "binding_unresolved",
        }
    }
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.env_name, self.kind.message())
    }
}

impl std::error::Error for BindError {}

/// Binds each binding to a field of a secret item in `items` (the vault's
/// metadata, `Vault::items`), in order. A reference without a field names
/// the item's only field. The first binding that cannot be bound fails the
/// whole set.
pub fn bind_items(
    bindings: &[Binding],
    items: &[ItemMeta],
) -> Result<Vec<BoundBinding>, BindError> {
    bindings.iter().map(|b| bind_one(b, items)).collect()
}

fn bind_one(b: &Binding, items: &[ItemMeta]) -> Result<BoundBinding, BindError> {
    let fail = |kind| BindError {
        env_name: b.env_name.clone(),
        kind,
    };
    let item = items
        .iter()
        .find(|m| m.slug == b.reference.slug)
        .ok_or_else(|| fail(BindErrorKind::UnknownItem))?;
    match item.class {
        ItemClass::Secret => {}
        ItemClass::Card => return Err(fail(BindErrorKind::CardReference)),
        ItemClass::IssuerCredential => return Err(fail(BindErrorKind::IssuerCredentialReference)),
        ItemClass::None => return Err(fail(BindErrorKind::UnknownItemClass)),
    }
    let field = match &b.reference.field {
        Some(name) => item
            .fields
            .iter()
            .find(|f| &f.name == name)
            .ok_or_else(|| fail(BindErrorKind::UnknownField))?,
        None => match item.fields.as_slice() {
            [only] => only,
            [] => return Err(fail(BindErrorKind::NoField)),
            _ => return Err(fail(BindErrorKind::AmbiguousField)),
        },
    };
    Ok(BoundBinding {
        env_name: b.env_name.clone(),
        item: item.id,
        field: field.id,
        classification: item.details.classification,
    })
}
