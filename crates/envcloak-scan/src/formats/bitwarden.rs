//! Plaintext Password Manager exports; history is never a fallback.
use super::*;
pub(super) fn parse(
    input: &mut stream::Input<impl Read>,
    batch: &mut Batch,
) -> Result<(), FormatError> {
    let mut items = false;
    input.object(|name, input| {
        if name.ct_eq(b"items") {
            items = true;
            input.array(|node| item(node, batch))
        } else if name.ct_eq(b"encrypted") {
            if scalar(&input.node()?, b"false") {
                Ok(())
            } else {
                Err(FormatError::Shape)
            }
        } else if name.ct_eq(b"folders") || name.ct_eq(b"collections") {
            input.array(|n| object(n).map(|_| ()))
        } else {
            Err(FormatError::Shape)
        }
    })?;
    if !items {
        return Err(FormatError::Shape);
    }
    Ok(())
}
fn item(node: Node, batch: &mut Batch) -> Result<(), FormatError> {
    batch.record()?;
    let mut fields = object(node)?;
    let kind = take(&mut fields, b"type").ok_or(FormatError::Shape)?;
    let Node::Scalar(tag) = &kind else {
        return Err(FormatError::Shape);
    };
    if !integer(tag) {
        return Err(FormatError::Shape);
    }
    text(take(&mut fields, b"name").ok_or(FormatError::Shape)?)?;
    let known = [b"1", b"2", b"3", b"4"].iter().any(|v| tag.ct_eq(*v));
    let login = take(&mut fields, b"login");
    if scalar(&kind, b"1") {
        for name in [b"secureNote".as_slice(), b"card", b"identity", b"sshKey"] {
            if take(&mut fields, name).is_some_and(|n| !scalar(&n, b"null")) {
                return Err(FormatError::Shape);
            }
        }
        let mut login = object(login.ok_or(FormatError::Shape)?)?;
        if let Some(value) = optional_text(take(&mut login, b"password"))? {
            batch.add(SecretBytes::copy_from(b"PASSWORD"), value)?;
        } else {
            batch.report.manual += 1;
        }
        if optional_text(take(&mut login, b"totp"))?.is_some_and(|v| !v.is_empty()) {
            batch.report.unsupported += 1;
        }
        if take(&mut login, b"fido2Credentials").is_some_and(|v| {
            !matches!(v,Node::Array(ref a) if a.is_empty()) && !scalar(&v, b"null")
        }) {
            batch.report.unsupported += 1;
        }
    } else {
        if login.is_some_and(|n| !scalar(&n, b"null")) {
            return Err(FormatError::Shape);
        }
        batch.report.unsupported += 1;
    }
    if let Some(custom) = take(&mut fields, b"fields") {
        if scalar(&custom, b"null") {
            return Ok(());
        }
        let Node::Array(custom) = custom else {
            return Err(FormatError::Shape);
        };
        for field in custom {
            let mut field = object(field)?;
            let kind = take(&mut field, b"type").ok_or(FormatError::Shape)?;
            let Node::Scalar(tag) = &kind else {
                return Err(FormatError::Shape);
            };
            if !integer(tag) {
                return Err(FormatError::Shape);
            }
            let name = optional_text(take(&mut field, b"name"))?;
            let value = optional_text(take(&mut field, b"value"))?;
            if known && (scalar(&kind, b"0") || scalar(&kind, b"1")) {
                match (name, value) {
                    (Some(name), Some(value)) => batch.add(name, value)?,
                    _ => batch.report.manual += 1,
                }
            } else {
                batch.report.unsupported += 1;
            }
        }
    }
    Ok(())
}
#[allow(clippy::disallowed_methods)] // Type tags decide selection, never authority.
fn integer(value: &SecretBytes) -> bool {
    let b = secrecy::ExposeSecret::expose_secret(value);
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}
