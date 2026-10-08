//! Documented nine-column Login/Password CSV; quotes double, bytes stay exact.
use super::*;
const HEADER: [&[u8]; 9] = [
    b"Title",
    b"Url",
    b"Username",
    b"Password",
    b"OTPAuth",
    b"Favorite",
    b"Archived",
    b"Tags",
    b"Notes",
];
pub(super) fn parse(
    input: &mut stream::Input<impl Read>,
    batch: &mut Batch,
) -> Result<(), FormatError> {
    if input.peek()? == Some(0xef) {
        for b in [0xef, 0xbb, 0xbf] {
            if input.next()? != Some(b) {
                return Err(FormatError::Invalid);
            }
        }
    }
    let header = row(input)?.ok_or(FormatError::Shape)?;
    if header.len() != HEADER.len() || !header.iter().zip(HEADER).all(|(v, w)| v.ct_eq(w)) {
        return Err(FormatError::Shape);
    }
    while let Some(mut fields) = row(input)? {
        batch.record()?;
        if fields.len() != 9 {
            return Err(FormatError::Shape);
        }
        if !fields[4].is_empty() {
            batch.report.unsupported += 1;
        }
        let value = fields.remove(3);
        batch.add(SecretBytes::copy_from(b"PASSWORD"), value)?;
    }
    Ok(())
}
fn row(input: &mut stream::Input<impl Read>) -> Result<Option<Vec<SecretBytes>>, FormatError> {
    if input.peek()?.is_none() {
        return Ok(None);
    }
    let mut fields = Vec::new();
    let mut total = 0;
    loop {
        let mut value = SecretBuf::with_capacity(128);
        let quoted = input.peek()? == Some(b'"');
        if quoted {
            input.next()?;
            loop {
                let b = input.next()?.ok_or(FormatError::Invalid)?;
                if b == b'"' {
                    if input.peek()? == Some(b'"') {
                        input.next()?;
                    } else {
                        break;
                    }
                }
                stream::append(&mut value, &[b], MAX_FIELD)?;
            }
        } else {
            while let Some(b) = input.peek()? {
                if matches!(b, b',' | b'\r' | b'\n') {
                    break;
                }
                if b == b'"' {
                    return Err(FormatError::Invalid);
                }
                input.next()?;
                stream::append(&mut value, &[b], MAX_FIELD)?;
            }
        }
        let value = value.freeze();
        if value.utf8_chars().is_none() || value.contains_byte(0) {
            return Err(FormatError::Invalid);
        }
        total += value.len();
        if fields.len() == 9 || total > MAX_RECORD {
            return Err(FormatError::Limit);
        }
        fields.push(value);
        match input.next()? {
            None | Some(b'\n') => return Ok(Some(fields)),
            Some(b'\r') => {
                if input.next()? != Some(b'\n') {
                    return Err(FormatError::Invalid);
                }
                return Ok(Some(fields));
            }
            Some(b',') => {}
            _ => return Err(FormatError::Invalid),
        }
    }
}
