//! Infisical CLI v0.43.139 SingleEnvironmentVariable JSON profile.
use super::*;
pub(super) fn parse(
    input: &mut stream::Input<impl Read>,
    batch: &mut Batch,
) -> Result<(), FormatError> {
    input.array(|node| {
        batch.record()?;
        let mut fields = object(node)?;
        let key = text(take(&mut fields, b"key").ok_or(FormatError::Shape)?)?;
        let value = text(take(&mut fields, b"value").ok_or(FormatError::Shape)?)?;
        for name in [
            b"workspace".as_slice(),
            b"type",
            b"_id",
            b"secretPath",
            b"comment",
            b"Etag",
        ] {
            text(take(&mut fields, name).ok_or(FormatError::Shape)?)?;
        }
        let flag = take(&mut fields, b"skipMultilineEncoding").ok_or(FormatError::Shape)?;
        if !scalar(&flag, b"true") && !scalar(&flag, b"false") {
            return Err(FormatError::Shape);
        }
        let tags = take(&mut fields, b"tags").ok_or(FormatError::Shape)?;
        if !scalar(&tags, b"null") {
            let Node::Array(tags) = tags else {
                return Err(FormatError::Shape);
            };
            for tag in tags {
                let mut tag = object(tag)?;
                for name in [b"id".as_slice(), b"name", b"slug", b"color"] {
                    text(take(&mut tag, name).ok_or(FormatError::Shape)?)?;
                }
                if !tag.is_empty() {
                    return Err(FormatError::Shape);
                }
            }
        }
        if !fields.is_empty() {
            return Err(FormatError::Shape);
        }
        batch.add(key, value)
    })
}
