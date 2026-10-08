//! Doppler secrets download --no-file --format json: string map only.
use super::*;
pub(super) fn parse(
    input: &mut stream::Input<impl Read>,
    batch: &mut Batch,
) -> Result<(), FormatError> {
    input.object(|name, input| {
        batch.record()?;
        batch.add(name, text(input.node()?)?)
    })
}
