use crate::error::KrbError;
use tracing::trace;

pub fn load(path: &str) -> Result<(), KrbError> {
    trace!(?path, "Loading credential cache collection");
    Ok(())
}
