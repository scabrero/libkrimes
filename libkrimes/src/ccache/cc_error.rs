#[derive(Debug)]
pub enum CredentialCacheError {
    BadName,
    BadFormat,
    IoError,
    NotImplemented,
}
