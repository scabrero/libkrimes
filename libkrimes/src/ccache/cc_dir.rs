use super::CredentialCache;
use crate::error::KrbError;
use crate::proto::{EncTicket, KdcReplyPart, Name};
use std::time::Duration;
use std::{fs::File, io::Read, path::PathBuf};
use tracing::{error, trace};
use walkdir::WalkDir;

pub(super) struct DirCredentialCacheContext {
    path: PathBuf,
}

impl CredentialCache for DirCredentialCacheContext {
    fn init(&mut self, _name: &Name, _clock_skew: Option<Duration>) -> Result<(), KrbError> {
        if !self.path.is_dir() {
            error!(?self.path, "Not a directory");
            return Err(KrbError::IoError);
        }
        Err(KrbError::UnsupportedCredentialCacheType)
    }

    fn destroy(&mut self) -> Result<(), KrbError> {
        Err(KrbError::UnsupportedCredentialCacheType)
    }

    fn store(
        &mut self,
        _name: &Name,
        _ticket: &EncTicket,
        _kdc_reply: &KdcReplyPart,
    ) -> Result<(), KrbError> {
        Err(KrbError::UnsupportedCredentialCacheType)
    }

    #[cfg(debug_assertions)]
    fn dump(&self) -> Result<(), KrbError> {
        trace!(?self.path, "Loading credential cache collection");

        if !self.path.is_dir() {
            error!(?self.path, "Not a directory");
            return Err(KrbError::IoError);
        }

        let primary = self.path.join("primary");
        let primary_name = match primary.exists() {
            true => {
                let mut f = File::open(&primary).map_err(|e| {
                    error!(?primary, ?e, "Failed to open file");
                    KrbError::IoError
                })?;
                let mut buffer = String::new();
                f.read_to_string(&mut buffer).map_err(|e| {
                    error!(?primary, ?e, "Filed to read file");
                    KrbError::IoError
                })?;
                Some(self.path.join(buffer.trim()))
            }
            false => None,
        };
        match primary_name {
            Some(p) => println!("Primary credentials stored in {p:?}"),
            None => println!("No primary credentials"),
        };

        for entry in WalkDir::new(&self.path)
            .into_iter()
            .filter_map(|e| {
                if e.is_err() {
                    error!(?e, "Failed to read directory entry");
                }
                e.ok()
            })
            .filter_map(|e| {
                let meta = e.metadata();
                match meta {
                    Err(e) => {
                        error!(?e, "Failed to read directory entry metadata");
                        None
                    }
                    Ok(m) => {
                        if m.is_file() {
                            Some(e)
                        } else {
                            None
                        }
                    }
                }
            })
            .filter(|e| e.file_name() != "primary")
        {
            if let Some(path) = entry.path().to_str() {
                println!("{path}:");
                let ccname = format!("FILE:{path}");
                let fcc = super::resolve(Some(&ccname))?;
                if let Err(e) = fcc.dump() {
                    error!(?e, ?ccname, "Failed to dump");
                }
            } else {
                error!(?entry, "Failed to get path");
            }
            println!();
        }

        Ok(())
    }
}

pub(super) fn resolve(ccache_name: &str) -> Result<Box<dyn CredentialCache>, KrbError> {
    trace!(?ccache_name, "Resolving credential cache");
    let path = ccache_name.strip_prefix("DIR:").unwrap_or(ccache_name);
    trace!(?path, "Resolving credential cache");

    let path = PathBuf::from(&path);

    let dcc = DirCredentialCacheContext { path };
    Ok(Box::new(dcc))
}
