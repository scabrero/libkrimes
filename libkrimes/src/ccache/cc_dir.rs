use crate::error::KrbError;
use std::{fs::File, io::Read, path::PathBuf};
use tracing::{error, trace};
use walkdir::WalkDir;

pub fn dump(path: &str) -> Result<(), KrbError> {
    let path = path.strip_prefix("DIR:").unwrap_or(path);

    trace!(?path, "Loading credential cache collection");

    let path = PathBuf::from(path);
    if !path.is_dir() {
        error!(?path, "Not a directory");
        return Err(KrbError::CredentialCacheError);
    }

    let primary = path.join("primary");
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
            Some(path.join(buffer.trim()))
        }
        false => None,
    };
    match primary_name {
        Some(p) => println!("Primary credentials stored in {p:?}"),
        None => println!("No primary credentials"),
    };

    for entry in WalkDir::new(path)
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
            if let Err(e) = super::cc_file::dump(path) {
                error!(?e, ?path, "Failed to dump");
            }
        } else {
            error!(?entry, "Failed to get path");
        }
        println!();
    }

    Ok(())
}
