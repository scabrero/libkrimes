use super::CredentialCache;
use crate::ccache::cc_file::FileCredentialCacheContext;
use crate::ccache::{CredentialCacheCollection, ResolvedCredentialCache};
use crate::error::KrbError;
use std::fs::{DirBuilder, File, Permissions};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{error, trace};
use walkdir::WalkDir;

fn create_ccache_dir(ccache_dir: &PathBuf) -> Result<(), KrbError> {
    trace!(?ccache_dir, "Check collection path");
    match std::fs::exists(ccache_dir) {
        Ok(true) => match ccache_dir.is_dir() {
            false => {
                error!(?ccache_dir, "Not a directory");
                Err(KrbError::CredentialCacheError)
            }
            true => Ok(()),
        },
        Ok(false) => DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(ccache_dir)
            .map_err(|e| {
                error!(?e, ?ccache_dir, "Failed to create directory",);
                KrbError::IoError
            }),
        Err(e) => {
            error!(?e, "Failed to check if path exists");
            Err(KrbError::IoError)
        }
    }
}

fn store_primary_subsidiary_name(
    subsidiary_name: &str,
    collection_path: &Path,
) -> Result<(), KrbError> {
    let primary_path = collection_path.join("primary");
    let mut f = File::create(&primary_path).map_err(|e| {
        error!(?e, ?primary_path, "Failed to create primary file");
        KrbError::IoError
    })?;

    let perms = Permissions::from_mode(0o600);
    f.set_permissions(perms).map_err(|x| {
        error!(?x, ?primary_path, "Failed to set primary file permissions");
        KrbError::IoError
    })?;

    f.write_all(subsidiary_name.as_bytes()).map_err(|e| {
        error!(?e, ?subsidiary_name, "Failed to write primary file");
        KrbError::IoError
    })
}

pub(super) struct DirCredentialCacheCollection {
    collection_path: PathBuf,
    subsidiaries: Vec<Box<dyn CredentialCache>>,
    // TODO Drop subsidiaries
}

impl Deref for DirCredentialCacheCollection {
    type Target = Vec<Box<dyn CredentialCache>>;
    fn deref(&self) -> &Self::Target {
        &self.subsidiaries
    }
}

impl DerefMut for DirCredentialCacheCollection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.subsidiaries
    }
}

impl CredentialCacheCollection for DirCredentialCacheCollection {
    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let primary = self.collection_path.join("primary");
        match std::fs::exists(&primary) {
            Ok(true) => {
                let mut f = File::open(&primary).map_err(|e| {
                    error!(?primary, ?e, "Failed to open file");
                    KrbError::IoError
                })?;
                let mut buffer = String::new();
                f.read_to_string(&mut buffer).map_err(|e| {
                    error!(?primary, ?e, "Filed to read file");
                    KrbError::IoError
                })?;
                let primary_path = self.collection_path.join(buffer.trim());
                let fcc = FileCredentialCacheContext { path: primary_path };
                Ok(Box::new(fcc))
            }
            Ok(false) => {
                let primary_name = "tkt".to_string();
                store_primary_subsidiary_name(&primary_name, self.collection_path.as_path())?;
                let fcc = FileCredentialCacheContext {
                    path: self.collection_path.join(primary_name),
                };
                // TODO Append to self.subsidiaries?
                Ok(Box::new(fcc))
            }
            Err(e) => {
                error!(?e, ?primary, "Failed to read primary credentials");
                Err(KrbError::IoError)
            }
        }
    }

    fn switch(&mut self, ccache: Box<dyn CredentialCache>) -> Result<(), KrbError> {
        let primary_path = ccache.name()?;
        let primary_path = PathBuf::from(primary_path);
        let primary_name = primary_path
            .file_name()
            .ok_or(KrbError::CredentialCacheNotFound)?;
        store_primary_subsidiary_name(
            &primary_name.to_string_lossy(),
            self.collection_path.as_path(),
        )?;
        Ok(())
    }
}

pub(super) fn resolve(ccache_name: &str) -> Result<ResolvedCredentialCache, KrbError> {
    trace!(?ccache_name, "Resolving dir credential cache");

    let ccache_name = ccache_name
        .strip_prefix("DIR:")
        .ok_or(KrbError::UnsupportedCredentialCacheType)?;

    let resolved = if ccache_name.starts_with(":") {
        trace!(?ccache_name, "Collection with subsidiary");
        let ccache_name = ccache_name
            .strip_prefix(":")
            .ok_or(KrbError::CredentialCacheError)?;
        let path = PathBuf::from(ccache_name);

        let collection_path = match path.parent() {
            Some(p) => Ok(PathBuf::from(p)),
            None => Err(KrbError::CredentialCacheError),
        }?;
        create_ccache_dir(&collection_path)?;

        let fcc = FileCredentialCacheContext { path };
        let fcc = Box::new(fcc);
        ResolvedCredentialCache::Subsidiary(fcc)
    } else {
        trace!(?ccache_name, "Collection without subsidiary");
        let collection_path = PathBuf::from(ccache_name);

        create_ccache_dir(&collection_path)?;

        let mut cccol = DirCredentialCacheCollection {
            collection_path,
            subsidiaries: vec![],
        };

        for entry in WalkDir::new(&cccol.collection_path)
            .into_iter()
            .filter_map(|dir_ent| {
                dir_ent
                    .map_err(|err| {
                        error!(?err, "Failed to read directory entry");
                        KrbError::IoError
                    })
                    .and_then(|dir_ent| {
                        dir_ent
                            .metadata()
                            .map_err(|err| {
                                error!(?err, "Failed to read directory entry metadata");
                                KrbError::IoError
                            })
                            .map(|dir_ent_meta| (dir_ent, dir_ent_meta))
                    })
                    .ok()
            })
            .filter(|a| a.1.is_file() && a.0.file_name() != "primary")
        {
            let fcc = FileCredentialCacheContext {
                path: entry.0.into_path(),
            };
            cccol.subsidiaries.push(Box::new(fcc));
        }

        let ccol = Box::new(cccol);
        ResolvedCredentialCache::Collection(ccol)
    };

    Ok(resolved)
}
