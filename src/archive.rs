use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use tar::Archive;
use uuid::Uuid;

use crate::{
    config::validate_private_file,
    crypto::vault_stream::{VaultReader, VaultWriter},
    error::{Result, VaultError},
};

pub fn seal_directory(directory: &Path, destination: &Path, data_key: &[u8; 32]) -> Result<()> {
    let temporary = destination.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&temporary)?;
        let writer = VaultWriter::new(file, data_key)?;
        let mut archive = tar::Builder::new(writer);
        archive.follow_symlinks(false);
        archive.append_dir_all(".", directory)?;
        let writer = archive.into_inner()?;
        let mut file = writer.finish()?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, destination)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn unseal_directory(source: &Path, destination: &Path, data_key: &[u8; 32]) -> Result<()> {
    validate_private_file(source).map_err(|_| VaultError::Integrity("unsafe vault state file"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(source)?;
    let reader = VaultReader::new(file, data_key)?;
    let mut archive = Archive::new(reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }
        if !(entry_type.is_file() || entry_type.is_dir()) {
            continue;
        }
        if !entry.unpack_in(destination)? {
            return Err(VaultError::Integrity(
                "archive entry escaped the runtime directory",
            ));
        }
    }

    archive.into_inner().verify_finished()?;
    Ok(())
}
