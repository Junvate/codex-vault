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
    crypto::vault_stream::{VaultReader, VaultWriter, map_read_error},
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

    for entry in archive.entries().map_err(map_read_error)? {
        let mut entry = entry.map_err(map_read_error)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }
        if !(entry_type.is_file() || entry_type.is_dir()) {
            continue;
        }
        if !entry.unpack_in(destination).map_err(map_read_error)? {
            return Err(VaultError::Integrity(
                "archive entry escaped the runtime directory",
            ));
        }
    }

    archive.into_inner().verify_finished()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    use tar::{EntryType, Header};

    use super::unseal_directory;
    use crate::{VaultError, crypto::vault_stream::VaultWriter};

    #[test]
    fn authenticated_archive_cannot_escape_destination() {
        let base = tempfile::tempdir().expect("temporary directory");
        let source = base.path().join("state.cvlt");
        let destination = base.path().join("destination");
        fs::create_dir(&destination).expect("create destination");
        let key = [13_u8; 32];
        let archive = traversal_archive();

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&source).expect("create encrypted state");
        let mut writer = VaultWriter::new(file, &key).expect("create writer");
        writer.write_all(&archive).expect("encrypt archive");
        writer.finish().expect("finish state");

        assert!(matches!(
            unseal_directory(&source, &destination, &key),
            Err(VaultError::Integrity(
                "archive entry escaped the runtime directory"
            ))
        ));
        assert!(!base.path().join("escaped.txt").exists());
    }

    fn traversal_archive() -> Vec<u8> {
        let payload = b"must not escape";
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o600);
        header.set_size(payload.len() as u64);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        let path = b"../escaped.txt";
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_cksum();

        let mut archive = Vec::new();
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(payload);
        let padding = 512 - payload.len();
        archive.resize(archive.len() + padding, 0);
        archive.resize(archive.len() + 1024, 0);
        archive
    }
}
