use std::{
    env, fs,
    path::{Path, PathBuf},
};

use nix::unistd::geteuid;

use crate::error::{Result, VaultError};

pub const APP_NAME: &str = "codex-vault";

pub fn default_vault_root() -> Result<PathBuf> {
    if let Some(root) = env::var_os("CODEX_VAULT_HOME") {
        return Ok(PathBuf::from(root));
    }

    let home = env::var_os("HOME").ok_or_else(|| {
        VaultError::InvalidConfiguration("HOME and CODEX_VAULT_HOME are unset".into())
    })?;
    Ok(PathBuf::from(home).join(".codex-vault"))
}

pub fn select_runtime_root() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("CODEX_VAULT_RUNTIME_DIR") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(path).join(APP_NAME));
    }
    if cfg!(target_os = "linux") {
        candidates.push(PathBuf::from(format!(
            "/dev/shm/{APP_NAME}-{}",
            geteuid().as_raw()
        )));
    }
    candidates.push(env::temp_dir().join(format!("{APP_NAME}-{}", geteuid().as_raw())));

    for candidate in candidates {
        if ensure_private_directory(&candidate).is_ok() {
            return Ok(candidate);
        }
    }

    Err(VaultError::InvalidConfiguration(
        "no private writable runtime directory is available".into(),
    ))
}

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VaultError::InvalidConfiguration(format!(
            "private path is not a real directory: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != geteuid().as_raw() {
            return Err(VaultError::InvalidConfiguration(format!(
                "private directory is owned by another UID: {}",
                path.display()
            )));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

pub fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VaultError::InvalidConfiguration(format!(
            "private path is not a real directory: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != geteuid().as_raw() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::InvalidConfiguration(format!(
                "private directory has unsafe ownership or permissions: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn validate_private_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(VaultError::InvalidConfiguration(format!(
            "private path is not a real file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != geteuid().as_raw() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::InvalidConfiguration(format!(
                "private file has unsafe ownership or permissions: {}",
                path.display()
            )));
        }
    }
    Ok(metadata)
}
