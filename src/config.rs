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

    select_runtime_root_from(
        env::var_os("CODEX_VAULT_RUNTIME_DIR").map(PathBuf::from),
        candidates,
    )
}

fn select_runtime_root_from(
    explicit: Option<PathBuf>,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return prepare_runtime_root(&path);
    }

    for candidate in candidates {
        if let Ok(path) = prepare_runtime_root(&candidate) {
            return Ok(path);
        }
    }

    Err(VaultError::InvalidConfiguration(
        "no private writable runtime directory is available".into(),
    ))
}

pub fn prepare_runtime_root(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(VaultError::InvalidConfiguration(
            "runtime root must be an absolute path; refusing implicit relocation".into(),
        ));
    }
    ensure_private_directory(path)?;
    Ok(fs::canonicalize(path)?)
}

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(VaultError::Io(error)),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;

    validate_private_directory(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_runtime_is_canonical_and_never_uses_fallback() {
        let base = tempfile::tempdir().expect("temporary directory");
        let explicit = base.path().join("private-runtime");
        let fallback = base.path().join("fallback");
        let selected = select_runtime_root_from(Some(explicit.clone()), [fallback.clone()])
            .expect("explicit runtime");
        assert_eq!(
            selected,
            fs::canonicalize(explicit).expect("canonical root")
        );
        assert!(!fallback.exists());
    }

    #[test]
    fn relative_and_empty_explicit_roots_do_not_fall_back() {
        let base = tempfile::tempdir().expect("temporary directory");
        let fallback = base.path().join("fallback");
        for path in [PathBuf::new(), PathBuf::from("relative-runtime")] {
            assert!(matches!(
                select_runtime_root_from(Some(path), [fallback.clone()]),
                Err(VaultError::InvalidConfiguration(_))
            ));
            assert!(!fallback.exists());
        }
    }

    #[test]
    fn regular_file_override_is_preserved_and_not_bypassed() {
        let base = tempfile::tempdir().expect("temporary directory");
        let path = base.path().join("not-a-directory");
        let fallback = base.path().join("fallback");
        fs::write(&path, b"preserve me").expect("file");
        assert!(select_runtime_root_from(Some(path.clone()), [fallback.clone()]).is_err());
        assert_eq!(fs::read(path).expect("file unchanged"), b"preserve me");
        assert!(!fallback.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_and_symlink_overrides_fail_without_mutation() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let base = tempfile::tempdir().expect("temporary directory");
        let shared = base.path().join("shared");
        let link = base.path().join("link");
        let fallback = base.path().join("fallback");
        fs::create_dir(&shared).expect("shared directory");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).expect("permissions");
        symlink(&shared, &link).expect("link");
        for path in [&shared, &link] {
            assert!(select_runtime_root_from(Some(path.clone()), [fallback.clone()]).is_err());
        }
        assert!(!fallback.exists());
        assert_eq!(fs::read_link(link).expect("preserved link"), shared);
        assert_eq!(
            fs::metadata(shared).expect("metadata").permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn automatic_selection_can_skip_an_unusable_candidate() {
        let base = tempfile::tempdir().expect("temporary directory");
        let file = base.path().join("file");
        let fallback = base.path().join("fallback");
        fs::write(&file, b"preserve me").expect("file");
        let selected = select_runtime_root_from(None, [file.clone(), fallback.clone()])
            .expect("automatic fallback");
        assert_eq!(
            selected,
            fs::canonicalize(fallback).expect("canonical fallback")
        );
        assert_eq!(fs::read(file).expect("file unchanged"), b"preserve me");
    }
}
