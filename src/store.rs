use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use fs2::FileExt;
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    archive::{seal_directory, unseal_directory},
    config::{
        default_vault_root, ensure_private_directory, select_runtime_root,
        validate_private_directory, validate_private_file,
    },
    crypto::{default_kdf_parameters, derive_key, unwrap_data_key, wrap_data_key},
    error::{Result, VaultError},
    manifest::{UserManifest, is_valid_username},
};

const MANIFEST_SIZE_LIMIT: u64 = 64 * 1024;

/// Persistent encrypted Codex profile storage.
pub struct VaultStore {
    root: PathBuf,
    runtime_root: Option<PathBuf>,
}

impl VaultStore {
    /// Creates a store from `CODEX_VAULT_HOME` or the current user's home directory.
    ///
    /// # Errors
    ///
    /// Returns an error when neither storage location is available.
    pub fn from_environment() -> Result<Self> {
        Ok(Self::new(default_vault_root()?))
    }

    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            runtime_root: None,
        }
    }

    #[must_use]
    pub fn with_runtime_root(mut self, runtime_root: impl Into<PathBuf>) -> Self {
        self.runtime_root = Some(runtime_root.into());
        self
    }

    /// Creates the private storage directories and enforces restrictive permissions.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is unsafe, owned by another UID, or inaccessible.
    pub fn initialize(&self) -> Result<()> {
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.users_root())
    }

    /// Creates an encrypted application-level user profile.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, duplicate users, random-source failures, or I/O
    /// failures while creating the initial vault.
    pub fn add_user(&self, username: &str, password: &[u8]) -> Result<()> {
        validate_username(username)?;
        validate_password(password)?;
        self.initialize()?;

        let user_root = self.user_root(username);
        if fs::symlink_metadata(&user_root).is_ok() {
            return Err(VaultError::UserExists(username.into()));
        }

        let staging = self
            .users_root()
            .join(format!(".creating-{}", Uuid::new_v4()));
        ensure_private_directory(&staging)?;

        let result = (|| {
            let kdf = default_kdf_parameters()?;
            let wrapping_key = derive_key(password, &kdf)?;
            let mut data_key = Zeroizing::new([0_u8; 32]);
            getrandom::fill(data_key.as_mut())
                .map_err(|_| VaultError::Cryptography("operating-system random source failed"))?;
            let mut manifest = UserManifest::new_header(username.into(), kdf)?;
            manifest.wrapped_data_key =
                wrap_data_key(&data_key, &wrapping_key, &manifest.associated_data()?)?;

            write_private_json(&staging.join("manifest.json"), &manifest)?;
            let empty = tempfile::tempdir()?;
            seal_directory(empty.path(), &staging.join("state.cvlt"), &data_key)?;
            fs::rename(&staging, &user_root)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    /// Lists valid user profiles without unlocking their encrypted state.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be initialized or enumerated.
    pub fn list_users(&self) -> Result<Vec<String>> {
        self.initialize()?;
        let mut users = Vec::new();
        for entry in fs::read_dir(self.users_root())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() || entry.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            if let Ok(manifest) = read_manifest(&entry.path()) {
                users.push(manifest.username);
            }
        }
        users.sort_unstable();
        Ok(users)
    }

    /// Authenticates a user and extracts their encrypted Codex state into a private runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, concurrent access, invalid encrypted state, or
    /// runtime-directory failures.
    pub fn unlock(&self, username: &str, password: &[u8]) -> Result<UnlockedVault> {
        validate_username(username)?;
        let user_root = self.user_root(username);
        validate_private_directory(&user_root).map_err(|_| VaultError::Authentication)?;
        let mut lock = Some(acquire_lock(&user_root.join("active.lock"))?);

        let result = (|| {
            let manifest = read_manifest(&user_root)?;
            manifest.validate()?;
            if !manifest.username.eq_ignore_ascii_case(username) {
                return Err(VaultError::Authentication);
            }
            let wrapping_key =
                derive_key(password, &manifest.kdf).map_err(|_| VaultError::Authentication)?;
            let data_key = unwrap_data_key(
                &manifest.wrapped_data_key,
                &wrapping_key,
                &manifest.associated_data()?,
            )?;

            let runtime_root = match &self.runtime_root {
                Some(path) => {
                    ensure_private_directory(path)?;
                    path.clone()
                }
                None => select_runtime_root()?,
            };
            let runtime = tempfile::Builder::new()
                .prefix(&format!("{}-", manifest.id))
                .tempdir_in(runtime_root)?;
            let codex_home = runtime.path().join("codex-home");
            ensure_private_directory(&codex_home)?;
            unseal_directory(&user_root.join("state.cvlt"), &codex_home, &data_key)?;

            Ok(UnlockedVault {
                username: manifest.username,
                codex_home,
                runtime,
                state_path: user_root.join("state.cvlt"),
                data_key,
                lock: lock
                    .take()
                    .ok_or(VaultError::Cryptography("vault lock was not available"))?,
            })
        })();

        if let (Err(_), Some(lock)) = (&result, lock.as_ref()) {
            let _ = FileExt::unlock(lock);
        }
        result
    }

    fn users_root(&self) -> PathBuf {
        self.root.join("users")
    }

    fn user_root(&self, username: &str) -> PathBuf {
        self.users_root().join(username.to_ascii_lowercase())
    }
}

/// An authenticated, exclusively locked Codex profile with a temporary plaintext runtime.
pub struct UnlockedVault {
    username: String,
    codex_home: PathBuf,
    runtime: TempDir,
    state_path: PathBuf,
    data_key: Zeroizing<[u8; 32]>,
    lock: File,
}

impl UnlockedVault {
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    /// Reseals the runtime state, releases the lock, and removes the temporary directory.
    ///
    /// # Errors
    ///
    /// Returns an error when resealing or releasing the file lock fails. The temporary directory is
    /// still removed to avoid leaving plaintext behind.
    pub fn close(self) -> Result<()> {
        let seal_result = seal_directory(&self.codex_home, &self.state_path, &self.data_key);
        let unlock_result = FileExt::unlock(&self.lock).map_err(VaultError::Io);
        drop(self.runtime);
        seal_result?;
        unlock_result
    }
}

fn validate_username(username: &str) -> Result<()> {
    if !is_valid_username(username) {
        return Err(VaultError::InvalidConfiguration(
            "username must be 1-64 ASCII letters, numbers, dot, underscore, or hyphen".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &[u8]) -> Result<()> {
    if password.len() < 12 {
        return Err(VaultError::InvalidConfiguration(
            "password must contain at least 12 bytes".into(),
        ));
    }
    Ok(())
}

fn write_private_json(path: &Path, value: &UserManifest) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_manifest(user_root: &Path) -> Result<UserManifest> {
    let path = user_root.join("manifest.json");
    let metadata = validate_private_file(&path)?;
    if metadata.len() > MANIFEST_SIZE_LIMIT {
        return Err(VaultError::InvalidConfiguration(
            "invalid user manifest file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        VaultError::InvalidConfiguration("user manifest size does not fit this platform".into())
    })?;
    let mut contents = Vec::with_capacity(capacity);
    file.take(MANIFEST_SIZE_LIMIT + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MANIFEST_SIZE_LIMIT {
        return Err(VaultError::InvalidConfiguration(
            "user manifest exceeds size limit".into(),
        ));
    }
    let manifest: UserManifest = serde_json::from_slice(&contents)?;
    manifest.validate()?;
    Ok(manifest)
}

fn acquire_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(VaultError::Locked);
        }
        Err(error) => return Err(VaultError::Io(error)),
    }
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "{{\"pid\":{}}}", std::process::id())?;
    file.flush()?;
    Ok(file)
}
