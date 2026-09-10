use std::{
    env,
    path::{Path, PathBuf},
};

use crate::{Result, VaultError, daemon_protocol::DaemonStatus};

#[cfg(target_os = "linux")]
use std::{
    fs,
    io::ErrorKind,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};

#[cfg(target_os = "linux")]
use crate::{
    config::ensure_private_directory,
    daemon_protocol::{
        DaemonCapabilities, DaemonErrorCode, DaemonRequest, DaemonResponse, PROTOCOL_VERSION,
        PeerIdentity, read_message, write_message,
    },
};

const SOCKET_ENVIRONMENT_VARIABLE: &str = "CODEX_VAULT_SOCKET";
#[cfg(target_os = "linux")]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub allowed_uid: u32,
}

impl DaemonConfig {
    /// Creates the status-only alpha policy for the daemon's current effective UID.
    ///
    /// # Errors
    ///
    /// Returns an error when a secure default socket path cannot be selected.
    pub fn for_current_user(socket_path: Option<&Path>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                socket_path: socket_path.map_or_else(default_daemon_socket, |path| {
                    Ok::<PathBuf, VaultError>(path.to_path_buf())
                })?,
                allowed_uid: geteuid().as_raw(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket_path;
            Err(VaultError::UnsupportedPlatform(
                "codex-vaultd currently requires Linux",
            ))
        }
    }
}

/// Selects the daemon socket from `CODEX_VAULT_SOCKET`, `XDG_RUNTIME_DIR`, `/run/user`, or a
/// per-UID temporary fallback.
///
/// # Errors
///
/// Returns an error when an explicit socket path is not absolute.
pub fn default_daemon_socket() -> Result<PathBuf> {
    if let Some(path) = env::var_os(SOCKET_ENVIRONMENT_VARIABLE) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(VaultError::InvalidConfiguration(format!(
                "{SOCKET_ENVIRONMENT_VARIABLE} must be an absolute path"
            )));
        }
        return Ok(path);
    }

    #[cfg(target_os = "linux")]
    {
        let uid = geteuid().as_raw();
        if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR") {
            let runtime = PathBuf::from(runtime);
            if !runtime.is_absolute() {
                return Err(VaultError::InvalidConfiguration(
                    "XDG_RUNTIME_DIR must be an absolute path".into(),
                ));
            }
            return Ok(runtime.join("codex-vault").join("control.sock"));
        }
        let run_user = PathBuf::from(format!("/run/user/{uid}"));
        if run_user.is_dir() {
            return Ok(run_user.join("codex-vault").join("control.sock"));
        }
        Ok(env::temp_dir()
            .join(format!("codex-vault-{uid}"))
            .join("control.sock"))
    }

    #[cfg(not(target_os = "linux"))]
    Err(VaultError::UnsupportedPlatform(
        "codex-vaultd currently requires Linux",
    ))
}

/// Connects to the daemon and performs a versioned status handshake.
///
/// # Errors
///
/// Returns an error when the daemon is unavailable, the response is invalid, or the server rejects
/// the client.
pub fn query_daemon_status(socket_path: &Path) -> Result<DaemonStatus> {
    #[cfg(target_os = "linux")]
    {
        if !socket_path.is_absolute() {
            return Err(VaultError::InvalidConfiguration(
                "daemon socket path must be absolute".into(),
            ));
        }
        let mut stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
        stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
        write_message(
            &mut stream,
            &DaemonRequest::Status {
                protocol_version: PROTOCOL_VERSION,
            },
        )?;
        match read_message(&mut stream)? {
            DaemonResponse::Status(status) if status.protocol_version == PROTOCOL_VERSION => {
                Ok(status)
            }
            DaemonResponse::Status(status) => Err(VaultError::Protocol(format!(
                "daemon returned protocol version {} instead of {PROTOCOL_VERSION}",
                status.protocol_version
            ))),
            DaemonResponse::Error { code, message, .. } => Err(VaultError::Protocol(format!(
                "daemon rejected request ({code:?}): {message}"
            ))),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket_path;
        Err(VaultError::UnsupportedPlatform(
            "codex-vaultd currently requires Linux",
        ))
    }
}

/// Runs the foreground daemon until `SIGINT` or `SIGTERM`.
///
/// # Errors
///
/// Returns an error when the socket cannot be secured or the listener fails.
pub fn serve_daemon(config: &DaemonConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};

        let stop = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(SIGINT, Arc::clone(&stop))?;
        signal_hook::flag::register(SIGTERM, Arc::clone(&stop))?;
        let (listener, _guard) = bind_listener(config)?;
        listener.set_nonblocking(true)?;
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Err(error) = handle_connection(&mut stream, config.allowed_uid) {
                        eprintln!("codex-vaultd: rejected connection: {error}");
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(VaultError::Io(error)),
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(VaultError::UnsupportedPlatform(
            "codex-vaultd currently requires Linux",
        ))
    }
}

/// Serves one connection and exits. Intended for deterministic integration tests and service
/// readiness probes.
///
/// # Errors
///
/// Returns an error when the socket cannot be secured or the connection is rejected.
pub fn serve_daemon_once(config: &DaemonConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (listener, _guard) = bind_listener(config)?;
        let (mut stream, _) = listener.accept()?;
        handle_connection(&mut stream, config.allowed_uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(VaultError::UnsupportedPlatform(
            "codex-vaultd currently requires Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn bind_listener(config: &DaemonConfig) -> Result<(UnixListener, SocketGuard)> {
    let path = &config.socket_path;
    if !path.is_absolute() {
        return Err(VaultError::InvalidConfiguration(
            "daemon socket path must be absolute".into(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        VaultError::InvalidConfiguration("daemon socket path has no parent directory".into())
    })?;
    ensure_private_directory(parent)?;
    remove_stale_socket(path)?;

    let listener = UnixListener::bind(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(VaultError::Io(error));
        }
    };
    let guard = SocketGuard {
        path: path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(VaultError::InvalidConfiguration(
            "daemon socket has unsafe ownership or permissions".into(),
        ));
    }
    Ok((listener, guard))
}

#[cfg(target_os = "linux")]
fn remove_stale_socket(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
        return Err(VaultError::InvalidConfiguration(
            "daemon socket path exists and is not a socket owned by the current UID".into(),
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(VaultError::DaemonAlreadyRunning),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) => Err(VaultError::Io(error)),
    }
}

#[cfg(target_os = "linux")]
fn handle_connection(stream: &mut UnixStream, allowed_uid: u32) -> Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let credentials = getsockopt(stream, PeerCredentials).map_err(|error| {
        VaultError::Protocol(format!("failed to read kernel peer credentials: {error}"))
    })?;
    let peer = PeerIdentity {
        pid: credentials.pid(),
        uid: credentials.uid(),
        gid: credentials.gid(),
    };
    if peer.uid != allowed_uid {
        write_message(
            stream,
            &DaemonResponse::Error {
                protocol_version: PROTOCOL_VERSION,
                code: DaemonErrorCode::PeerRejected,
                message: "kernel-authenticated peer UID is not allowed".into(),
            },
        )?;
        return Err(VaultError::PeerRejected(peer.uid));
    }

    match read_message(stream)? {
        DaemonRequest::Status { protocol_version } if protocol_version == PROTOCOL_VERSION => {
            write_message(
                stream,
                &DaemonResponse::Status(DaemonStatus {
                    protocol_version: PROTOCOL_VERSION,
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    daemon_uid: geteuid().as_raw(),
                    peer,
                    capabilities: DaemonCapabilities::alpha_status_only(),
                }),
            )
        }
        DaemonRequest::Status { protocol_version } => write_message(
            stream,
            &DaemonResponse::Error {
                protocol_version: PROTOCOL_VERSION,
                code: DaemonErrorCode::UnsupportedProtocol,
                message: format!(
                    "client protocol version {protocol_version} is unsupported; expected {PROTOCOL_VERSION}"
                ),
            },
        ),
    }
}

#[cfg(target_os = "linux")]
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
