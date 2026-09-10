#![cfg(target_os = "linux")]

use std::{
    fs,
    io::ErrorKind,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    thread,
    time::Duration,
};

use codex_vault::{
    DaemonConfig, VaultError,
    daemon_protocol::{
        DaemonErrorCode, DaemonRequest, DaemonResponse, PROTOCOL_VERSION, read_message,
        write_message,
    },
    query_daemon_status, serve_daemon_once,
};
use nix::unistd::geteuid;

#[test]
fn status_handshake_uses_private_socket_and_kernel_peer_credentials() {
    let base = tempfile::tempdir().expect("temporary directory");
    let socket = base.path().join("run/control.sock");
    let config = DaemonConfig::for_current_user(Some(&socket)).expect("daemon config");
    let server = spawn_once(config);
    wait_for_socket(&socket);

    assert_eq!(
        fs::symlink_metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let status = query_daemon_status(&socket).expect("query status");
    assert_eq!(status.protocol_version, PROTOCOL_VERSION);
    assert_eq!(status.daemon_uid, geteuid().as_raw());
    assert_eq!(status.peer.uid, geteuid().as_raw());
    assert!(status.capabilities.kernel_peer_credentials.is_enabled());
    assert!(!status.capabilities.pam_authentication.is_enabled());
    assert!(!status.capabilities.dedicated_uid.is_enabled());
    assert!(!status.capabilities.encrypted_mount.is_enabled());

    server.join().expect("join server").expect("serve status");
    assert!(!socket.exists());
}

#[test]
fn wrong_protocol_version_receives_a_structured_rejection() {
    let base = tempfile::tempdir().expect("temporary directory");
    let socket = base.path().join("run/control.sock");
    let config = DaemonConfig::for_current_user(Some(&socket)).expect("daemon config");
    let server = spawn_once(config);
    wait_for_socket(&socket);

    let mut stream = UnixStream::connect(&socket).expect("connect");
    write_message(
        &mut stream,
        &DaemonRequest::Status {
            protocol_version: PROTOCOL_VERSION + 1,
        },
    )
    .expect("write request");
    let response: DaemonResponse = read_message(&mut stream).expect("read response");
    assert!(matches!(
        response,
        DaemonResponse::Error {
            code: DaemonErrorCode::UnsupportedProtocol,
            ..
        }
    ));
    server.join().expect("join server").expect("serve status");
}

#[test]
fn kernel_peer_uid_policy_rejects_an_unlisted_uid() {
    let base = tempfile::tempdir().expect("temporary directory");
    let socket = base.path().join("run/control.sock");
    let rejected_uid = geteuid().as_raw().saturating_add(1);
    let config = DaemonConfig {
        socket_path: socket.clone(),
        allowed_uid: rejected_uid,
    };
    let server = spawn_once(config);
    wait_for_socket(&socket);

    let error = query_daemon_status(&socket).expect_err("peer must be rejected");
    assert!(matches!(error, VaultError::Protocol(_)));
    assert!(matches!(
        server.join().expect("join server"),
        Err(VaultError::PeerRejected(uid)) if uid == geteuid().as_raw()
    ));
}

#[test]
fn stale_owned_socket_is_replaced_but_regular_files_are_refused() {
    let base = tempfile::tempdir().expect("temporary directory");
    let run = base.path().join("run");
    fs::create_dir(&run).expect("create run directory");
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("secure run directory");
    let socket = run.join("control.sock");
    let stale = std::os::unix::net::UnixListener::bind(&socket).expect("bind stale socket");
    drop(stale);

    let config = DaemonConfig::for_current_user(Some(&socket)).expect("daemon config");
    let server = spawn_once(config);
    query_status_with_retry(&socket);
    server.join().expect("join server").expect("serve status");

    fs::write(&socket, b"do not replace").expect("create regular file");
    let config = DaemonConfig::for_current_user(Some(&socket)).expect("daemon config");
    assert!(matches!(
        serve_daemon_once(&config),
        Err(VaultError::InvalidConfiguration(_))
    ));
    assert_eq!(
        fs::read(&socket).expect("read regular file"),
        b"do not replace"
    );
}

#[test]
fn shutdown_does_not_remove_a_replacement_at_the_socket_path() {
    let base = tempfile::tempdir().expect("temporary directory");
    let socket = base.path().join("run/control.sock");
    let moved_socket = base.path().join("run/moved.sock");
    let config = DaemonConfig::for_current_user(Some(&socket)).expect("daemon config");
    let server = spawn_once(config);
    wait_for_socket(&socket);

    fs::rename(&socket, &moved_socket).expect("move live socket path");
    fs::write(&socket, b"replacement must remain").expect("write replacement");
    query_daemon_status(&moved_socket).expect("query moved live socket");
    server.join().expect("join server").expect("serve status");

    assert_eq!(
        fs::read(&socket).expect("read replacement"),
        b"replacement must remain"
    );
    fs::remove_file(&moved_socket).expect("remove moved socket");
}

fn spawn_once(config: DaemonConfig) -> thread::JoinHandle<codex_vault::Result<()>> {
    thread::spawn(move || serve_daemon_once(&config))
}

fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("daemon socket was not created: {}", path.display());
}

fn query_status_with_retry(path: &Path) {
    for _ in 0..200 {
        match query_daemon_status(path) {
            Ok(_) => return,
            Err(VaultError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotFound
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("daemon status query failed: {error}"),
        }
    }
    panic!("daemon did not replace stale socket: {}", path.display());
}
