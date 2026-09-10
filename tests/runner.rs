#[cfg(unix)]
#[test]
fn runner_injects_codex_home_and_reseals_state() {
    use std::{ffi::OsString, fs};

    use codex_vault::{VaultStore, run_program};

    let base = tempfile::tempdir().expect("temporary directory");
    let store =
        VaultStore::new(base.path().join("vault")).with_runtime_root(base.path().join("runtime"));
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");

    let arguments = vec![
        OsString::from("-c"),
        OsString::from(
            "mkdir -p \"$CODEX_HOME/sessions\" && printf resume-private > \"$CODEX_HOME/sessions/result.txt\"",
        ),
    ];
    assert_eq!(
        run_program(&store, "alice", password, "/bin/sh", &arguments).expect("run program"),
        0
    );

    let reopened = store.unlock("alice", password).expect("reopen");
    assert_eq!(
        fs::read(reopened.codex_home().join("sessions/result.txt")).expect("read result"),
        b"resume-private"
    );
    reopened.close().expect("close");
}

#[cfg(unix)]
#[test]
fn runner_preserves_arguments_exit_status_and_user_state() {
    use codex_vault::{VaultStore, run_program};
    use std::{ffi::OsString, fs};

    let base = tempfile::tempdir().expect("temporary directory");
    let runtime = base.path().join("runtime");
    let store = VaultStore::new(base.path().join("vault")).with_runtime_root(&runtime);
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add alice");
    store.add_user("bob", password).expect("add bob");
    let arguments: Vec<OsString> = [
        "-c",
        "printf '%s\\0' \"$@\" > \"$CODEX_HOME/arguments\"; printf '%s' \"$CODEX_VAULT_ACTIVE_USER\" > \"$CODEX_HOME/user\"; exit 23",
        "mock-codex",
        "resume",
        "--last",
        "two words",
        "",
        "$(touch should-not-exist)",
    ].into_iter().map(OsString::from).collect();
    assert_eq!(
        run_program(&store, "alice", password, "/bin/sh", &arguments).expect("launch"),
        23
    );
    assert_eq!(fs::read_dir(&runtime).expect("runtime").count(), 0);
    let alice = store.unlock("alice", password).expect("reopen alice");
    assert_eq!(
        fs::read(alice.codex_home().join("arguments")).expect("arguments"),
        b"resume\0--last\0two words\0\0$(touch should-not-exist)\0"
    );
    assert_eq!(
        fs::read(alice.codex_home().join("user")).expect("user"),
        b"alice"
    );
    alice.close().expect("close alice");
    let bob = store.unlock("bob", password).expect("open bob");
    assert!(!bob.codex_home().join("arguments").exists());
    bob.close().expect("close bob");
}

#[cfg(unix)]
#[test]
fn failed_launch_reseals_state_and_releases_profile_lock() {
    use codex_vault::{VaultError, VaultStore, run_program};
    use std::fs;

    let base = tempfile::tempdir().expect("temporary directory");
    let runtime = base.path().join("runtime");
    let store = VaultStore::new(base.path().join("vault")).with_runtime_root(&runtime);
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add alice");
    let alice = store.unlock("alice", password).expect("unlock");
    fs::write(alice.codex_home().join("marker"), b"preserve me").expect("write marker");
    alice.close().expect("close");
    assert!(matches!(
        run_program(
            &store,
            "alice",
            password,
            base.path().join("missing-program"),
            &[]
        ),
        Err(VaultError::Launch(_))
    ));
    assert_eq!(fs::read_dir(&runtime).expect("runtime").count(), 0);
    let alice = store.unlock("alice", password).expect("lock released");
    assert_eq!(
        fs::read(alice.codex_home().join("marker")).expect("read marker"),
        b"preserve me"
    );
    alice.close().expect("close");
}
