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
