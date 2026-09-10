#![cfg(unix)]

use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use codex_vault::{VaultError, VaultStore};

#[test]
fn explicit_environment_runtime_is_not_silently_bypassed() {
    const CHILD_ROOT: &str = "CODEX_VAULT_TEST_ENVIRONMENT_ROOT";
    if let Some(root) = env::var_os(CHILD_ROOT) {
        let root = PathBuf::from(root);
        let store = VaultStore::from_environment().expect("store from environment");
        let password = b"disposable test password only";
        store.add_user("alice", password).expect("create profile");
        assert!(matches!(
            store.unlock("alice", password),
            Err(VaultError::InvalidConfiguration(_))
        ));
        assert!(!root.join("xdg/codex-vault").exists());
        assert_eq!(
            fs::metadata(root.join("unsafe-runtime"))
                .expect("unchanged runtime")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        return;
    }

    let base = tempfile::tempdir().expect("temporary directory");
    let root = base.path();
    fs::create_dir(root.join("unsafe-runtime")).expect("unsafe runtime");
    fs::set_permissions(
        root.join("unsafe-runtime"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("unsafe permissions");
    // Isolate environment changes in a child rather than mutating the multithreaded test runner.
    let output = Command::new(env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "explicit_environment_runtime_is_not_silently_bypassed",
            "--nocapture",
        ])
        .env_clear()
        .env(CHILD_ROOT, root)
        .env("HOME", root)
        .env("TMPDIR", root)
        .env("CODEX_VAULT_HOME", root.join("vault"))
        .env("CODEX_VAULT_RUNTIME_DIR", root.join("unsafe-runtime"))
        .env("XDG_RUNTIME_DIR", root.join("xdg"))
        .output()
        .expect("run isolated environment test");
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("xdg").exists());
}
