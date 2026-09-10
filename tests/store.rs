use std::{fs, path::Path};

use codex_vault::{VaultError, VaultStore};

fn store_at(base: &Path) -> VaultStore {
    VaultStore::new(base.join("vault")).with_runtime_root(base.join("runtime"))
}

#[test]
fn state_is_encrypted_at_rest_and_reopens() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";

    store.add_user("alice", password).expect("add user");
    let vault = store.unlock("alice", password).expect("unlock");
    fs::write(
        vault.codex_home().join("session-secret.txt"),
        b"classified prompt",
    )
    .expect("write state");
    vault.close().expect("close");

    let user_root = base.path().join("vault/users/alice");
    let ciphertext = fs::read(user_root.join("state.cvlt")).expect("read ciphertext");
    let manifest = fs::read(user_root.join("manifest.json")).expect("read manifest");
    assert!(!contains(&ciphertext, b"classified prompt"));
    assert!(!contains(&ciphertext, password));
    assert!(!contains(&manifest, password));
    assert!(matches!(
        store.unlock("alice", b"incorrect password"),
        Err(VaultError::Authentication)
    ));

    let reopened = store.unlock("alice", password).expect("reopen");
    assert_eq!(
        fs::read(reopened.codex_home().join("session-secret.txt")).expect("read state"),
        b"classified prompt"
    );
    reopened.close().expect("close reopened vault");
}

#[test]
fn users_are_isolated_and_locked_against_concurrent_access() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let alice_password = b"alice password is long enough";
    let bob_password = b"bob password is also long enough";
    store.add_user("alice", alice_password).expect("add alice");
    store.add_user("bob", bob_password).expect("add bob");

    let alice = store.unlock("alice", alice_password).expect("unlock alice");
    fs::write(alice.codex_home().join("owner.txt"), b"alice").expect("write owner");
    assert!(matches!(
        store.unlock("alice", alice_password),
        Err(VaultError::Locked)
    ));
    alice.close().expect("close alice");

    let bob = store.unlock("bob", bob_password).expect("unlock bob");
    assert!(!bob.codex_home().join("owner.txt").exists());
    bob.close().expect("close bob");

    let alice = store.unlock("alice", alice_password).expect("reopen alice");
    assert_eq!(
        fs::read(alice.codex_home().join("owner.txt")).expect("read owner"),
        b"alice"
    );
    alice.close().expect("close alice again");
}

#[test]
fn password_rotation_rewraps_the_key_without_rewriting_state() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let old_password = b"old password is long enough";
    let new_password = b"new password is also long enough";
    store.add_user("alice", old_password).expect("add alice");

    let vault = store.unlock("alice", old_password).expect("unlock alice");
    fs::write(vault.codex_home().join("owner.txt"), b"alice").expect("write owner");
    vault.close().expect("close alice");
    let state_path = base.path().join("vault/users/alice/state.cvlt");
    let state_before = fs::read(&state_path).expect("read original state");

    assert!(matches!(
        store.rotate_password("alice", b"incorrect password", new_password),
        Err(VaultError::Authentication)
    ));
    assert_eq!(
        fs::read(&state_path).expect("read state after failed rotation"),
        state_before
    );
    store
        .unlock("alice", old_password)
        .expect("old password remains valid after failed rotation")
        .close()
        .expect("close after failed rotation");
    let state_before_successful_rotation =
        fs::read(&state_path).expect("read state before successful rotation");

    store
        .rotate_password("alice", old_password, new_password)
        .expect("rotate password");
    assert_eq!(
        fs::read(&state_path).expect("read state after rotation"),
        state_before_successful_rotation
    );
    assert!(matches!(
        store.unlock("alice", old_password),
        Err(VaultError::Authentication)
    ));
    let reopened = store
        .unlock("alice", new_password)
        .expect("new password works");
    assert_eq!(
        fs::read(reopened.codex_home().join("owner.txt")).expect("read owner"),
        b"alice"
    );
    reopened.close().expect("close reopened vault");
}

#[test]
fn password_rotation_rejects_an_active_profile() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");
    let vault = store.unlock("alice", password).expect("unlock");

    assert!(matches!(
        store.rotate_password("alice", password, b"replacement password is long"),
        Err(VaultError::Locked)
    ));
    vault.close().expect("close");
}

#[test]
fn manifest_identity_tampering_invalidates_the_wrapped_key() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");

    let manifest_path = base.path().join("vault/users/alice/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["createdAt"] =
        serde_json::Value::from(manifest["createdAt"].as_u64().expect("timestamp") + 1);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    assert!(matches!(
        store.unlock("alice", password),
        Err(VaultError::Authentication)
    ));
}

#[cfg(unix)]
#[test]
fn symbolic_links_inside_codex_home_are_not_restored() {
    use std::os::unix::fs::symlink;

    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");

    let vault = store.unlock("alice", password).expect("unlock");
    symlink("/etc/passwd", vault.codex_home().join("unsafe-link")).expect("create symlink");
    vault.close().expect("close");

    let reopened = store.unlock("alice", password).expect("reopen");
    assert!(!reopened.codex_home().join("unsafe-link").exists());
    reopened.close().expect("close reopened vault");
}

#[cfg(unix)]
#[test]
fn storage_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    store
        .add_user("alice", b"correct horse battery staple")
        .expect("add user");

    let root_mode = fs::metadata(base.path().join("vault"))
        .expect("root metadata")
        .permissions()
        .mode()
        & 0o777;
    let manifest_mode = fs::metadata(base.path().join("vault/users/alice/manifest.json"))
        .expect("manifest metadata")
        .permissions()
        .mode()
        & 0o777;
    let state_mode = fs::metadata(base.path().join("vault/users/alice/state.cvlt"))
        .expect("state metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(root_mode, 0o700);
    assert_eq!(manifest_mode, 0o600);
    assert_eq!(state_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn unlock_rejects_overly_broad_profile_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");
    fs::set_permissions(
        base.path().join("vault/users/alice"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("broaden permissions");

    assert!(matches!(
        store.unlock("alice", password),
        Err(VaultError::Authentication)
    ));
}

#[cfg(unix)]
#[test]
fn lock_file_symlink_is_rejected_without_modifying_its_target() {
    use std::os::unix::fs::symlink;

    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");
    let victim = base.path().join("victim.txt");
    fs::write(&victim, b"must remain intact").expect("write victim");
    symlink(&victim, base.path().join("vault/users/alice/active.lock"))
        .expect("create lock symlink");

    assert!(store.unlock("alice", password).is_err());
    assert_eq!(
        fs::read(victim).expect("read victim"),
        b"must remain intact"
    );
}

#[test]
fn stale_lock_contents_do_not_block_recovery() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");
    fs::write(
        base.path().join("vault/users/alice/active.lock"),
        b"{\"pid\":999999999}\n",
    )
    .expect("write stale lock contents");

    store
        .unlock("alice", password)
        .expect("OS lock, not stale contents, controls access")
        .close()
        .expect("close");
}

#[test]
fn encrypted_state_failures_are_reported_as_integrity_errors() {
    let base = tempfile::tempdir().expect("temporary directory");
    let store = store_at(base.path());
    let password = b"correct horse battery staple";
    store.add_user("alice", password).expect("add user");
    let state_path = base.path().join("vault/users/alice/state.cvlt");
    let mut state = fs::read(&state_path).expect("read state");
    let index = state.len() / 2;
    state[index] ^= 1;
    fs::write(&state_path, state).expect("tamper state");

    assert!(matches!(
        store.unlock("alice", password),
        Err(VaultError::Integrity(_))
    ));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
