#![cfg(unix)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use codex_vault::VaultStore;

// Opt-in: require a native binary, never a shell wrapper or the user's normal Codex home.
#[test]
#[ignore = "requires an explicitly selected native Codex binary and exact version"]
fn file_auth_survives_runtime_relocation_and_logout_is_persisted() {
    let binary = PathBuf::from(env::var_os("CODEX_VAULT_TEST_CODEX").expect("binary path"));
    assert!(binary.is_absolute() && binary.is_file());
    let version = env::var("CODEX_VAULT_TEST_CODEX_VERSION").expect("expected full version");
    let base = tempfile::tempdir().expect("temporary directory");
    let home = base.path().join("home");
    fs::create_dir(&home).expect("create home");
    let empty = base.path().join("empty-codex-home");
    fs::create_dir(&empty).expect("create empty state");
    let (code, output) = invoke(&binary, &home, &empty, &["--version"]);
    assert_eq!(code, 0);
    assert_eq!(output.trim(), version);
    println!("Validated binary version: {version}");

    let runtime = base.path().join("runtime");
    let store = VaultStore::new(base.path().join("vault")).with_runtime_root(&runtime);
    let password = b"disposable test password only";
    for username in ["alice", "bob"] {
        store.add_user(username, password).expect("create profile");
    }
    let alice = store.unlock("alice", password).expect("unlock alice");
    let first_path = alice.codex_home().to_path_buf();
    fs::write(
        alice.codex_home().join("auth.json"),
        serde_json::to_vec(
            &serde_json::json!({"OPENAI_API_KEY": "sk-fictional-vault-test-not-a-valid-key"}),
        )
        .expect("serialize fixture"),
    )
    .expect("seed fictional file credential");
    let (code, output) = invoke(&binary, &home, alice.codex_home(), &["login", "status"]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Logged in using an API key"), "{output}");
    alice.close().expect("seal alice");
    assert!(!first_path.exists());

    let bob = store.unlock("bob", password).expect("unlock bob");
    let (code, output) = invoke(&binary, &home, bob.codex_home(), &["login", "status"]);
    assert_eq!(code, 1, "{output}");
    assert!(output.contains("Not logged in"), "{output}");
    bob.close().expect("seal bob");

    let alice = store.unlock("alice", password).expect("reopen alice");
    assert_ne!(alice.codex_home(), first_path);
    let (code, output) = invoke(&binary, &home, alice.codex_home(), &["login", "status"]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Logged in using an API key"), "{output}");
    let (code, output) = invoke(&binary, &home, alice.codex_home(), &["logout"]);
    assert_eq!(code, 0, "{output}");
    assert!(!alice.codex_home().join("auth.json").exists());
    alice.close().expect("seal logout");

    let alice = store
        .unlock("alice", password)
        .expect("reopen after logout");
    let (code, output) = invoke(&binary, &home, alice.codex_home(), &["login", "status"]);
    assert_eq!(code, 1, "{output}");
    assert!(output.contains("Not logged in"), "{output}");
    alice.close().expect("seal empty state");
    assert_eq!(fs::read_dir(&runtime).expect("runtime").count(), 0);
}

fn invoke(binary: &Path, home: &Path, codex_home: &Path, arguments: &[&str]) -> (i32, String) {
    let output = tempfile::NamedTempFile::new_in(home).expect("capture output");
    let mut child = Command::new(binary)
        .env_clear()
        .env("HOME", home)
        .env("CODEX_HOME", codex_home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("TMPDIR", home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home)
        .args(["-c", "cli_auth_credentials_store=\"file\""])
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(output.as_file().try_clone().expect("stdout"))
        .stderr(output.as_file().try_clone().expect("stderr"))
        .spawn()
        .expect("launch real Codex");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for Codex") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("real Codex exceeded 15-second deadline");
        }
        thread::sleep(Duration::from_millis(20));
    };
    (
        status.code().unwrap_or(-1),
        fs::read_to_string(output.path()).expect("read output"),
    )
}
