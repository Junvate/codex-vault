#![cfg(unix)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use codex_vault::VaultStore;

mod support;

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

    let relocated_runtime = base.path().join("relocated-runtime");
    let store = VaultStore::new(base.path().join("vault")).with_runtime_root(&relocated_runtime);
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
    assert_eq!(
        fs::read_dir(&relocated_runtime)
            .expect("relocated runtime")
            .count(),
        0
    );
}

#[test]
#[ignore = "requires an explicitly selected native Codex binary and exact version"]
// Keep the ordered cross-profile scenario together so its history assertions remain auditable.
#[allow(clippy::too_many_lines)]
fn real_resume_uses_only_the_unlocked_profile_history() {
    let binary = PathBuf::from(env::var_os("CODEX_VAULT_TEST_CODEX").expect("binary path"));
    assert!(binary.is_absolute() && binary.is_file());
    let version = env::var("CODEX_VAULT_TEST_CODEX_VERSION").expect("expected full version");
    let base = tempfile::tempdir().expect("temporary directory");
    let home = base.path().join("home");
    fs::create_dir(&home).expect("create home");
    let runtime = base.path().join("runtime");
    let store = VaultStore::new(base.path().join("vault")).with_runtime_root(&runtime);
    let password = b"disposable test password only";
    let server = support::LocalResponses::start();
    for username in ["alice", "bob"] {
        store.add_user(username, password).expect("create profile");
        let profile = store.unlock(username, password).expect("unlock profile");
        fs::write(profile.codex_home().join("config.toml"), format!(
            "model = \"fixture-model\"\nmodel_provider = \"fixture\"\nsandbox_mode = \"read-only\"\n[model_providers.fixture]\nname = \"Local fixture\"\nbase_url = \"{}\"\nwire_api = \"responses\"\nrequires_openai_auth = false\n", server.url()
        )).expect("write fixture-only configuration");
        profile.close().expect("seal configuration");
    }

    let alice = store.unlock("alice", password).expect("unlock alice");
    let (code, output) = invoke(&binary, &home, alice.codex_home(), &["--version"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(output.trim(), version);
    let first_path = alice.codex_home().to_path_buf();
    let (code, output) = invoke(
        &binary,
        &home,
        alice.codex_home(),
        &[
            "exec",
            "--skip-git-repo-check",
            "--json",
            "alice-private-marker-18739",
        ],
    );
    assert_eq!(code, 0, "{output}");
    let alice_thread = thread_id(&output);
    assert!(output.contains("fixture-reply"), "{output}");
    alice.close().expect("seal first turn");
    assert!(!first_path.exists());
    let initial = server.take_requests();
    assert_eq!(initial.len(), 1);
    assert!(
        initial[0]
            .to_string()
            .contains("alice-private-marker-18739")
    );

    let bob = store.unlock("bob", password).expect("unlock bob");
    let (code, output) = invoke(
        &binary,
        &home,
        bob.codex_home(),
        &[
            "exec",
            "resume",
            "--skip-git-repo-check",
            "--json",
            &alice_thread,
            "foreign-id-probe-82516",
        ],
    );
    assert_ne!(code, 0, "foreign thread must not resume: {output}");
    assert!(!output.contains("alice-private-marker-18739"), "{output}");
    assert!(
        server.take_requests().is_empty(),
        "foreign resume must not reach provider"
    );
    let (code, output) = invoke(
        &binary,
        &home,
        bob.codex_home(),
        &[
            "exec",
            "resume",
            "--last",
            "--all",
            "--skip-git-repo-check",
            "--json",
            "bob-public-marker-24198",
        ],
    );
    assert_eq!(code, 0, "{output}");
    assert_ne!(thread_id(&output), alice_thread);
    bob.close().expect("seal bob");
    let requests = server.take_requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].to_string().contains("bob-public-marker-24198"));
    assert!(
        !requests[0]
            .to_string()
            .contains("alice-private-marker-18739")
    );

    let alice = store.unlock("alice", password).expect("reopen alice");
    assert_eq!(alice.codex_home(), first_path);
    let (code, output) = invoke(
        &binary,
        &home,
        alice.codex_home(),
        &[
            "exec",
            "resume",
            "--last",
            "--all",
            "--skip-git-repo-check",
            "--json",
            "alice-followup-marker-95310",
        ],
    );
    assert_eq!(code, 0, "{output}");
    assert_eq!(thread_id(&output), alice_thread);
    alice.close().expect("seal resumed turn");
    let requests = server.take_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].to_string();
    assert!(body.contains("alice-private-marker-18739"));
    assert!(body.contains("alice-followup-marker-95310"));
    assert!(body.contains("fixture-reply"));
    assert!(!body.contains("bob-public-marker-24198"));

    let alice = store
        .unlock("alice", password)
        .expect("reopen for explicit ID");
    let (code, output) = invoke(
        &binary,
        &home,
        alice.codex_home(),
        &[
            "exec",
            "resume",
            "--skip-git-repo-check",
            "--json",
            &alice_thread,
            "alice-explicit-id-marker-62941",
        ],
    );
    assert_eq!(code, 0, "{output}");
    assert_eq!(thread_id(&output), alice_thread);
    alice.close().expect("seal explicit-ID turn");
    let requests = server.take_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].to_string();
    assert!(body.contains("alice-private-marker-18739"));
    assert!(body.contains("alice-followup-marker-95310"));
    assert!(body.contains("alice-explicit-id-marker-62941"));
    assert!(!body.contains("foreign-id-probe-82516"));
    assert!(!body.contains("bob-public-marker-24198"));
    assert_eq!(fs::read_dir(&runtime).expect("runtime").count(), 0);
}

fn thread_id(output: &str) -> String {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["type"] == "thread.started")
        .and_then(|value| value["thread_id"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("missing thread.started event: {output}"))
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
