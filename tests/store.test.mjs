import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { VaultStore } from "../dist/vault/store.js";

test("user state is encrypted at rest and isolated by password", async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), "codex-vault-test-"));
  const root = path.join(base, "vault");
  process.env.CODEX_VAULT_RUNTIME_DIR = path.join(base, "runtime");
  t.after(async () => {
    delete process.env.CODEX_VAULT_RUNTIME_DIR;
    await rm(base, { recursive: true, force: true });
  });

  const store = new VaultStore(root);
  await store.addUser("alice", "correct horse battery staple");
  const unlocked = await store.unlock("alice", "correct horse battery staple");
  await writeFile(path.join(unlocked.codexHome, "session-secret.txt"), "classified prompt", "utf8");
  await unlocked.close();

  const encryptedState = await readFile(path.join(root, "users", "alice", "state.cvlt"));
  assert.equal(encryptedState.includes(Buffer.from("classified prompt")), false);
  await assert.rejects(() => store.unlock("alice", "incorrect password"), /invalid username or password/i);

  const reopened = await store.unlock("alice", "correct horse battery staple");
  assert.equal(
    await readFile(path.join(reopened.codexHome, "session-secret.txt"), "utf8"),
    "classified prompt",
  );
  await reopened.close();
});

test("different users receive different Codex homes", async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), "codex-vault-users-"));
  const root = path.join(base, "vault");
  process.env.CODEX_VAULT_RUNTIME_DIR = path.join(base, "runtime");
  t.after(async () => {
    delete process.env.CODEX_VAULT_RUNTIME_DIR;
    await rm(base, { recursive: true, force: true });
  });

  const store = new VaultStore(root);
  await store.addUser("alice", "alice password is long enough");
  await store.addUser("bob", "bob password is also long enough");

  const alice = await store.unlock("alice", "alice password is long enough");
  await writeFile(path.join(alice.codexHome, "owner.txt"), "alice", "utf8");
  await alice.close();

  const bob = await store.unlock("bob", "bob password is also long enough");
  await assert.rejects(() => readFile(path.join(bob.codexHome, "owner.txt")), /ENOENT/);
  await bob.close();
});

test("manifest identity tampering invalidates the wrapped key", async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), "codex-vault-manifest-"));
  const root = path.join(base, "vault");
  process.env.CODEX_VAULT_RUNTIME_DIR = path.join(base, "runtime");
  t.after(async () => {
    delete process.env.CODEX_VAULT_RUNTIME_DIR;
    await rm(base, { recursive: true, force: true });
  });

  const store = new VaultStore(root);
  await store.addUser("alice", "correct horse battery staple");
  const manifestPath = path.join(root, "users", "alice", "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.createdAt = "2026-09-11T00:00:00.000Z";
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`, "utf8");

  await assert.rejects(
    () => store.unlock("alice", "correct horse battery staple"),
    /invalid username or password/i,
  );
});

test("symbolic links inside CODEX_HOME are not restored", async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), "codex-vault-links-"));
  const root = path.join(base, "vault");
  process.env.CODEX_VAULT_RUNTIME_DIR = path.join(base, "runtime");
  t.after(async () => {
    delete process.env.CODEX_VAULT_RUNTIME_DIR;
    await rm(base, { recursive: true, force: true });
  });

  const { symlink } = await import("node:fs/promises");
  const store = new VaultStore(root);
  await store.addUser("alice", "correct horse battery staple");
  const unlocked = await store.unlock("alice", "correct horse battery staple");
  await symlink("/etc/passwd", path.join(unlocked.codexHome, "unsafe-link"));
  await unlocked.close();

  const reopened = await store.unlock("alice", "correct horse battery staple");
  await assert.rejects(() => readFile(path.join(reopened.codexHome, "unsafe-link")), /ENOENT/);
  await reopened.close();
});
