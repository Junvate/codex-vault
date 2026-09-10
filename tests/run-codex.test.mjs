import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runCodex } from "../dist/runtime/run-codex.js";
import { VaultStore } from "../dist/vault/store.js";

test("runner injects the unlocked directory as CODEX_HOME and reseals it", async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), "codex-vault-runner-"));
  const root = path.join(base, "vault");
  const mock = path.join(base, "mock-codex.mjs");
  process.env.CODEX_VAULT_RUNTIME_DIR = path.join(base, "runtime");
  process.env.CODEX_VAULT_REAL_CODEX = process.execPath;
  t.after(async () => {
    delete process.env.CODEX_VAULT_RUNTIME_DIR;
    delete process.env.CODEX_VAULT_REAL_CODEX;
    await rm(base, { recursive: true, force: true });
  });

  await writeFile(
    mock,
    `import { mkdir, writeFile } from "node:fs/promises";\n` +
      `import path from "node:path";\n` +
      `await mkdir(path.join(process.env.CODEX_HOME, "sessions"), { recursive: true });\n` +
      `await writeFile(path.join(process.env.CODEX_HOME, "sessions", "result.txt"), process.argv[2]);\n`,
    "utf8",
  );

  const store = new VaultStore(root);
  await store.addUser("alice", "correct horse battery staple");
  assert.equal(
    await runCodex(store, "alice", "correct horse battery staple", [mock, "resume-private"]),
    0,
  );

  const reopened = await store.unlock("alice", "correct horse battery staple");
  assert.equal(
    await readFile(path.join(reopened.codexHome, "sessions", "result.txt"), "utf8"),
    "resume-private",
  );
  await reopened.close();
});
