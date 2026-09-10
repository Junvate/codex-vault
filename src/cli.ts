#!/usr/bin/env node

import { VaultStore } from "./vault/store.js";
import { readPassword, promptLine } from "./ui/prompt.js";
import { runCodex } from "./runtime/run-codex.js";

function usage(): void {
  console.log(`codex-vault 0.1.0

Usage:
  codex-vault init
  codex-vault user add <username>
  codex-vault user list
  codex-vault run [--user <username>] -- [codex arguments]

Examples:
  codex-vault user add alice
  codex-vault run --user alice -- resume
  codex-vault run --user alice -- resume --last`);
}

function optionValue(arguments_: string[], option: string): string | undefined {
  const index = arguments_.indexOf(option);
  return index >= 0 ? arguments_[index + 1] : undefined;
}

async function main(): Promise<number> {
  const arguments_ = process.argv.slice(2);
  const store = new VaultStore();

  if (arguments_.length === 0 || arguments_.includes("--help") || arguments_.includes("-h")) {
    usage();
    return 0;
  }

  if (arguments_[0] === "init") {
    await store.initialize();
    console.log("Codex Vault initialized.");
    return 0;
  }

  if (arguments_[0] === "user" && arguments_[1] === "add") {
    const username = arguments_[2];
    if (!username) {
      throw new Error("A username is required");
    }
    const password = await readPassword("New password: ");
    const confirmation = await readPassword("Confirm password: ");
    if (password !== confirmation) {
      throw new Error("Passwords do not match");
    }
    await store.addUser(username, password);
    console.log(`Created encrypted Codex profile for ${username}.`);
    return 0;
  }

  if (arguments_[0] === "user" && arguments_[1] === "list") {
    const users = await store.listUsers();
    console.log(users.length === 0 ? "No users." : users.join("\n"));
    return 0;
  }

  if (arguments_[0] === "run") {
    const separator = arguments_.indexOf("--");
    const launcherArguments = separator >= 0 ? arguments_.slice(1, separator) : arguments_.slice(1);
    const codexArguments = separator >= 0 ? arguments_.slice(separator + 1) : [];
    const username =
      optionValue(launcherArguments, "--user") ??
      process.env.CODEX_VAULT_USER ??
      (await promptLine("Username: "));
    const password = await readPassword();
    return runCodex(store, username, password, codexArguments);
  }

  usage();
  return 2;
}

main()
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`codex-vault: ${message}`);
    process.exitCode = 1;
  });
