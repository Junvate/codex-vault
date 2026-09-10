import { spawn } from "node:child_process";
import { VaultStore } from "../vault/store.js";

function forwardSignal(child: ReturnType<typeof spawn>, signal: NodeJS.Signals): void {
  if (!child.killed) {
    child.kill(signal);
  }
}

export async function runCodex(
  store: VaultStore,
  username: string,
  password: string,
  codexArguments: string[],
): Promise<number> {
  const unlocked = await store.unlock(username, password);
  const executable = process.env.CODEX_VAULT_REAL_CODEX ?? "codex";
  const child = spawn(executable, codexArguments, {
    env: {
      ...process.env,
      CODEX_HOME: unlocked.codexHome,
      CODEX_VAULT_ACTIVE_USER: unlocked.username,
    },
    stdio: "inherit",
  });

  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    const handler = (): void => forwardSignal(child, signal);
    handlers.set(signal, handler);
    process.on(signal, handler);
  }

  try {
    return await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => {
        if (signal) {
          resolve(1);
          return;
        }
        resolve(code ?? 1);
      });
    });
  } finally {
    for (const [signal, handler] of handlers) {
      process.off(signal, handler);
    }
    await unlocked.close();
  }
}
