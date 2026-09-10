import { homedir, tmpdir } from "node:os";
import { access, chmod, constants, lstat, mkdir } from "node:fs/promises";
import path from "node:path";

export const APP_NAME = "codex-vault";
export const MANIFEST_VERSION = 1;

export function vaultRoot(): string {
  return process.env.CODEX_VAULT_HOME ?? path.join(homedir(), ".codex-vault");
}

export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Private path is not a real directory: ${directory}`);
  }
  await chmod(directory, 0o700);
}

export async function runtimeRoot(): Promise<string> {
  const candidates = [
    process.env.CODEX_VAULT_RUNTIME_DIR,
    process.env.XDG_RUNTIME_DIR
      ? path.join(process.env.XDG_RUNTIME_DIR, APP_NAME)
      : undefined,
    process.platform === "linux" ? `/dev/shm/${APP_NAME}-${process.getuid?.() ?? "user"}` : undefined,
    path.join(tmpdir(), `${APP_NAME}-${process.getuid?.() ?? "user"}`),
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    try {
      await ensurePrivateDirectory(candidate);
      await access(candidate, constants.R_OK | constants.W_OK | constants.X_OK);
      return candidate;
    } catch {
      // Try the next runtime location.
    }
  }

  throw new Error("No private writable runtime directory is available");
}
