import { randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_KDF_PARAMETERS, deriveKey } from "../crypto/kdf.js";
import { unwrapDataKey, wrapDataKey } from "../crypto/key-wrap.js";
import { ensurePrivateDirectory, MANIFEST_VERSION, runtimeRoot, vaultRoot } from "../config.js";
import { AuthenticationError, VaultError } from "../errors.js";
import type { KdfParameters, UserManifest } from "../types.js";
import { acquireUserLock } from "../runtime/lock.js";
import { sealDirectory, unsealDirectory } from "./archive.js";

const USERNAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function userDirectoryName(username: string): string {
  return username.toLowerCase();
}

function manifestAssociatedData(manifest: Omit<UserManifest, "wrappedDataKey">): Buffer {
  return Buffer.from(
    JSON.stringify({
      context: "codex-vault-key-wrap-v1",
      version: manifest.version,
      id: manifest.id,
      username: manifest.username,
      createdAt: manifest.createdAt,
      kdf: manifest.kdf,
      vaultFormat: manifest.vaultFormat,
    }),
    "utf8",
  );
}

async function writePrivateJson(filePath: string, value: unknown): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  await chmod(filePath, 0o600);
}

export interface UnlockedVault {
  username: string;
  codexHome: string;
  close(): Promise<void>;
}

export class VaultStore {
  constructor(private readonly root = vaultRoot()) {}

  async initialize(): Promise<void> {
    await ensurePrivateDirectory(this.root);
    await ensurePrivateDirectory(this.usersRoot());
  }

  async addUser(username: string, password: string): Promise<void> {
    this.validateUsername(username);
    this.validatePassword(password);
    await this.initialize();

    const userRoot = this.userRoot(username);
    try {
      await lstat(userRoot);
      throw new VaultError(`User already exists: ${username}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }
    const staging = `${userRoot}.creating-${randomUUID()}`;
    await mkdir(staging, { recursive: false, mode: 0o700 });

    const dataKey = randomBytes(32);
    const salt = randomBytes(16);
    const kdf: KdfParameters = {
      ...DEFAULT_KDF_PARAMETERS,
      salt: salt.toString("base64"),
    };
    const wrappingKey = await deriveKey(password, kdf);

    try {
      const manifestHeader: Omit<UserManifest, "wrappedDataKey"> = {
        version: MANIFEST_VERSION,
        id: randomUUID(),
        username,
        createdAt: new Date().toISOString(),
        kdf,
        vaultFormat: "cdxvlt01",
      };
      const manifest: UserManifest = {
        ...manifestHeader,
        wrappedDataKey: wrapDataKey(
          dataKey,
          wrappingKey,
          manifestAssociatedData(manifestHeader),
        ),
      };

      await writePrivateJson(path.join(staging, "manifest.json"), manifest);
      const emptyState = path.join(staging, "empty-state");
      await mkdir(emptyState, { mode: 0o700 });
      await sealDirectory(emptyState, path.join(staging, "state.cvlt"), dataKey);
      await rm(emptyState, { recursive: true, force: true });
      await mkdir(path.dirname(userRoot), { recursive: true, mode: 0o700 });
      await rename(staging, userRoot);
    } catch (error) {
      await rm(staging, { recursive: true, force: true });
      throw error;
    } finally {
      dataKey.fill(0);
      wrappingKey.fill(0);
    }
  }

  async listUsers(): Promise<string[]> {
    await this.initialize();
    const entries = await readdir(this.usersRoot(), { withFileTypes: true });
    const users: string[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.includes(".creating-")) {
        continue;
      }
      try {
        const manifest = await this.readManifest(path.join(this.usersRoot(), entry.name));
        users.push(manifest.username);
      } catch {
        // Ignore incomplete or invalid directories when listing accounts.
      }
    }

    return users.sort((a, b) => a.localeCompare(b));
  }

  async unlock(username: string, password: string): Promise<UnlockedVault> {
    this.validateUsername(username);
    const userRoot = this.userRoot(username);
    let releaseLock: () => Promise<void> = async () => {};
    let runtimeDirectory: string | undefined;
    let dataKey: Buffer | undefined;
    let wrappingKey: Buffer | undefined;

    try {
      const userMetadata = await lstat(userRoot);
      if (!userMetadata.isDirectory() || userMetadata.isSymbolicLink()) {
        throw new AuthenticationError("Invalid username or password");
      }
      releaseLock = await acquireUserLock(path.join(userRoot, "active.lock"));
      const manifest = await this.readManifest(userRoot);
      if (manifest.username.toLowerCase() !== username.toLowerCase()) {
        throw new AuthenticationError("Invalid username or password");
      }

      wrappingKey = await deriveKey(password, manifest.kdf);
      const { wrappedDataKey: _wrappedDataKey, ...manifestHeader } = manifest;
      dataKey = unwrapDataKey(
        manifest.wrappedDataKey,
        wrappingKey,
        manifestAssociatedData(manifestHeader),
      );

      const baseRuntime = await runtimeRoot();
      runtimeDirectory = path.join(baseRuntime, `${manifest.id}-${randomUUID()}`);
      const codexHome = path.join(runtimeDirectory, "codex-home");
      await mkdir(codexHome, { recursive: true, mode: 0o700 });
      await unsealDirectory(path.join(userRoot, "state.cvlt"), codexHome, dataKey);

      let closed = false;
      return {
        username: manifest.username,
        codexHome,
        close: async () => {
          if (closed) {
            return;
          }
          closed = true;
          try {
            await sealDirectory(codexHome, path.join(userRoot, "state.cvlt"), dataKey!);
          } finally {
            await rm(runtimeDirectory!, { recursive: true, force: true });
            dataKey!.fill(0);
            wrappingKey!.fill(0);
            await releaseLock();
          }
        },
      };
    } catch (error) {
      if (runtimeDirectory) {
        await rm(runtimeDirectory, { recursive: true, force: true });
      }
      dataKey?.fill(0);
      wrappingKey?.fill(0);
      await releaseLock();
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new AuthenticationError("Invalid username or password");
      }
      throw error;
    }
  }

  private usersRoot(): string {
    return path.join(this.root, "users");
  }

  private userRoot(username: string): string {
    return path.join(this.usersRoot(), userDirectoryName(username));
  }

  private validateUsername(username: string): void {
    if (!USERNAME_PATTERN.test(username)) {
      throw new VaultError(
        "Username must be 1-64 characters and contain only letters, numbers, dot, underscore, or hyphen",
      );
    }
  }

  private validatePassword(password: string): void {
    if (password.length < 12) {
      throw new VaultError("Password must contain at least 12 characters");
    }
  }

  private async readManifest(userRoot: string): Promise<UserManifest> {
    const manifestPath = path.join(userRoot, "manifest.json");
    const metadata = await lstat(manifestPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 64 * 1024) {
      throw new VaultError("Invalid user manifest file");
    }
    const parsed = JSON.parse(await readFile(manifestPath, "utf8")) as Partial<UserManifest> | null;
    if (
      !parsed ||
      parsed.version !== MANIFEST_VERSION ||
      typeof parsed.id !== "string" ||
      !UUID_PATTERN.test(parsed.id) ||
      typeof parsed.username !== "string" ||
      !USERNAME_PATTERN.test(parsed.username) ||
      typeof parsed.createdAt !== "string" ||
      !Number.isFinite(Date.parse(parsed.createdAt)) ||
      parsed.kdf?.algorithm !== "argon2id" ||
      typeof parsed.kdf.salt !== "string" ||
      typeof parsed.kdf.memoryCostKiB !== "number" ||
      typeof parsed.kdf.timeCost !== "number" ||
      typeof parsed.kdf.parallelism !== "number" ||
      typeof parsed.kdf.outputLength !== "number" ||
      parsed.wrappedDataKey?.algorithm !== "aes-256-gcm" ||
      typeof parsed.wrappedDataKey.iv !== "string" ||
      typeof parsed.wrappedDataKey.ciphertext !== "string" ||
      typeof parsed.wrappedDataKey.authenticationTag !== "string" ||
      parsed.vaultFormat !== "cdxvlt01"
    ) {
      throw new VaultError("Unsupported or invalid user manifest");
    }
    return parsed as UserManifest;
  }
}
