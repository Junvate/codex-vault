import { createReadStream, createWriteStream } from "node:fs";
import { chmod, open, rename, rm } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import * as tar from "tar";
import { VaultDecryptTransform, VaultEncryptTransform } from "../crypto/vault-stream.js";
import { IntegrityError } from "../errors.js";

function isSafeArchivePath(entryPath: string): boolean {
  if (path.isAbsolute(entryPath)) {
    return false;
  }

  return !entryPath.split(/[\\/]/).includes("..");
}

export async function sealDirectory(
  directory: string,
  destination: string,
  dataKey: Buffer,
): Promise<void> {
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  await rm(temporary, { force: true });

  try {
    await pipeline(
      tar.c({ cwd: directory, portable: true, noMtime: true }, ["."]),
      new VaultEncryptTransform(dataKey),
      createWriteStream(temporary, { flags: "wx", mode: 0o600 }),
    );
    await chmod(temporary, 0o600);
    const handle = await open(temporary, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

export async function unsealDirectory(
  source: string,
  destination: string,
  dataKey: Buffer,
): Promise<void> {
  try {
    await pipeline(
      createReadStream(source),
      new VaultDecryptTransform(dataKey),
      tar.x({
        cwd: destination,
        preservePaths: false,
        strict: true,
        filter: (entryPath, entry) => {
          if (!isSafeArchivePath(entryPath)) {
            return false;
          }
          if ("type" in entry) {
            return entry.type !== "SymbolicLink" && entry.type !== "Link";
          }
          return !entry.isSymbolicLink();
        },
      }),
    );
  } catch (error) {
    if (error instanceof IntegrityError) {
      throw error;
    }
    throw new IntegrityError("Unable to extract encrypted Codex state", { cause: error });
  }
}
