import { hashRaw } from "@node-rs/argon2";
import type { KdfParameters } from "../types.js";
import { VaultError } from "../errors.js";

export const DEFAULT_KDF_PARAMETERS = {
  algorithm: "argon2id",
  memoryCostKiB: 64 * 1024,
  timeCost: 3,
  parallelism: 1,
  outputLength: 32,
} as const;

export async function deriveKey(password: string, parameters: KdfParameters): Promise<Buffer> {
  const salt = Buffer.from(parameters.salt, "base64");
  if (
    parameters.algorithm !== "argon2id" ||
    salt.length !== 16 ||
    parameters.memoryCostKiB < 16 * 1024 ||
    parameters.memoryCostKiB > 256 * 1024 ||
    parameters.timeCost < 1 ||
    parameters.timeCost > 10 ||
    parameters.parallelism < 1 ||
    parameters.parallelism > 16 ||
    parameters.outputLength !== 32
  ) {
    throw new VaultError("Invalid Argon2id parameters in user manifest");
  }

  const passwordBytes = Buffer.from(password, "utf8");
  try {
    const derived = await hashRaw(passwordBytes, {
      algorithm: 2,
      salt,
      memoryCost: parameters.memoryCostKiB,
      timeCost: parameters.timeCost,
      parallelism: parameters.parallelism,
      outputLen: parameters.outputLength,
    });

    return Buffer.from(derived);
  } finally {
    passwordBytes.fill(0);
  }
}
