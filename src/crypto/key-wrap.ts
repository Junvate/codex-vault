import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { AuthenticationError } from "../errors.js";
import type { WrappedKey } from "../types.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function wrapDataKey(
  dataKey: Buffer,
  wrappingKey: Buffer,
  associatedData: Buffer,
): WrappedKey {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, wrappingKey, iv);
  cipher.setAAD(associatedData);
  const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);

  return {
    algorithm: ALGORITHM,
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authenticationTag: cipher.getAuthTag().toString("base64"),
  };
}

export function unwrapDataKey(
  wrapped: WrappedKey,
  wrappingKey: Buffer,
  associatedData: Buffer,
): Buffer {
  try {
    const decipher = createDecipheriv(
      ALGORITHM,
      wrappingKey,
      Buffer.from(wrapped.iv, "base64"),
    );
    decipher.setAAD(associatedData);
    decipher.setAuthTag(Buffer.from(wrapped.authenticationTag, "base64"));
    const dataKey = Buffer.concat([
      decipher.update(Buffer.from(wrapped.ciphertext, "base64")),
      decipher.final(),
    ]);
    if (dataKey.length !== 32) {
      throw new Error("Invalid data key length");
    }
    return dataKey;
  } catch (error) {
    throw new AuthenticationError("Invalid username or password", { cause: error });
  }
}
