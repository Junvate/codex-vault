export interface KdfParameters {
  algorithm: "argon2id";
  salt: string;
  memoryCostKiB: number;
  timeCost: number;
  parallelism: number;
  outputLength: number;
}

export interface WrappedKey {
  algorithm: "aes-256-gcm";
  iv: string;
  ciphertext: string;
  authenticationTag: string;
}

export interface UserManifest {
  version: 1;
  id: string;
  username: string;
  createdAt: string;
  kdf: KdfParameters;
  wrappedDataKey: WrappedKey;
  vaultFormat: "cdxvlt01";
}
