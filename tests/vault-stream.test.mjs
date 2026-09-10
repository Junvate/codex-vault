import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import test from "node:test";
import { VaultDecryptTransform, VaultEncryptTransform } from "../dist/crypto/vault-stream.js";

function collector(chunks) {
  return new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
}

async function collectThrough(source, transform) {
  const chunks = [];
  await pipeline(source, transform, collector(chunks));
  return Buffer.concat(chunks);
}

async function encrypt(plaintext, key) {
  return collectThrough(Readable.from([plaintext]), new VaultEncryptTransform(key, 31));
}

async function decrypt(ciphertext, key) {
  return collectThrough(Readable.from([ciphertext]), new VaultDecryptTransform(key));
}

test("encrypted vault streams round trip across multiple frames", async () => {
  const key = randomBytes(32);
  const plaintext = randomBytes(1024 * 3 + 17);
  const ciphertext = await encrypt(plaintext, key);

  assert.notDeepEqual(ciphertext, plaintext);
  assert.deepEqual(await decrypt(ciphertext, key), plaintext);
});

test("encrypted vault rejects tampering", async () => {
  const key = randomBytes(32);
  const ciphertext = await encrypt(Buffer.from("private Codex session"), key);
  ciphertext[Math.floor(ciphertext.length / 2)] ^= 0x01;

  await assert.rejects(() => decrypt(ciphertext, key), /authentication failed|integrity/i);
});

test("encrypted vault rejects truncation and trailing data", async () => {
  const key = randomBytes(32);
  const ciphertext = await encrypt(Buffer.from("private Codex session"), key);

  await assert.rejects(() => decrypt(ciphertext.subarray(0, -1), key), /truncated|integrity/i);
  await assert.rejects(
    () => decrypt(Buffer.concat([ciphertext, Buffer.from([0])]), key),
    /trailing data|integrity/i,
  );
});
