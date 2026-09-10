import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Transform, type TransformCallback } from "node:stream";
import { IntegrityError } from "../errors.js";

const MAGIC = Buffer.from("CDXVLT01", "ascii");
const NONCE_PREFIX_LENGTH = 8;
const FRAME_HEADER_LENGTH = 9;
const TAG_LENGTH = 16;
const DEFAULT_CHUNK_SIZE = 64 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024;
const DATA_FRAME = 0;
const FINAL_FRAME = 1;

function makeNonce(prefix: Buffer, sequence: number): Buffer {
  const nonce = Buffer.alloc(12);
  prefix.copy(nonce, 0);
  nonce.writeUInt32BE(sequence, NONCE_PREFIX_LENGTH);
  return nonce;
}

function makeFrameHeader(type: number, sequence: number, length: number): Buffer {
  const header = Buffer.alloc(FRAME_HEADER_LENGTH);
  header.writeUInt8(type, 0);
  header.writeUInt32BE(sequence, 1);
  header.writeUInt32BE(length, 5);
  return header;
}

function encryptFrame(
  plaintext: Buffer,
  type: number,
  sequence: number,
  dataKey: Buffer,
  fileHeader: Buffer,
  noncePrefix: Buffer,
): Buffer {
  const frameHeader = makeFrameHeader(type, sequence, plaintext.length);
  const cipher = createCipheriv("aes-256-gcm", dataKey, makeNonce(noncePrefix, sequence));
  cipher.setAAD(Buffer.concat([fileHeader, frameHeader]));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([frameHeader, ciphertext, cipher.getAuthTag()]);
}

export class VaultEncryptTransform extends Transform {
  private readonly fileHeader: Buffer;
  private readonly noncePrefix: Buffer;
  private pending = Buffer.alloc(0);
  private sequence = 0;

  constructor(
    private readonly dataKey: Buffer,
    private readonly chunkSize = DEFAULT_CHUNK_SIZE,
  ) {
    super();
    if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
      throw new RangeError(`Vault chunk size must be between 1 and ${MAX_CHUNK_SIZE} bytes`);
    }
    this.noncePrefix = randomBytes(NONCE_PREFIX_LENGTH);
    this.fileHeader = Buffer.concat([MAGIC, this.noncePrefix]);
    this.push(this.fileHeader);
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    try {
      this.pending = Buffer.concat([this.pending, chunk]);
      while (this.pending.length >= this.chunkSize) {
        const plaintext = this.pending.subarray(0, this.chunkSize);
        this.pending = this.pending.subarray(this.chunkSize);
        this.push(
          encryptFrame(
            plaintext,
            DATA_FRAME,
            this.sequence++,
            this.dataKey,
            this.fileHeader,
            this.noncePrefix,
          ),
        );
      }
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      if (this.pending.length > 0) {
        this.push(
          encryptFrame(
            this.pending,
            DATA_FRAME,
            this.sequence++,
            this.dataKey,
            this.fileHeader,
            this.noncePrefix,
          ),
        );
      }
      this.push(
        encryptFrame(
          Buffer.alloc(0),
          FINAL_FRAME,
          this.sequence,
          this.dataKey,
          this.fileHeader,
          this.noncePrefix,
        ),
      );
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }
}

export class VaultDecryptTransform extends Transform {
  private pending = Buffer.alloc(0);
  private fileHeader?: Buffer;
  private noncePrefix?: Buffer;
  private sequence = 0;
  private finalized = false;

  constructor(private readonly dataKey: Buffer) {
    super();
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    try {
      if (this.finalized) {
        throw new IntegrityError("Encrypted vault has trailing data");
      }
      this.pending = Buffer.concat([this.pending, chunk]);
      this.processFrames();
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      this.processFrames();
      if (!this.finalized || this.pending.length !== 0) {
        throw new IntegrityError("Encrypted vault is truncated");
      }
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  private processFrames(): void {
    if (!this.fileHeader) {
      if (this.pending.length < MAGIC.length + NONCE_PREFIX_LENGTH) {
        return;
      }
      this.fileHeader = this.pending.subarray(0, MAGIC.length + NONCE_PREFIX_LENGTH);
      if (!this.fileHeader.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new IntegrityError("Unsupported encrypted vault format");
      }
      this.noncePrefix = this.fileHeader.subarray(MAGIC.length);
      this.pending = this.pending.subarray(this.fileHeader.length);
    }

    while (!this.finalized && this.pending.length >= FRAME_HEADER_LENGTH) {
      const frameHeader = this.pending.subarray(0, FRAME_HEADER_LENGTH);
      const type = frameHeader.readUInt8(0);
      const sequence = frameHeader.readUInt32BE(1);
      const length = frameHeader.readUInt32BE(5);
      const totalLength = FRAME_HEADER_LENGTH + length + TAG_LENGTH;

      if (length > MAX_CHUNK_SIZE) {
        throw new IntegrityError("Encrypted vault frame exceeds the size limit");
      }

      if (this.pending.length < totalLength) {
        return;
      }
      if (sequence !== this.sequence) {
        throw new IntegrityError("Encrypted vault frame order is invalid");
      }
      if (type !== DATA_FRAME && type !== FINAL_FRAME) {
        throw new IntegrityError("Encrypted vault contains an unknown frame type");
      }
      if (type === FINAL_FRAME && length !== 0) {
        throw new IntegrityError("Encrypted vault final frame is invalid");
      }

      const ciphertext = this.pending.subarray(FRAME_HEADER_LENGTH, FRAME_HEADER_LENGTH + length);
      const tag = this.pending.subarray(FRAME_HEADER_LENGTH + length, totalLength);

      try {
        const decipher = createDecipheriv(
          "aes-256-gcm",
          this.dataKey,
          makeNonce(this.noncePrefix!, sequence),
        );
        decipher.setAAD(Buffer.concat([this.fileHeader!, frameHeader]));
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        if (type === DATA_FRAME) {
          this.push(plaintext);
        } else {
          this.finalized = true;
        }
      } catch (error) {
        throw new IntegrityError("Encrypted vault authentication failed", { cause: error });
      }

      this.pending = this.pending.subarray(totalLength);
      this.sequence += 1;
    }

    if (this.finalized && this.pending.length > 0) {
      throw new IntegrityError("Encrypted vault has trailing data");
    }
  }
}
