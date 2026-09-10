use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

const MAGIC: &[u8; 8] = b"CDXVLT02";
const NONCE_SEED_LENGTH: usize = 12;
const FILE_HEADER_LENGTH: usize = MAGIC.len() + NONCE_SEED_LENGTH;
const FRAME_HEADER_LENGTH: usize = 9;
const TAG_LENGTH: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const DATA_FRAME: u8 = 0;
const FINAL_FRAME: u8 = 1;

#[derive(Debug)]
struct IntegrityIoError(&'static str);

impl fmt::Display for IntegrityIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for IntegrityIoError {}

fn io_integrity(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, IntegrityIoError(message))
}

pub(crate) fn map_read_error(error: io::Error) -> VaultError {
    if let Some(integrity) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<IntegrityIoError>())
    {
        return VaultError::Integrity(integrity.0);
    }
    if error.kind() == io::ErrorKind::InvalidData {
        return VaultError::Integrity("encrypted vault or archive data is invalid");
    }
    VaultError::Io(error)
}

fn nonce_bytes(mut seed: [u8; NONCE_SEED_LENGTH], sequence: u32) -> Result<[u8; 12]> {
    let mut carry = u64::from(sequence);
    for byte in seed.iter_mut().rev() {
        let sum = u64::from(*byte) + (carry & 0xff);
        *byte = (sum & 0xff) as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    if carry != 0 {
        return Err(VaultError::Cryptography("vault nonce sequence overflow"));
    }
    Ok(seed)
}

fn frame_header(frame_type: u8, sequence: u32, length: usize) -> Result<[u8; FRAME_HEADER_LENGTH]> {
    let length = u32::try_from(length)
        .map_err(|_| VaultError::Cryptography("vault frame length overflow"))?;
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&sequence.to_be_bytes());
    header[5..9].copy_from_slice(&length.to_be_bytes());
    Ok(header)
}

pub struct VaultWriter<W: Write> {
    inner: Option<W>,
    cipher: Aes256Gcm,
    file_header: [u8; FILE_HEADER_LENGTH],
    nonce_seed: [u8; NONCE_SEED_LENGTH],
    pending: Zeroizing<Vec<u8>>,
    sequence: u32,
    finished: bool,
}

impl<W: Write> VaultWriter<W> {
    pub fn new(mut inner: W, data_key: &[u8; 32]) -> Result<Self> {
        let mut nonce_seed = [0_u8; NONCE_SEED_LENGTH];
        getrandom::fill(&mut nonce_seed)
            .map_err(|_| VaultError::Cryptography("operating-system random source failed"))?;
        let mut file_header = [0_u8; FILE_HEADER_LENGTH];
        file_header[..MAGIC.len()].copy_from_slice(MAGIC);
        file_header[MAGIC.len()..].copy_from_slice(&nonce_seed);
        inner.write_all(&file_header)?;

        Ok(Self {
            inner: Some(inner),
            cipher: Aes256Gcm::new_from_slice(data_key)
                .map_err(|_| VaultError::Cryptography("invalid vault data key"))?,
            file_header,
            nonce_seed,
            pending: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            sequence: 0,
            finished: false,
        })
    }

    pub fn finish(mut self) -> Result<W> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.write_frame(DATA_FRAME, &pending)?;
        }
        self.write_frame(FINAL_FRAME, &[])?;
        self.inner_mut()?.flush()?;
        self.finished = true;
        self.inner
            .take()
            .ok_or(VaultError::Cryptography("vault writer is already finished"))
    }

    fn inner_mut(&mut self) -> Result<&mut W> {
        self.inner
            .as_mut()
            .ok_or(VaultError::Cryptography("vault writer is already finished"))
    }

    fn write_frame(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<()> {
        if self.sequence == u32::MAX {
            return Err(VaultError::Cryptography("vault frame sequence exhausted"));
        }
        let header = frame_header(frame_type, self.sequence, plaintext.len())?;
        let mut associated_data = [0_u8; FILE_HEADER_LENGTH + FRAME_HEADER_LENGTH];
        associated_data[..FILE_HEADER_LENGTH].copy_from_slice(&self.file_header);
        associated_data[FILE_HEADER_LENGTH..].copy_from_slice(&header);
        let nonce_data = nonce_bytes(self.nonce_seed, self.sequence)?;
        let nonce = Nonce::try_from(nonce_data.as_slice())
            .map_err(|_| VaultError::Cryptography("invalid vault nonce"))?;
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| VaultError::Cryptography("vault frame encryption failed"))?;

        let inner = self.inner_mut()?;
        inner.write_all(&header)?;
        inner.write_all(&ciphertext)?;
        self.sequence += 1;
        Ok(())
    }
}

impl<W: Write> Write for VaultWriter<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("vault writer is already finished"));
        }
        let original_length = input.len();

        if !self.pending.is_empty() {
            let needed = CHUNK_SIZE - self.pending.len();
            let take = needed.min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.pending.len() == CHUNK_SIZE {
                let frame = std::mem::take(&mut self.pending);
                self.write_frame(DATA_FRAME, &frame)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                self.pending = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE));
            }
        }

        while input.len() >= CHUNK_SIZE {
            self.write_frame(DATA_FRAME, &input[..CHUNK_SIZE])
                .map_err(|error| io::Error::other(error.to_string()))?;
            input = &input[CHUNK_SIZE..];
        }
        self.pending.extend_from_slice(input);
        Ok(original_length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| io::Error::other("vault writer is already finished"))?
            .flush()
    }
}

pub struct VaultReader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    file_header: [u8; FILE_HEADER_LENGTH],
    nonce_seed: [u8; NONCE_SEED_LENGTH],
    plaintext: Zeroizing<Vec<u8>>,
    plaintext_offset: usize,
    sequence: u32,
    finalized: bool,
}

impl<R: Read> VaultReader<R> {
    pub fn new(mut inner: R, data_key: &[u8; 32]) -> Result<Self> {
        let mut file_header = [0_u8; FILE_HEADER_LENGTH];
        inner
            .read_exact(&mut file_header)
            .map_err(|_| VaultError::Integrity("encrypted vault header is truncated"))?;
        if &file_header[..MAGIC.len()] != MAGIC {
            return Err(VaultError::Integrity("unsupported encrypted vault format"));
        }
        let mut nonce_seed = [0_u8; NONCE_SEED_LENGTH];
        nonce_seed.copy_from_slice(&file_header[MAGIC.len()..]);

        Ok(Self {
            inner,
            cipher: Aes256Gcm::new_from_slice(data_key)
                .map_err(|_| VaultError::Cryptography("invalid vault data key"))?,
            file_header,
            nonce_seed,
            plaintext: Zeroizing::new(Vec::new()),
            plaintext_offset: 0,
            sequence: 0,
            finalized: false,
        })
    }

    pub fn verify_finished(mut self) -> Result<()> {
        io::copy(&mut self, &mut io::sink()).map_err(map_read_error)?;
        if !self.finalized {
            return Err(VaultError::Integrity("encrypted vault is truncated"));
        }
        Ok(())
    }

    fn read_next_frame(&mut self) -> io::Result<()> {
        let mut header = [0_u8; FRAME_HEADER_LENGTH];
        self.inner
            .read_exact(&mut header)
            .map_err(|_| io_integrity("encrypted vault is truncated"))?;
        let frame_type = header[0];
        let sequence = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;

        if sequence != self.sequence {
            return Err(io_integrity("encrypted vault frame order is invalid"));
        }
        if frame_type != DATA_FRAME && frame_type != FINAL_FRAME {
            return Err(io_integrity("encrypted vault frame type is invalid"));
        }
        if length > CHUNK_SIZE || (frame_type == FINAL_FRAME && length != 0) {
            return Err(io_integrity("encrypted vault frame length is invalid"));
        }

        let mut ciphertext = vec![0_u8; length + TAG_LENGTH];
        self.inner
            .read_exact(&mut ciphertext)
            .map_err(|_| io_integrity("encrypted vault is truncated"))?;
        let mut associated_data = [0_u8; FILE_HEADER_LENGTH + FRAME_HEADER_LENGTH];
        associated_data[..FILE_HEADER_LENGTH].copy_from_slice(&self.file_header);
        associated_data[FILE_HEADER_LENGTH..].copy_from_slice(&header);
        let nonce_data = nonce_bytes(self.nonce_seed, sequence)
            .map_err(|_| io_integrity("encrypted vault nonce sequence overflow"))?;
        let nonce = Nonce::try_from(nonce_data.as_slice())
            .map_err(|_| io_integrity("encrypted vault nonce is invalid"))?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| io_integrity("encrypted vault authentication failed"))?;

        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io_integrity("encrypted vault frame sequence overflow"))?;
        if frame_type == FINAL_FRAME {
            let mut trailing = [0_u8; 1];
            if self.inner.read(&mut trailing)? != 0 {
                return Err(io_integrity("encrypted vault has trailing data"));
            }
            self.finalized = true;
            self.plaintext.clear();
        } else {
            self.plaintext = Zeroizing::new(plaintext);
            self.plaintext_offset = 0;
        }
        Ok(())
    }
}

impl<R: Read> Read for VaultReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        while self.plaintext_offset >= self.plaintext.len() && !self.finalized {
            self.read_next_frame()?;
        }
        if self.finalized {
            return Ok(0);
        }

        let remaining = &self.plaintext[self.plaintext_offset..];
        let length = remaining.len().min(output.len());
        output[..length].copy_from_slice(&remaining[..length]);
        self.plaintext_offset += length;
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::{FILE_HEADER_LENGTH, FRAME_HEADER_LENGTH, TAG_LENGTH, VaultReader, VaultWriter};

    fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let mut writer = VaultWriter::new(Vec::new(), key).expect("writer");
        writer.write_all(plaintext).expect("encrypt");
        writer.finish().expect("finish")
    }

    fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        let mut reader = VaultReader::new(Cursor::new(ciphertext), key)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;
        Ok(plaintext)
    }

    #[test]
    fn round_trip_multiple_frames() {
        let key = [7_u8; 32];
        let plaintext = vec![42_u8; 64 * 1024 * 2 + 17];
        let ciphertext = encrypt(&plaintext, &key);
        assert_ne!(ciphertext, plaintext);
        assert_eq!(decrypt(&ciphertext, &key).expect("decrypt"), plaintext);
    }

    #[test]
    fn rejects_tampering_truncation_and_trailing_data() {
        let key = [9_u8; 32];
        let ciphertext = encrypt(b"private Codex session", &key);

        let mut tampered = ciphertext.clone();
        let index = tampered.len() / 2;
        tampered[index] ^= 1;
        assert!(decrypt(&tampered, &key).is_err());
        assert!(decrypt(&ciphertext[..ciphertext.len() - 1], &key).is_err());

        let mut trailing = ciphertext;
        trailing.push(0);
        assert!(decrypt(&trailing, &key).is_err());
    }

    #[test]
    fn rejects_reordered_authenticated_frames() {
        let key = [11_u8; 32];
        let plaintext = vec![42_u8; 64 * 1024 * 2 + 17];
        let ciphertext = encrypt(&plaintext, &key);
        let frames = frame_ranges(&ciphertext);
        assert!(
            frames.len() >= 3,
            "expected two data frames and a final frame"
        );

        let mut reordered = ciphertext[..FILE_HEADER_LENGTH].to_vec();
        reordered.extend_from_slice(&ciphertext[frames[1].clone()]);
        reordered.extend_from_slice(&ciphertext[frames[0].clone()]);
        for frame in &frames[2..] {
            reordered.extend_from_slice(&ciphertext[frame.clone()]);
        }

        let error = decrypt(&reordered, &key).expect_err("reordered frames must fail");
        assert!(error.to_string().contains("frame order is invalid"));
    }

    fn frame_ranges(ciphertext: &[u8]) -> Vec<std::ops::Range<usize>> {
        let mut ranges = Vec::new();
        let mut offset = FILE_HEADER_LENGTH;
        while offset < ciphertext.len() {
            let length_offset = offset + 5;
            let length = u32::from_be_bytes(
                ciphertext[length_offset..length_offset + 4]
                    .try_into()
                    .expect("frame length"),
            ) as usize;
            let end = offset + FRAME_HEADER_LENGTH + length + TAG_LENGTH;
            ranges.push(offset..end);
            offset = end;
        }
        assert_eq!(offset, ciphertext.len());
        ranges
    }
}
