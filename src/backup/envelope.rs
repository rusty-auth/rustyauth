//! AES-256-GCM backup envelope sealing and unsealing: compact-binary encode,
//! compress, then encrypt with the versioned header authenticated as AAD.

use std::io::{Cursor, Read};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Generate, Nonce, Payload},
};
use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::config::KeyRing;

use super::snapshot::BackupSnapshot;

const MAGIC_V3: &[u8; 8] = b"RAUTHBK3";
const MAGIC_V2: &[u8; 8] = b"RAUTHBK2";
const LEGACY_MAGIC: &[u8; 8] = b"PAUTHBK1";
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn encode_snapshot(keys: &KeyRing, snapshot: &BackupSnapshot) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(snapshot.encode_binary_v3()?);
    if plaintext.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("backup snapshot exceeds the 512 MiB plaintext safety limit");
    }
    let compressed = zstd::stream::encode_all(Cursor::new(plaintext.as_slice()), 3)
        .context("compress backup snapshot");
    let compressed = Zeroizing::new(compressed?);
    encrypt_envelope(keys, MAGIC_V3, &compressed)
}

pub(super) fn decode_snapshot(keys: &KeyRing, envelope: &[u8]) -> Result<BackupSnapshot> {
    let binary_v3 = envelope.starts_with(MAGIC_V3);
    let compressed = Zeroizing::new(decrypt_envelope(keys, envelope)?);
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed.as_slice()))
        .context("open compressed backup snapshot")?;
    let mut limited = decoder.take(MAX_SNAPSHOT_BYTES + 1);
    let mut plaintext = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut plaintext)
        .context("decompress backup snapshot")?;
    drop(limited);
    if plaintext.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("decompressed backup exceeds the 512 MiB safety limit");
    }
    if binary_v3 {
        BackupSnapshot::decode_binary_v3(&plaintext)
    } else {
        serde_json::from_slice(&plaintext).context("decode legacy JSON backup snapshot")
    }
}

fn encrypt_envelope(keys: &KeyRing, magic: &[u8; 8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key_id, key) = keys.active();
    if key_id.len() > u8::MAX as usize {
        bail!("backup encryption key id is too long");
    }
    let nonce = Nonce::<Aes256Gcm>::generate();
    let mut header = Vec::with_capacity(magic.len() + 1 + key_id.len() + nonce.len());
    header.extend_from_slice(magic);
    header.push(key_id.len() as u8);
    header.extend_from_slice(key_id.as_bytes());
    header.extend_from_slice(&nonce);
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt auth backup"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn decrypt_envelope(keys: &KeyRing, envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.starts_with(LEGACY_MAGIC) {
        bail!("legacy PAUTHBK1 payloads predate restorable snapshots and cannot be restored");
    }
    if !supported_magic(envelope) || envelope.len() < MAGIC_V3.len() + 1 + 12 + 16 {
        bail!("backup envelope is truncated or has an unsupported format");
    }
    let key_id = envelope_key_id(envelope)?;
    let key_id_start = MAGIC_V3.len() + 1;
    let nonce_start = key_id_start.saturating_add(key_id.len());
    let ciphertext_start = nonce_start.saturating_add(12);
    let key = keys.get(key_id).with_context(|| {
        format!(
            "backup requires encryption key {key_id}; retain it in AUTH_BACKUP_PREVIOUS_KEYS_HEX"
        )
    })?;
    let nonce = &envelope[nonce_start..ciphertext_start];
    let nonce: [u8; 12] = nonce.try_into().expect("12-byte nonce slice");
    let nonce = Nonce::<Aes256Gcm>::from(nonce);
    let header = &envelope[..ciphertext_start];
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope[ciphertext_start..],
                aad: header,
            },
        )
        .map_err(|_| anyhow::anyhow!("backup authentication failed"))
}

pub(super) fn envelope_key_id(envelope: &[u8]) -> Result<&str> {
    if envelope.starts_with(LEGACY_MAGIC) {
        bail!("legacy PAUTHBK1 payloads predate restorable snapshots and cannot be restored");
    }
    if !supported_magic(envelope) || envelope.len() < MAGIC_V3.len() + 1 + 12 + 16 {
        bail!("backup envelope is truncated or has an unsupported format");
    }
    let key_id_length = envelope[MAGIC_V3.len()] as usize;
    let key_id_start = MAGIC_V3.len() + 1;
    let nonce_start = key_id_start.saturating_add(key_id_length);
    let ciphertext_start = nonce_start.saturating_add(12);
    if key_id_length == 0 || ciphertext_start.saturating_add(16) > envelope.len() {
        bail!("backup envelope header is malformed");
    }
    std::str::from_utf8(&envelope[key_id_start..nonce_start])
        .context("backup encryption key id is not UTF-8")
}

pub(super) fn envelope_format_version(envelope: &[u8]) -> Result<u8> {
    if envelope.starts_with(MAGIC_V3) {
        return Ok(3);
    }
    if envelope.starts_with(MAGIC_V2) {
        return Ok(2);
    }
    if envelope.starts_with(LEGACY_MAGIC) {
        bail!("legacy PAUTHBK1 payloads predate restorable snapshots and cannot be restored");
    }
    bail!("backup envelope has an unsupported format")
}

fn supported_magic(envelope: &[u8]) -> bool {
    envelope.starts_with(MAGIC_V3) || envelope.starts_with(MAGIC_V2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::snapshot::minimal_snapshot;

    #[test]
    fn backup_envelope_round_trips_and_authenticates_header() {
        let keys = KeyRing::new("backup", [7; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&keys);
        let one = encode_snapshot(&keys, &snapshot).unwrap();
        let two = encode_snapshot(&keys, &snapshot).unwrap();
        assert!(one.starts_with(MAGIC_V3));
        assert_ne!(one, two);
        assert_eq!(decode_snapshot(&keys, &one).unwrap(), snapshot);

        let mut tampered = one;
        tampered[MAGIC_V3.len() + 2] ^= 1;
        assert!(decode_snapshot(&keys, &tampered).is_err());
    }

    #[test]
    fn backup_key_rollover_keeps_old_snapshots_readable() {
        let old = KeyRing::new("backup", [8; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&old);
        let envelope = encode_snapshot(&old, &snapshot).unwrap();
        let rolled = KeyRing::new("backup", [9; 32], vec![[8; 32]]).unwrap();
        assert_eq!(decode_snapshot(&rolled, &envelope).unwrap(), snapshot);
        let without_old = KeyRing::new("backup", [9; 32], Vec::new()).unwrap();
        assert!(decode_snapshot(&without_old, &envelope).is_err());
    }

    #[test]
    fn malformed_and_truncated_envelopes_fail_closed() {
        let keys = KeyRing::new("backup", [10; 32], Vec::new()).unwrap();
        for input in [Vec::new(), MAGIC_V2.to_vec(), LEGACY_MAGIC.to_vec()] {
            assert!(decode_snapshot(&keys, &input).is_err());
        }
        let snapshot = minimal_snapshot(&keys);
        let mut envelope = encode_snapshot(&keys, &snapshot).unwrap();
        envelope.truncate(envelope.len() - 1);
        assert!(decode_snapshot(&keys, &envelope).is_err());
    }

    #[test]
    fn version_two_json_envelopes_remain_restorable() {
        let keys = KeyRing::new("backup", [12; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&keys);
        let plaintext = Zeroizing::new(serde_json::to_vec(&snapshot).unwrap());
        let compressed =
            Zeroizing::new(zstd::stream::encode_all(Cursor::new(plaintext.as_slice()), 3).unwrap());
        let envelope = encrypt_envelope(&keys, MAGIC_V2, &compressed).unwrap();
        assert_eq!(decode_snapshot(&keys, &envelope).unwrap(), snapshot);
        assert!(encode_snapshot(&keys, &snapshot).unwrap().len() < envelope.len());
    }
}
