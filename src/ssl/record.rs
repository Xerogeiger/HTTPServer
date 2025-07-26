use super::aes::AesCipher;
use super::crypto::{hmac, sha256};
use super::rng::secure_random_bytes;

pub type ContentType = u8;

/// TLS version constant for TLS 1.2 used by the examples.
pub const TLS_VERSION_1_2: u16 = 0x0303;

#[derive(Debug)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None; // Not enough data for header
        }
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);
        Some(RecordHeader {
            content_type,
            version,
            length,
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = self.content_type;
        bytes[1..3].copy_from_slice(&self.version.to_be_bytes());
        bytes[3..5].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }
}

/// A parsed TLS record containing the header and decrypted payload.
#[derive(Debug)]
pub struct TlsRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

/// Encrypt a plaintext `payload` and build a TLS record.
pub fn encrypt_record(
    content_type: ContentType,
    payload: &[u8],
    cipher: &AesCipher,
    mac_key: &[u8],
    seq: u64,
) -> Vec<u8> {
    // HMAC over seq_num || header || payload as in TLS 1.2
    let mut mac_input = Vec::with_capacity(8 + 5 + payload.len());
    mac_input.extend_from_slice(&seq.to_be_bytes());
    mac_input.push(content_type);
    mac_input.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
    mac_input.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(payload);
    let mac = hmac::hmac(sha256::hash, mac_key, &mac_input);
    let mut plain = Vec::with_capacity(payload.len() + mac.len());
    plain.extend_from_slice(payload);
    plain.extend_from_slice(&mac);
    // Random IV for each record
    let iv_vec = secure_random_bytes(16).expect("failed to get random iv");
    let iv: [u8; 16] = iv_vec[..].try_into().unwrap();
    let encrypted = cipher.encrypt_cbc(&plain, &iv);
    let header = RecordHeader {
        content_type,
        version: TLS_VERSION_1_2,
        length: (iv.len() + encrypted.len()) as u16,
    };
    let mut out = Vec::new();
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted);
    out
}

/// Decrypt a record payload and verify its MAC.
pub fn decrypt_record(
    header: &RecordHeader,
    data: &[u8],
    cipher: &AesCipher,
    mac_key: &[u8],
    seq: u64,
) -> Option<TlsRecord> {
    if data.len() < 16 {
        return None;
    }
    let iv: [u8; 16] = data[..16].try_into().unwrap();
    let decrypted = cipher.decrypt_cbc(&data[16..], &iv)?;
    if decrypted.len() < 32 {
        return None;
    }
    let mac_start = decrypted.len() - 32;
    let payload = &decrypted[..mac_start];
    let mac = &decrypted[mac_start..];
    let mut mac_input = Vec::with_capacity(8 + 5 + payload.len());
    mac_input.extend_from_slice(&seq.to_be_bytes());
    mac_input.push(header.content_type);
    mac_input.extend_from_slice(&header.version.to_be_bytes());
    mac_input.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(payload);
    let expected = hmac::hmac(sha256::hash, mac_key, &mac_input);
    if mac != expected {
        return None;
    }
    Some(TlsRecord {
        header: RecordHeader {
            content_type: header.content_type,
            version: header.version,
            length: payload.len() as u16,
        },
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssl::aes::AesCipher;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key = [0u8; 16];
        let cipher = AesCipher::new_128(&key);
        let mac_key = b"mac-key".to_vec();
        let msg = b"hello world";
        let enc = encrypt_record(23, msg, &cipher, &mac_key, 0);
        let header = RecordHeader::parse(&enc[..5]).unwrap();
        let body = &enc[5..];
        let dec = decrypt_record(&header, body, &cipher, &mac_key, 0).unwrap();
        assert_eq!(dec.payload, msg);
    }

    #[test]
    fn bad_mac_fails() {
        let key = [0u8; 16];
        let cipher = AesCipher::new_128(&key);
        let mac_key = b"mac-key".to_vec();
        let msg = b"hello";
        let mut enc = encrypt_record(22, msg, &cipher, &mac_key, 0);
        // Flip a byte in ciphertext
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        let header = RecordHeader::parse(&enc[..5]).unwrap();
        let body = &enc[5..];
        assert!(decrypt_record(&header, body, &cipher, &mac_key, 0).is_none());
    }
}
