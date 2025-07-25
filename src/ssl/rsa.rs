use crate::ssl::bigint::BigUint;
use crate::ssl::crypto::sha256;
use crate::ssl::rng::fill_secure_random;
use crate::ssl::x509::DerReader;
use std::io::{self, Cursor};

/// RSA public key (n, e)
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

/// RSA private key (n, d)
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

fn lcg_next(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*seed >> 24) as u8
}

fn random_nonzero_bytes(len: usize, seed: &mut u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let b = lcg_next(seed);
        if b != 0 {
            out.push(b);
        }
    }
    out
}

fn random_nonzero_bytes_secure(len: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut b = [0u8; 1];
        fill_secure_random(&mut b)?;
        if b[0] != 0 {
            out.push(b[0]);
        }
    }
    Ok(out)
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut accum = 0u32;
    let mut bits = 0u8;
    for c in s.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => {
                bits = (bits / 8) * 8;
                break;
            }
            _ => continue,
        };
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accum >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    decode_base64(&b64)
}

fn parse_private_key_der(der: &[u8]) -> Result<RsaPrivateKey, String> {
    let mut rdr = DerReader::new(Cursor::new(der));
    let seq = rdr.read_object().map_err(|e| e.to_string())?;
    if seq.tag != 0x30 {
        return Err("Expected SEQUENCE".into());
    }
    let mut inner = DerReader::new(Cursor::new(&seq.value));
    // version
    inner.read_object().map_err(|e| e.to_string())?;
    let n_obj = inner.read_object().map_err(|e| e.to_string())?;
    if n_obj.tag != 0x02 {
        return Err("Expected INTEGER".into());
    }
    let n = BigUint::from_bytes_be(&n_obj.value);
    let _e_obj = inner.read_object().map_err(|e| e.to_string())?; // public exponent
    let d_obj = inner.read_object().map_err(|e| e.to_string())?;
    if d_obj.tag != 0x02 {
        return Err("Expected INTEGER".into());
    }
    let d = BigUint::from_bytes_be(&d_obj.value);
    Ok(RsaPrivateKey { n, d })
}

pub fn parse_private_key(data: &[u8]) -> Result<RsaPrivateKey, String> {
    if data.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(data).map_err(|_| "invalid pem")?;
        let der = pem_to_der(s)?;
        parse_private_key_der(&der)
    } else {
        parse_private_key_der(data)
    }
}

impl RsaPublicKey {
    pub fn new(n: BigUint, e: BigUint) -> Self {
        Self { n, e }
    }

    /// Encrypt using PKCS#1 v1.5 padding with caller-provided RNG seed.
    pub fn encrypt_pkcs1_v1_5_with_seed(
        &self,
        msg: &[u8],
        seed: &mut u64,
    ) -> Result<Vec<u8>, String> {
        let k = self.n.to_bytes_be().len();
        if msg.len() > k - 11 {
            return Err("message too long".into());
        }
        let ps = random_nonzero_bytes(k - msg.len() - 3, seed);
        let mut em = Vec::with_capacity(k);
        em.push(0);
        em.push(0x02);
        em.extend_from_slice(&ps);
        em.push(0);
        em.extend_from_slice(msg);
        let m = BigUint::from_bytes_be(&em);
        let c = m.modpow(&self.e, &self.n);
        let mut out = c.to_bytes_be();
        if out.len() < k {
            let mut pad = vec![0u8; k - out.len()];
            pad.extend_from_slice(&out);
            out = pad;
        }
        Ok(out)
    }

    /// Encrypt using PKCS#1 v1.5 padding pulling randomness from the OS.
    pub fn encrypt_pkcs1_v1_5(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.n.to_bytes_be().len();
        if msg.len() > k - 11 {
            return Err("message too long".into());
        }
        let ps = random_nonzero_bytes_secure(k - msg.len() - 3).map_err(|e| e.to_string())?;
        let mut em = Vec::with_capacity(k);
        em.push(0);
        em.push(0x02);
        em.extend_from_slice(&ps);
        em.push(0);
        em.extend_from_slice(msg);
        let m = BigUint::from_bytes_be(&em);
        let c = m.modpow(&self.e, &self.n);
        let mut out = c.to_bytes_be();
        if out.len() < k {
            let mut pad = vec![0u8; k - out.len()];
            pad.extend_from_slice(&out);
            out = pad;
        }
        Ok(out)
    }

    /// Verify RSA PKCS#1 v1.5 signature over SHA-256 digest
    pub fn verify_pkcs1_v1_5_sha256(&self, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        let digest = sha256::hash(msg);
        let k = self.n.to_bytes_be().len();
        if sig.len() != k {
            return Err("invalid signature length".into());
        }
        let s = BigUint::from_bytes_be(sig);
        let m_int = s.modpow(&self.e, &self.n);
        let mut em = m_int.to_bytes_be();
        if em.len() < k {
            let mut pad = vec![0u8; k - em.len()];
            pad.extend_from_slice(&em);
            em = pad;
        }
        let mut i = 0;
        if em[i] == 0 {
            i += 1;
        }
        if em.get(i) != Some(&0x01) {
            return Err("invalid padding".into());
        }
        i += 1;
        while i < em.len() && em[i] == 0xFF {
            i += 1;
        }
        if i >= em.len() || em[i] != 0x00 {
            return Err("invalid padding".into());
        }
        i += 1;
        let mut rdr = DerReader::new(Cursor::new(&em[i..]));
        let seq = rdr.read_object().map_err(|e| e.to_string())?;
        let mut inner = DerReader::new(Cursor::new(&seq.value));
        let _ = inner.read_object().map_err(|e| e.to_string())?;
        let oct = inner.read_object().map_err(|e| e.to_string())?;
        if oct.tag != 0x04 {
            return Err("expected octet string".into());
        }
        Ok(oct.value == digest)
    }
}

impl RsaPrivateKey {
    pub fn new(n: BigUint, d: BigUint) -> Self {
        Self { n, d }
    }

    /// Decrypt PKCS#1 v1.5 padded ciphertext
    pub fn decrypt_pkcs1_v1_5(&self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.n.to_bytes_be().len();
        if ct.len() != k {
            return Err("invalid ciphertext length".into());
        }
        let c = BigUint::from_bytes_be(ct);
        let m = c.modpow(&self.d, &self.n);
        let mut em = m.to_bytes_be();
        if em.len() < k {
            let mut pad = vec![0u8; k - em.len()];
            pad.extend_from_slice(&em);
            em = pad;
        }
        if em.len() < 11 || em[0] != 0 || em[1] != 0x02 {
            return Err("invalid padding".into());
        }
        let mut idx = 2;
        while idx < em.len() && em[idx] != 0 {
            idx += 1;
        }
        if idx == em.len() {
            return Err("invalid padding".into());
        }
        Ok(em[idx + 1..].to_vec())
    }

    /// Sign SHA-256 digest using PKCS#1 v1.5
    pub fn sign_pkcs1_v1_5_sha256(&self, msg: &[u8]) -> Vec<u8> {
        let digest = sha256::hash(msg);
        let mut t = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        t.extend_from_slice(&digest);
        let k = self.n.to_bytes_be().len();
        let mut em = Vec::with_capacity(k);
        em.push(0);
        em.push(0x01);
        em.extend_from_slice(&vec![0xFF; k - t.len() - 3]);
        em.push(0);
        em.extend_from_slice(&t);
        let m = BigUint::from_bytes_be(&em);
        let s = m.modpow(&self.d, &self.n);
        let mut out = s.to_bytes_be();
        if out.len() < k {
            let mut pad = vec![0u8; k - out.len()];
            pad.extend_from_slice(&out);
            out = pad;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn pkcs1_v1_5_roundtrip() {
        let n = hex_to_bytes("ca2468d07c941c8cf7d3b75cb67cff07c7ccb043cb8a5b3dc4d84f98120424ae8230cfb38c86c2add733373a44f41805c802acbe485b57f2e4177c7ef1c91ba3");
        let d = hex_to_bytes("0eece74c55967e112e8f545fa51dcf9adc76d1a0ffdb6467482c8c9bf6e09570a7868f5856cba3eb333d0bcd24e1661b61e478b0d2afbf2bee55aba59c576551");
        let e = BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
        let n = BigUint::from_bytes_be(&n);
        let d = BigUint::from_bytes_be(&d);
        let pubkey = RsaPublicKey::new(n.clone(), e);
        let privkey = RsaPrivateKey::new(n, d);
        let mut seed = 1u64; // deterministic
        let msg = b"hello world".to_vec();
        let ct = pubkey
            .encrypt_pkcs1_v1_5_with_seed(&msg, &mut seed)
            .unwrap();
        let dec = privkey.decrypt_pkcs1_v1_5(&ct).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn encrypt_message_too_long() {
        let n = hex_to_bytes("ca2468d07c941c8cf7d3b75cb67cff07c7ccb043cb8a5b3dc4d84f98120424ae8230cfb38c86c2add733373a44f41805c802acbe485b57f2e4177c7ef1c91ba3");
        let e = BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
        let n = BigUint::from_bytes_be(&n);
        let pubkey = RsaPublicKey::new(n.clone(), e);
        // message longer than modulus size - 11
        let msg = vec![0u8; n.to_bytes_be().len()];
        assert!(pubkey.encrypt_pkcs1_v1_5(&msg).is_err());
    }

    #[test]
    fn sign_and_verify() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDOc6QyXOwbegyKURR5/mWitXTo7lFF8CD51gAcI9+K7uwfbxW1w+s7g6tw4mKh+/3IxTZ4cqz6MOhCJgqmd/JK3y4DJFk/9P0a3nsaibcUM8DEGwd/3kVYzhXzjAyFXVqn0plSUt4M8YbFtfWtJnCDKHAaeDBxe17DoAvYVTXKbQIDAQABAoGBAKV0onRGamc+8kvr3RhEHNpAyNhhHruJTjRMILxst5wWDSDIG0MYKC8DQGPw2xFs7iB4hUYUybKdfZZ9/G0blg6fX0Ql2w1cUAtDzbFl0b+iifJ5cz8aQT1+ZQYAJxM9SdCIYrJmrmRQ1ndczADxyJCaMn+bPYrI9EHRFNHvmuGBAkEA+pxOW2k8YaxSH/OOYYP6GcAJ4zeAfr7UQXhguXrbDCpIMqvC+qm/4ezvcbw/9jko84vwyhNYDIxNjxh+HERcYQJBANLkOe3LT6/Z5zP11i1DVxCaUs2h716Cjm+GTselWEZ4fG3txUOuP/kVd2bHkyEH80cIMVppKeoe8iwxhpp/iY0CQQCRjxHP9Dq2/HCi0ELljtNH+4uCKmrQJw8jWopn10xx+0u0R7EP+ocqPVi2nDDl+D6a4znMKyI5T+NNolPrJKXmECQHQdXRfkvXdhTr95N/esACAQGE9IPfeXgr09AdtC2pvScxBDvj1Jj8ehXiCk+glRy0zs4d+Zz44sg8J5cldWqXECQG0t47qQWbmCEL/WvN5OkoWV9wQS34r28RTeL4Q8HwvbSpJN3oefIsAqUwnp7CCKy20GhRnEv7Hu2gpL9gk/YDc=\n-----END RSA PRIVATE KEY-----";
        let key = parse_private_key(pem.as_bytes()).unwrap();
        let msg = b"test message";
        let sig = key.sign_pkcs1_v1_5_sha256(msg);
        let pubkey = RsaPublicKey::new(key.n.clone(), BigUint::from_bytes_be(&[1, 0, 1]));
        assert!(pubkey.verify_pkcs1_v1_5_sha256(msg, &sig).unwrap());
    }
}
