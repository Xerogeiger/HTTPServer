use crate::ssl::bigint::BigUint;
use crate::ssl::rng::{fill_secure_random};
use std::io;

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
        if b != 0 { out.push(b); }
    }
    out
}

fn random_nonzero_bytes_secure(len: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut b = [0u8; 1];
        fill_secure_random(&mut b)?;
        if b[0] != 0 { out.push(b[0]); }
    }
    Ok(out)
}

impl RsaPublicKey {
    pub fn new(n: BigUint, e: BigUint) -> Self { Self { n, e } }

    /// Encrypt using PKCS#1 v1.5 padding with caller-provided RNG seed.
    pub fn encrypt_pkcs1_v1_5_with_seed(&self, msg: &[u8], seed: &mut u64) -> Result<Vec<u8>, String> {
        let k = self.n.to_bytes_be().len();
        if msg.len() > k - 11 { return Err("message too long".into()); }
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
        if msg.len() > k - 11 { return Err("message too long".into()); }
        let ps = random_nonzero_bytes_secure(k - msg.len() - 3)
            .map_err(|e| e.to_string())?;
        let mut em = Vec::with_capacity(k);
        em.push(0);
        em.push(0x02);
        em.extend_from_slice(&ps);
        em.push(0);
        em.extend_from_slice(msg);
        let m = BigUint::from_bytes_be(&em);
        let c = m.modpow(&self.e, &self.n);
        let mut out = c.to_bytes_be();
        if out.len() < k { let mut pad = vec![0u8; k - out.len()]; pad.extend_from_slice(&out); out = pad; }
        Ok(out)
    }
}

impl RsaPrivateKey {
    pub fn new(n: BigUint, d: BigUint) -> Self { Self { n, d } }

    /// Decrypt PKCS#1 v1.5 padded ciphertext
    pub fn decrypt_pkcs1_v1_5(&self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.n.to_bytes_be().len();
        if ct.len() != k { return Err("invalid ciphertext length".into()); }
        let c = BigUint::from_bytes_be(ct);
        let m = c.modpow(&self.d, &self.n);
        let mut em = m.to_bytes_be();
        if em.len() < k {
            let mut pad = vec![0u8; k - em.len()];
            pad.extend_from_slice(&em);
            em = pad;
        }
        if em.len() < 11 || em[0] != 0 || em[1] != 0x02 { return Err("invalid padding".into()); }
        let mut idx = 2;
        while idx < em.len() && em[idx] != 0 { idx += 1; }
        if idx == em.len() { return Err("invalid padding".into()); }
        Ok(em[idx+1..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()
    }

    #[test]
    fn pkcs1_v1_5_roundtrip() {
        let n = hex_to_bytes("ca2468d07c941c8cf7d3b75cb67cff07c7ccb043cb8a5b3dc4d84f98120424ae8230cfb38c86c2add733373a44f41805c802acbe485b57f2e4177c7ef1c91ba3");
        let d = hex_to_bytes("0eece74c55967e112e8f545fa51dcf9adc76d1a0ffdb6467482c8c9bf6e09570a7868f5856cba3eb333d0bcd24e1661b61e478b0d2afbf2bee55aba59c576551");
        let e = BigUint::from_bytes_be(&[0x01,0x00,0x01]);
        let n = BigUint::from_bytes_be(&n);
        let d = BigUint::from_bytes_be(&d);
        let pubkey = RsaPublicKey::new(n.clone(), e);
        let privkey = RsaPrivateKey::new(n, d);
        let mut seed = 1u64; // deterministic
        let msg = b"hello world".to_vec();
        let ct = pubkey.encrypt_pkcs1_v1_5_with_seed(&msg, &mut seed).unwrap();
        let dec = privkey.decrypt_pkcs1_v1_5(&ct).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn encrypt_message_too_long() {
        let n = hex_to_bytes("ca2468d07c941c8cf7d3b75cb67cff07c7ccb043cb8a5b3dc4d84f98120424ae8230cfb38c86c2add733373a44f41805c802acbe485b57f2e4177c7ef1c91ba3");
        let e = BigUint::from_bytes_be(&[0x01,0x00,0x01]);
        let n = BigUint::from_bytes_be(&n);
        let pubkey = RsaPublicKey::new(n.clone(), e);
        // message longer than modulus size - 11
        let msg = vec![0u8; n.to_bytes_be().len()];
        assert!(pubkey.encrypt_pkcs1_v1_5(&msg).is_err());
    }
}
