use super::crypto::{hmac, sha256};

/// HKDF implementation using HMAC and SHA-256.
/// Provides extract and expand operations as specified in RFC 5869.
pub struct HkdfSha256;

impl HkdfSha256 {
    /// HKDF-Extract(salt, ikm) -> prk
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        hmac::hmac(sha256::hash, salt, ikm)
    }

    /// HKDF-Expand(prk, info, len) -> okm
    pub fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(len);
        let mut previous: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while okm.len() < len {
            let mut data = Vec::with_capacity(previous.len() + info.len() + 1);
            data.extend_from_slice(&previous);
            data.extend_from_slice(info);
            data.push(counter);
            previous = hmac::hmac(sha256::hash, prk, &data).to_vec();
            okm.extend_from_slice(&previous);
            counter = counter.wrapping_add(1);
        }
        okm.truncate(len);
        okm
    }
}

/// TLS PRF using HMAC and SHA-256 as defined in RFC 5246.
pub struct TlsPrfSha256;

impl TlsPrfSha256 {
    /// Derive `len` bytes using the given `secret`, `label`, and `seed`.
    pub fn derive(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut label_seed = Vec::with_capacity(label.len() + seed.len());
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);
        Self::p_hash(secret, &label_seed, len)
    }

    fn p_hash(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut a = hmac::hmac(sha256::hash, secret, seed).to_vec();
        while out.len() < len {
            let mut input = Vec::with_capacity(a.len() + seed.len());
            input.extend_from_slice(&a);
            input.extend_from_slice(seed);
            let chunk = hmac::hmac(sha256::hash, secret, &input);
            out.extend_from_slice(&chunk);
            a = hmac::hmac(sha256::hash, secret, &a).to_vec();
        }
        out.truncate(len);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{HkdfSha256, TlsPrfSha256};

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let prk = HkdfSha256::extract(&salt, &ikm);
        assert_eq!(hex::encode(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm = HkdfSha256::expand(&prk, &info, 42);
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn tls_prf_simple() {
        let out = TlsPrfSha256::derive(b"secret", b"", b"seed", 10);
        assert_eq!(hex::encode(out), "8e4d932530d765a0aae9");
    }

    #[test]
    fn tls_prf_known_vector() {
        let secret = hex_to_bytes("9bbe436bd24e08313df428278d6ea83f");
        let seed = hex_to_bytes("123456789abcdef0123456789abcdef0");
        let out = TlsPrfSha256::derive(&secret, b"test label", &seed, 100);
        assert_eq!(hex::encode(out), "94f9b4f7c5c7d6d7fe084e6388d5752906be4638d4c914a6c1dc6cedc43dd66400f419a951a0240f5fab4fc38368baa3d26125a70720f4dbdb1e33554ea57d6f169e5b2e48a50940fc57a2c37d0ac72759666b76232e9693e1c423189a03431ab1562de0");
    }
}
