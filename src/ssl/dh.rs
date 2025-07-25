use crate::ssl::bigint::BigUint;
use crate::ssl::rng::{secure_random_bytes};
use std::io;

/// Simple Diffie-Hellman key exchange over a prime field.
/// Uses `BigUint` for arithmetic. Not cryptographically secure but
/// sufficient for demonstration/testing purposes.
#[derive(Clone)]
pub struct DiffieHellman {
    pub p: BigUint, // prime modulus
    pub g: BigUint, // generator
}

impl DiffieHellman {
    /// Create a new Diffie-Hellman context with parameters `(p, g)`.
    pub fn new(p: BigUint, g: BigUint) -> Self { Self { p, g } }

    /// Generate a private key of `bits` length using simple LCG RNG.
    pub fn generate_private_key(bits: usize, seed: &mut u64) -> BigUint {
        let mut bytes = vec![0u8; (bits + 7) / 8];
        for b in &mut bytes {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (*seed >> 24) as u8;
        }
        // ensure non-zero and within range by setting top bit and making odd
        if let Some(first) = bytes.first_mut() {
            *first |= 0x80;
        }
        if let Some(last) = bytes.last_mut() {
            *last |= 1;
        }
        BigUint::from_bytes_be(&bytes)
    }

    /// Grab a private key using the OS RNG for `bits` bits.
    pub fn generate_private_key_secure(bits: usize) -> io::Result<BigUint> {
        let mut bytes = secure_random_bytes((bits + 7) / 8)?;
        if let Some(first) = bytes.first_mut() { *first |= 0x80; }
        if let Some(last) = bytes.last_mut() { *last |= 1; }
        Ok(BigUint::from_bytes_be(&bytes))
    }

    /// Compute the public key corresponding to `private`.
    pub fn compute_public_key(&self, private: &BigUint) -> BigUint {
        self.g.modpow(private, &self.p)
    }

    /// Compute the shared secret given our private key and peer's public key.
    pub fn compute_shared_secret(&self, private: &BigUint, peer_public: &BigUint) -> BigUint {
        peer_public.modpow(private, &self.p)
    }
}

/// Very naive primality test by trial division.
fn is_prime(candidate: &BigUint) -> bool {
    // small primes for trial division
    const SMALL_PRIMES: [u32; 11] = [2,3,5,7,11,13,17,19,23,29,31];
    for &p in &SMALL_PRIMES {
        let prime = BigUint::from_bytes_be(&p.to_be_bytes());
        if candidate.modpow(&BigUint::from_bytes_be(&[1]), &prime).to_bytes_be().iter().all(|&b| b==0) {
            return candidate.to_bytes_be() == p.to_be_bytes();
        }
    }
    // crude trial division up to sqrt using u32 step
    let two = BigUint::from_bytes_be(&[2]);
    let mut d = BigUint::from_bytes_be(&[37]);
    while {
        let du = to_u64(&d);
        let cu = to_u64(candidate);
        du.checked_mul(du).unwrap_or(u64::MAX) <= cu
    } {
        if candidate.modpow(&BigUint::from_bytes_be(&[1]), &d).to_bytes_be().iter().all(|&b| b==0) {
            return false;
        }
        d = d.add(&two);
    }
    true
}

fn to_u64(n: &BigUint) -> u64 {
    let bytes = n.to_bytes_be();
    let mut arr = [0u8; 8];
    if bytes.len() > 8 { return u64::MAX; }
    arr[8 - bytes.len()..].copy_from_slice(&bytes);
    u64::from_be_bytes(arr)
}

/// Generate a prime roughly `bits` bits long using the provided seed.
pub fn generate_prime(bits: usize, seed: &mut u64) -> BigUint {
    loop {
        let mut candidate = DiffieHellman::generate_private_key(bits, seed);
        // ensure odd
        if let Some(last) = candidate.to_bytes_be().last() { if last % 2 == 0 { let bytes = candidate.to_bytes_be(); let mut new_bytes = bytes.clone(); *new_bytes.last_mut().unwrap() |= 1; candidate = BigUint::from_bytes_be(&new_bytes); } }
        if is_prime(&candidate) { return candidate; }
    }
}

/// Generate a prime using the OS RNG for randomness.
pub fn generate_prime_secure(bits: usize) -> io::Result<BigUint> {
    loop {
        let mut candidate = DiffieHellman::generate_private_key_secure(bits)?;
        if let Some(last) = candidate.to_bytes_be().last() {
            if last % 2 == 0 {
                let bytes = candidate.to_bytes_be();
                let mut new_bytes = bytes.clone();
                *new_bytes.last_mut().unwrap() |= 1;
                candidate = BigUint::from_bytes_be(&new_bytes);
            }
        }
        if is_prime(&candidate) { return Ok(candidate); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_key_exchange() {
        // small 64-bit prime for testing
        let mut seed = 1u64;
        let p = generate_prime(32, &mut seed);
        let g = BigUint::from_bytes_be(&[2]);
        let dh = DiffieHellman::new(p, g);

        let alice_priv = DiffieHellman::generate_private_key(16, &mut seed);
        let bob_priv = DiffieHellman::generate_private_key(16, &mut seed);
        let alice_pub = dh.compute_public_key(&alice_priv);
        let bob_pub = dh.compute_public_key(&bob_priv);

        let s1 = dh.compute_shared_secret(&alice_priv, &bob_pub);
        let s2 = dh.compute_shared_secret(&bob_priv, &alice_pub);
        assert_eq!(s1.to_bytes_be(), s2.to_bytes_be());
    }
}
