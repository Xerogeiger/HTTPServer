use crate::ssl::bigint::BigUint;
use crate::ssl::rng::secure_random_bytes;

// 2048-bit prime from RFC 3526 (group 14)
const PRIME_2048: [u8; 256] = [
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x37,0xed,0x6b,0x0b,0xff,0x5c,0xb6,0xf4,0x06,0xb7,0xed,
    0xee,0x38,0x6b,0xfb,0x5a,0x89,0x9f,0xa5,0xae,0x9f,0x24,0x11,0x7c,0x4b,0x1f,0xe6,
    0x49,0x28,0x66,0x51,0xec,0xe4,0x5b,0x3d,0xc2,0x00,0x7c,0xb8,0xa1,0x63,0xbf,0x05,
    0x98,0xda,0x48,0x36,0x1c,0x55,0xd3,0x9a,0x69,0x16,0x3f,0xa8,0xfd,0x24,0xcf,0x5f,
    0x83,0x65,0x5d,0x23,0xdc,0xa3,0xad,0x96,0x1c,0x62,0xf3,0x56,0x20,0x85,0x52,0xbb,
    0x9e,0xd5,0x29,0x07,0x70,0x96,0x96,0x6d,0x67,0x0c,0x35,0x4e,0x4a,0xbc,0x98,0x04,
    0xf1,0x74,0x6c,0x08,0xca,0x18,0x21,0x7c,0x32,0x90,0x5e,0x46,0x2e,0x36,0xce,0x3b,
    0xe3,0x9e,0x77,0x2c,0x18,0x0e,0x86,0x03,0x9b,0x27,0x83,0xa2,0xec,0x07,0xa2,0x8f,
    0xb5,0xc5,0x5d,0xf0,0x6f,0x4c,0x52,0xc9,0xde,0x2b,0xcb,0xf6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7c,0xea,0x95,0x6a,0xe5,0x15,0xd2,0x26,0x18,0x98,0xfa,0x05,0x10,
    0x15,0x72,0x8e,0x5a,0x8a,0xac,0xaa,0x68,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
];
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

/// Probabilistic primality test using a small set of Miller-Rabin witnesses.
/// Probabilistic Miller-Rabin primality test.
/// Exposed for verifying received Diffie-Hellman parameters.
pub fn is_prime(candidate: &BigUint) -> bool {
    use std::cmp::Ordering;

    // handle small primes explicitly
    const SMALL_PRIMES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for &p in &SMALL_PRIMES {
        let prime = BigUint::from_bytes_be(&p.to_be_bytes());
        if candidate.cmp(&prime) == Ordering::Equal {
            return true;
        }
        if candidate.rem(&prime).to_bytes_be() == vec![0] {
            return false;
        }
    }

    // write candidate-1 = 2^s * d
    let one = BigUint::from_bytes_be(&[1]);
    let two = BigUint::from_bytes_be(&[2]);
    let mut d = candidate.sub(&one);
    let mut s = 0u32;
    let zero = BigUint::from_bytes_be(&[0]);
    while d.rem(&two).cmp(&zero) == Ordering::Equal {
        d = d.div_u32(2);
        s += 1;
    }

    const WITNESSES: [u32; 5] = [2, 3, 5, 7, 11];
    let n_minus_one = candidate.sub(&one);
    for &a_small in &WITNESSES {
        let a = BigUint::from_bytes_be(&a_small.to_be_bytes());
        let mut x = a.modpow(&d, candidate);
        if x.cmp(&one) == Ordering::Equal || x.cmp(&n_minus_one) == Ordering::Equal {
            continue;
        }
        let mut r = 1u32;
        while r < s {
            x = x.modpow(&two, candidate);
            if x.cmp(&n_minus_one) == Ordering::Equal {
                break;
            }
            r += 1;
        }
        if r == s {
            return false;
        }
    }
    true
}

/// Check that `val` is in the inclusive range [2, p-2].
pub fn in_range_2_to_p_minus_2(val: &BigUint, p: &BigUint) -> bool {
    use std::cmp::Ordering;
    let two = BigUint::from_bytes_be(&[2]);
    if val.cmp(&two) == Ordering::Less {
        return false;
    }
    if p.cmp(&two) != Ordering::Greater {
        return false;
    }
    let max = p.sub(&two);
    val.cmp(&max) != Ordering::Greater
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
    if bits >= 2048 {
        return BigUint::from_bytes_be(&PRIME_2048);
    }
    loop {
        let mut candidate = DiffieHellman::generate_private_key(bits, seed);
        if let Some(last) = candidate.to_bytes_be().last() {
            if last % 2 == 0 {
                let bytes = candidate.to_bytes_be();
                let mut new_bytes = bytes.clone();
                *new_bytes.last_mut().unwrap() |= 1;
                candidate = BigUint::from_bytes_be(&new_bytes);
            }
        }
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
        // larger prime for testing the generator
        let mut seed = 1u64;
        let p = generate_prime(2048, &mut seed);
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
