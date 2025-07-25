//! Pure-Rust SHA family implementations: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
//!
//! This crate provides standalone, no-std-free SHA algorithms.  
//! Each module exposes a single `hash(input: &[u8]) -> [u8; N]` function.

/// SHA-1 (160-bit) implementation.
pub mod sha1 {
    //! Pure-Rust SHA-1 implementation.

    /// Initial SHA-1 hash values (h0..h4).
    const H0: u32 = 0x67452301;
    const H1: u32 = 0xEFCDAB89;
    const H2: u32 = 0x98BADCFE;
    const H3: u32 = 0x10325476;
    const H4: u32 = 0xC3D2E1F0;

    /// SHA-1 round constant for round `t`.
    #[inline]
    fn k(t: usize) -> u32 {
        match t {
            0..=19  => 0x5A827999,
            20..=39 => 0x6ED9EBA1,
            40..=59 => 0x8F1BBCDC,
            _       => 0xCA62C1D6,
        }
    }

    /// SHA-1 nonlinear function for round `t`.
    #[inline]
    fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
        match t {
            0..=19  => (b & c) | ((!b) & d),
            20..=39 => b ^ c ^ d,
            40..=59 => (b & c) | (b & d) | (c & d),
            _       => b ^ c ^ d,
        }
    }

    /// Compute SHA-1 digest of `input`.
    ///
    /// # Returns
    ///
    /// A 20-byte array containing the hash.
    pub fn hash(input: &[u8]) -> [u8; 20] {
        // 1) Initialize state
        let mut h = [H0, H1, H2, H3, H4];

        // 2) Pre-processing: padding
        let bit_len = (input.len() as u64) * 8;
        let mut msg = Vec::from(input);
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // 3) Process each 512-bit chunk
        for chunk in msg.chunks_exact(64) {
            // 3a) Message schedule
            let mut w = [0u32; 80];
            for (i, block) in chunk.chunks_exact(4).enumerate().take(16) {
                w[i] = u32::from_be_bytes(block.try_into().unwrap());
            }
            for t in 16..80 {
                w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
            }

            // 3b) Initialize working vars
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

            // 3c) Main loop
            for t in 0..80 {
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f(t, b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(k(t))
                    .wrapping_add(w[t]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            // 3d) Compute intermediate hash
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }

        // 4) Produce final digest (big-endian)
        let mut digest = [0u8; 20];
        for (i, &word) in h.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// SHA-224 (224-bit) implementation.
pub mod sha224 {
    //! Pure-Rust SHA-224: same structure as SHA-256 but different initial state, truncated output.

    /// SHA-224 initial hash values.
    const H0: u32 = 0xc1059ed8;
    const H1: u32 = 0x367cd507;
    const H2: u32 = 0x3070dd17;
    const H3: u32 = 0xf70e5939;
    const H4: u32 = 0xffc00b31;
    const H5: u32 = 0x68581511;
    const H6: u32 = 0x64f98fa7;
    const H7: u32 = 0xbefa4fa4;

    // Reuse SHA-256 constants and helper functions
    const K: [u32; 64] = super::sha256::K;
    use super::sha256::{big_sigma0, big_sigma1, small_sigma0, small_sigma1, ch, maj};

    /// Compute SHA-224 digest of `input`.
    ///
    /// # Returns
    ///
    /// A 28-byte array containing the hash.
    pub fn hash(input: &[u8]) -> [u8; 28] {
        // 1) Initialize state
        let mut h = [H0, H1, H2, H3, H4, H5, H6, H7];

        // 2) Pre-processing (pad to 512-bit blocks)
        let bit_len = (input.len() as u64) * 8;
        let mut msg = Vec::from(input);
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // 3) Process each chunk
        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, block) in chunk.chunks_exact(4).enumerate().take(16) {
                w[i] = u32::from_be_bytes(block.try_into().unwrap());
            }
            for t in 16..64 {
                w[t] = small_sigma1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(small_sigma0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for t in 0..64 {
                let t1 = hh
                    .wrapping_add(big_sigma1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        // 4) Truncate to 224 bits (first 7 words)
        let mut digest = [0u8; 28];
        for i in 0..7 {
            digest[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        digest
    }
}

/// SHA-256 (256-bit) implementation.
pub mod sha256 {
    //! Pure-Rust SHA-256 implementation.

    /// SHA-256 constants.
    pub const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    #[inline]
    pub(crate) fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
    #[inline]
    pub(crate) fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
    #[inline]
    pub(crate) fn big_sigma0(x: u32) -> u32 { x.rotate_right(2)  ^ x.rotate_right(13) ^ x.rotate_right(22) }
    #[inline]
    pub(crate) fn big_sigma1(x: u32) -> u32 { x.rotate_right(6)  ^ x.rotate_right(11) ^ x.rotate_right(25) }
    #[inline]
    pub(crate) fn small_sigma0(x: u32) -> u32 { x.rotate_right(7)  ^ x.rotate_right(18) ^ (x >> 3) }
    #[inline]
    pub(crate) fn small_sigma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

    /// Compute SHA-256 digest of `input`.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the hash.
    pub fn hash(input: &[u8]) -> [u8; 32] {
        // Initial hash values
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        // Pre-processing: padding
        let bit_len = (input.len() as u64) * 8;
        let mut msg = Vec::from(input);
        msg.push(0x80);
        while (msg.len() % 64) != 56 { msg.push(0); }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // Process each 512-bit chunk
        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, block) in chunk.chunks_exact(4).enumerate().take(16) {
                w[i] = u32::from_be_bytes(block.try_into().unwrap());
            }
            for t in 16..64 {
                w[t] = small_sigma1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(small_sigma0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for t in 0..64 {
                let t1 = hh
                    .wrapping_add(big_sigma1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        // Produce digest
        let mut digest = [0u8; 32];
        for (i, &word) in h.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// SHA-384 (384-bit) implementation.
pub mod sha384 {
    //! Pure-Rust SHA-384: same structure as SHA-512 but different initial state, truncated output.

    /// SHA-384 initial hash values.
    const H0: u64 = 0xcbbb9d5dc1059ed8;
    const H1: u64 = 0x629a292a367cd507;
    const H2: u64 = 0x9159015a3070dd17;
    const H3: u64 = 0x152fecd8f70e5939;
    const H4: u64 = 0x67332667ffc00b31;
    const H5: u64 = 0x8eb44a8768581511;
    const H6: u64 = 0xdb0c2e0d64f98fa7;
    const H7: u64 = 0x47b5481dbefa4fa4;

    // Reuse SHA-512 constants and helpers
    const K: [u64; 64] = super::sha512::K;
    use super::sha512::{big_sigma0 as BS0, big_sigma1 as BS1, small_sigma0 as SS0, small_sigma1 as SS1, ch, maj};

    /// Compute SHA-384 digest of `input`.
    ///
    /// # Returns
    ///
    /// A 48-byte array containing the hash.
    pub fn hash(input: &[u8]) -> [u8; 48] {
        // 1) Initialize state
        let mut h = [H0, H1, H2, H3, H4, H5, H6, H7];

        // 2) Pre-processing
        let bit_len = (input.len() as u128) * 8;
        let mut msg = Vec::from(input);
        msg.push(0x80);
        while (msg.len() % 128) != 112 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // 3) Process each 1024-bit chunk
        for chunk in msg.chunks_exact(128) {
            let mut w = [0u64; 80];
            for (i, block) in chunk.chunks_exact(8).enumerate().take(16) {
                w[i] = u64::from_be_bytes(block.try_into().unwrap());
            }
            for t in 16..80 {
                w[t] = SS1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(SS0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for t in 0..80 {
                let t1 = hh
                    .wrapping_add(BS1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = BS0(a).wrapping_add(maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        // 4) Truncate to 384 bits (first 6 words)
        let mut digest = [0u8; 48];
        for i in 0..6 {
            digest[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
        }
        digest
    }
}

/// SHA-512 (512-bit) implementation.
pub mod sha512 {
    //! Pure-Rust SHA-512 implementation.

    /// SHA-512 constants.
    pub const K: [u64; 64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
        0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210,
        0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910,
        0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60,
        0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9,
        0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    ];

    #[inline]
    pub(crate) fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (!x & z) }
    #[inline]
    pub(crate) fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
    #[inline]
    pub(crate) fn big_sigma0(x: u64) -> u64 { x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39) }
    #[inline]
    pub(crate) fn big_sigma1(x: u64) -> u64 { x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41) }
    #[inline]
    pub(crate) fn small_sigma0(x: u64) -> u64 { x.rotate_right(1)  ^ x.rotate_right(8)  ^ (x >> 7) }
    #[inline]
    pub(crate) fn small_sigma1(x: u64) -> u64 { x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6) }

    /// Compute SHA-512 digest of `input`.
    ///
    /// # Returns
    ///
    /// A 64-byte array containing the hash.
    pub fn hash(input: &[u8]) -> [u8; 64] {
        // Initial hash values
        let mut h: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];

        // Pre-processing: padding
        let bit_len = (input.len() as u128) * 8;
        let mut msg = Vec::from(input);
        msg.push(0x80);
        while (msg.len() % 128) != 112 { msg.push(0); }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // Process each 1024-bit chunk
        for chunk in msg.chunks_exact(128) {
            let mut w = [0u64; 80];
            for (i, block) in chunk.chunks_exact(8).enumerate().take(16) {
                w[i] = u64::from_be_bytes(block.try_into().unwrap());
            }
            for t in 16..80 {
                w[t] = small_sigma1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(small_sigma0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for t in 0..80 {
                let t1 = hh
                    .wrapping_add(big_sigma1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        // Produce digest
        let mut digest = [0u8; 64];
        for (i, &word) in h.iter().enumerate() {
            digest[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}
