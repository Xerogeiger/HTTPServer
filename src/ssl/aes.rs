// AES implementation for 128/256-bit keys in CBC mode.
// Minimal, no external dependencies.

pub struct AesCipher {
    round_keys: Vec<[u8; 16]>,
}

impl AesCipher {
    /// Create AES cipher with a 128-bit key
    pub fn new_128(key: &[u8; 16]) -> Self {
        AesCipher { round_keys: expand_key(key, 4, 10) }
    }

    /// Create AES cipher with a 256-bit key
    pub fn new_256(key: &[u8; 32]) -> Self {
        AesCipher { round_keys: expand_key(key, 8, 14) }
    }

    /// Encrypt a single 16-byte block
    pub fn encrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
        encrypt_block(block, &self.round_keys)
    }

    /// Decrypt a single 16-byte block
    pub fn decrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
        decrypt_block(block, &self.round_keys)
    }

    /// Encrypt data in CBC mode with PKCS7 padding
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let mut padded = data.to_vec();
        let pad_len = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let mut prev = *iv;
        let mut out = Vec::with_capacity(padded.len());
        for chunk in padded.chunks(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            block = encrypt_block(block, &self.round_keys);
            out.extend_from_slice(&block);
            prev = block;
        }
        out
    }

    /// Decrypt data in CBC mode with PKCS7 padding
    pub fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 16]) -> Option<Vec<u8>> {
        if data.len() % 16 != 0 { return None; }
        let mut prev = *iv;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let block: [u8;16] = chunk.try_into().unwrap();
            let mut decrypted = decrypt_block(block, &self.round_keys);
            for i in 0..16 {
                decrypted[i] ^= prev[i];
            }
            out.extend_from_slice(&decrypted);
            prev = block;
        }
        if out.is_empty() { return Some(out); }
        let pad_len = *out.last().unwrap() as usize;
        if pad_len == 0 || pad_len > 16 { return None; }
        if out[out.len()-pad_len..].iter().any(|&b| b as usize != pad_len) {
            return None;
        }
        out.truncate(out.len()-pad_len);
        Some(out)
    }

    /// Decrypt CBC data without removing padding (used for test vectors)
    fn decrypt_cbc_nopad(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert!(data.len() % 16 == 0);
        let mut prev = *iv;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let block: [u8;16] = chunk.try_into().unwrap();
            let mut decrypted = decrypt_block(block, &self.round_keys);
            for i in 0..16 { decrypted[i] ^= prev[i]; }
            out.extend_from_slice(&decrypted);
            prev = block;
        }
        out
    }

    /// Encrypt data in CBC mode without padding (used for test vectors)
    fn encrypt_cbc_nopad(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert!(data.len() % 16 == 0);
        let mut prev = *iv;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let mut block = [0u8;16];
            for i in 0..16 { block[i] = chunk[i] ^ prev[i]; }
            block = encrypt_block(block, &self.round_keys);
            out.extend_from_slice(&block);
            prev = block;
        }
        out
    }
}

// ================= Internal AES primitives =================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round constants for key expansion
const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

fn sub_word(w: u32) -> u32 {
    let bytes = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

fn rot_word(w: u32) -> u32 { w.rotate_left(8) }

fn expand_key(key: &[u8], nk: usize, nr: usize) -> Vec<[u8; 16]> {
    let nb = 4;
    let mut w = vec![0u32; nb * (nr + 1)];
    for i in 0..nk {
        w[i] = u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in nk..nb * (nr + 1) {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ (RCON[i / nk - 1] as u32) << 24;
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
    let mut round_keys = Vec::with_capacity(nr + 1);
    for r in 0..=nr {
        let mut block = [0u8; 16];
        for c in 0..nb {
            block[c * 4..c * 4 + 4].copy_from_slice(&w[r * nb + c].to_be_bytes());
        }
        round_keys.push(block);
    }
    round_keys
}

fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 { state[i] ^= key[i]; }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = SBOX[*b as usize]; }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = INV_SBOX[*b as usize]; }
}

fn shift_rows(state: &mut [u8; 16]) {
    let tmp = [state[1], state[5], state[9], state[13]];
    state[1] = tmp[1]; state[5] = tmp[2]; state[9] = tmp[3]; state[13] = tmp[0];
    let tmp = [state[2], state[6], state[10], state[14]];
    state[2] = tmp[2]; state[6] = tmp[3]; state[10]= tmp[0]; state[14]= tmp[1];
    let tmp = [state[3], state[7], state[11], state[15]];
    state[3] = tmp[3]; state[7] = tmp[0]; state[11]= tmp[1]; state[15]= tmp[2];
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let tmp = [state[1], state[5], state[9], state[13]];
    state[1] = tmp[3]; state[5] = tmp[0]; state[9]=tmp[1]; state[13]=tmp[2];
    let tmp = [state[2], state[6], state[10], state[14]];
    state[2] = tmp[2]; state[6]=tmp[3]; state[10]=tmp[0]; state[14]=tmp[1];
    let tmp = [state[3], state[7], state[11], state[15]];
    state[3] = tmp[1]; state[7]=tmp[2]; state[11]=tmp[3]; state[15]=tmp[0];
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]];
        state[c*4]   = gmul(col[0],2) ^ gmul(col[1],3) ^ col[2] ^ col[3];
        state[c*4+1] = col[0] ^ gmul(col[1],2) ^ gmul(col[2],3) ^ col[3];
        state[c*4+2] = col[0] ^ col[1] ^ gmul(col[2],2) ^ gmul(col[3],3);
        state[c*4+3] = gmul(col[0],3) ^ col[1] ^ col[2] ^ gmul(col[3],2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]];
        state[c*4]   = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3],9);
        state[c*4+1] = gmul(col[0],9)  ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13);
        state[c*4+2] = gmul(col[0],13) ^ gmul(col[1],9)  ^ gmul(col[2],14) ^ gmul(col[3],11);
        state[c*4+3] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2],9)  ^ gmul(col[3],14);
    }
}

fn encrypt_block(mut block: [u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    add_round_key(&mut block, &round_keys[0]);
    for rk in round_keys.iter().skip(1).take(round_keys.len()-2) {
        sub_bytes(&mut block);
        shift_rows(&mut block);
        mix_columns(&mut block);
        add_round_key(&mut block, rk);
    }
    sub_bytes(&mut block);
    shift_rows(&mut block);
    add_round_key(&mut block, round_keys.last().unwrap());
    block
}

fn decrypt_block(mut block: [u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    add_round_key(&mut block, round_keys.last().unwrap());
    for rk in round_keys.iter().rev().skip(1).take(round_keys.len()-2) {
        inv_shift_rows(&mut block);
        inv_sub_bytes(&mut block);
        add_round_key(&mut block, rk);
        inv_mix_columns(&mut block);
    }
    inv_shift_rows(&mut block);
    inv_sub_bytes(&mut block);
    add_round_key(&mut block, &round_keys[0]);
    block
}

#[cfg(test)]
mod tests {
    use super::AesCipher;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn aes128_cbc_nist_example() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let iv_arr: [u8;16] = iv.clone().try_into().unwrap();
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = hex_to_bytes(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        let cipher = AesCipher::new_128(&key.try_into().unwrap());
        let ct = cipher.encrypt_cbc_nopad(&pt, &iv_arr);
        assert_eq!(ct, expected);
        let dec = cipher.decrypt_cbc_nopad(&ct, &iv_arr);
        assert_eq!(dec, pt);
    }

    #[test]
    fn aes256_cbc_nist_example() {
        let key = hex_to_bytes(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let iv_arr: [u8;16] = iv.clone().try_into().unwrap();
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = hex_to_bytes(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        );
        let cipher = AesCipher::new_256(&key.try_into().unwrap());
        let ct = cipher.encrypt_cbc_nopad(&pt, &iv_arr);
        assert_eq!(ct, expected);
        let dec = cipher.decrypt_cbc_nopad(&ct, &iv_arr);
        assert_eq!(dec, pt);
    }
}

