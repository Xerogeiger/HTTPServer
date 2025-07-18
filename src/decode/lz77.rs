//! lz77.rs
//!
//! A simple LZ77 sliding-window parser for DEFLATE (RFC1951 §3.2.5)

use crate::decode::gz_shared::{DIST_BASE, LENGTH_BASE};

/// A single LZ77 token: either a literal byte or a length/distance match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Literal(u8),
    Match { length: usize, distance: usize },
}

const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1,
    2, 2, 2, 2,
    3, 3, 3, 3,
    4, 4, 4, 4,
    5, 5, 5, 5,
    0
];

const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9,10,10,
    11,11,12,12,13,13,
];

// ------ Helper functions for mapping length/distance to codes ------

/// Map a match length (3..=258) to its DEFLATE length code (257..=285),
/// the number of extra bits, and the base length.
pub fn length_code_and_bits(len: usize) -> (usize, u8, usize) {
    // find largest i where LENGTH_BASE[i] <= len
    for (i, &base) in LENGTH_BASE.iter().enumerate().rev() {
        let extra = LENGTH_EXTRA[i] as usize;
        if len >= base.0 {
            let symbol = 257 + i;
            let eb = extra as u8;
            return (symbol, eb, base.0);
        }
    }
    // fallback to code 257
    (257, 0, LENGTH_BASE[0].0)
}

/// Map a match distance (1..32768) to (symbol, extra_bits, base_distance).
pub fn distance_code_and_bits(dist: usize) -> (usize, u8, usize) {
    for (i, &base) in DIST_BASE.iter().enumerate().rev() {
        let extra = DIST_EXTRA[i] as usize;
        if dist >= base.0 {
            let symbol = i;
            let eb = extra as u8;
            return (symbol, eb, base.0);
        }
    }
    // fallback to code 0
    (0, 0, DIST_BASE[0].0)
}

/// Naïve sliding-window LZ77 parser.
/// Window size = 32_768, lookahead buffer up to 258 bytes.
pub fn lz77_parse(data: &[u8]) -> Vec<Token> {
    let mut i = 0;
    let n = data.len();
    let mut tokens = Vec::new();
    while i < n {
        let window_start = i.saturating_sub(32_768);
        let mut best_len = 0;
        let mut best_dist = 0;
        let max_look = (n - i).min(258);
        // find longest match in window
        for j in window_start..i {
            let mut length = 0;
            while length < max_look && data[j + length] == data[i + length] {
                length += 1;
            }
            if length > best_len {
                best_len = length;
                best_dist = i - j;
                if best_len == max_look {
                    break;
                }
            }
        }
        if best_len >= 3 {
            tokens.push(Token::Match { length: best_len, distance: best_dist });
            i += best_len;
        } else {
            tokens.push(Token::Literal(data[i]));
            i += 1;
        }
    }
    tokens
}

/// Reconstructs the original byte stream from a sequence of LZ77 tokens.
/// For each `Match`, it copies `length` bytes from `distance` back in the output buffer.
pub fn lz77_reconstruct(tokens: &[Token]) -> Vec<u8> {
    let mut out = Vec::new();
    for token in tokens {
        match *token {
            Token::Literal(b) => out.push(b),
            Token::Match { length, distance } => {
                let start = out.len().checked_sub(distance)
                    .expect("Invalid distance in LZ77 reconstruct");
                for i in 0..length {
                    let byte = out[start + i];
                    out.push(byte);
                }
            }
        }
    }
    out
}

// ------ Unit tests ------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_code_and_bits_basic() {
        let (sym, eb, base) = length_code_and_bits(3);
        assert_eq!(sym, 257);
        assert_eq!(eb, 0);
        assert_eq!(base, 3);

        let (sym, eb, base) = length_code_and_bits(10);
        assert_eq!(sym, 264);
        assert_eq!(eb, 0);
        assert_eq!(base, 10);

        let (sym, eb, base) = length_code_and_bits(258);
        assert_eq!(sym, 285);
        assert_eq!(eb, 0);
        assert_eq!(base, 258);
    }

    #[test]
    fn test_distance_code_and_bits_basic() {
        let (sym, eb, base) = distance_code_and_bits(1);
        assert_eq!(sym, 0);
        assert_eq!(eb, 0);
        assert_eq!(base, 1);

        let (sym, eb, base) = distance_code_and_bits(5);
        assert_eq!(sym, 4);
        assert_eq!(eb, 1);
        assert_eq!(base, 5);
    }

    #[test]
    fn test_lz77_parse_literals_only() {
        let data = b"abcdef";
        let toks = lz77_parse(data);
        assert_eq!(toks.len(), 6);
        for (i, tok) in toks.iter().enumerate() {
            assert_eq!(*tok, Token::Literal(data[i]));
        }
    }

    #[test]
    fn test_lz77_parse_repeats() {
        let data = b"abcabcabc";
        let toks = lz77_parse(data);
        assert!(toks.len() < data.len());
        // Expect first three as literals, then a match of length 6, distance 3
        assert_eq!(toks[0], Token::Literal(b'a'));
        assert_eq!(toks[1], Token::Literal(b'b'));
        assert_eq!(toks[2], Token::Literal(b'c'));
        if let Token::Match { length, distance } = toks[3] {
            assert_eq!(length, 6);
            assert_eq!(distance, 3);
        } else {
            panic!("Expected a match token");
        }
    }
}
