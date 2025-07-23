use crate::decode::gz_shared::{
    fixed_dist_lens, fixed_lit_len_lens, gen_codes, generate_crc32_table, DeflateBlockType,
    GzHeader, CODE_LENGTH_ORDER,
};
use crate::decode::lz77::{distance_code_and_bits, length_code_and_bits, lz77_parse, Token};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;

struct BitWriter {
    out: Vec<u8>,
    bit_buf: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            out: Vec::new(),
            bit_buf: 0,
            bit_count: 0,
        }
    }

    /// Write a single bit (LSB first)
    fn write_bit(&mut self, bit: u8) {
        self.bit_buf |= (bit & 1) << self.bit_count;
        self.bit_count += 1;
        if self.bit_count == 8 {
            self.flush_byte();
        }
    }

    /// Write `count` bits from `bits` (LSB first)
    fn write_bits(&mut self, bits: u32, count: u8) {
        for i in 0..count {
            let b = ((bits >> i) & 1) as u8;
            self.write_bit(b);
        }
    }

    /// Align to next byte boundary by padding with zeros
    fn align_byte(&mut self) {
        while self.bit_count != 0 {
            self.write_bit(0);
        }
    }

    fn flush_byte(&mut self) {
        self.out.push(self.bit_buf);
        self.bit_buf = 0;
        self.bit_count = 0;
    }

    /// Finish writing bits and return the full byte vector
    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.flush_byte();
        }
        self.out
    }
}

/// GZip Encoder supporting Stored, Fixed Huffman, Dynamic Huffman
pub struct GzEncoder {
    header: GzHeader,
}

pub struct DeflateEncoder {
    block_type: DeflateBlockType,
}

impl DeflateEncoder {
    pub fn new(block_type: DeflateBlockType) -> Self {
        DeflateEncoder { block_type }
    }

    pub fn encode(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        // 1) Run LZ77 encoding
        let tokens = lz77_parse(data);
        match self.block_type {
            DeflateBlockType::Stored => self.encode_stored(data, &mut out)?,
            DeflateBlockType::FixedHuffman => self.encode_fixed_tokens(&tokens, &mut out)?,
            DeflateBlockType::DynamicHuffman => self.encode_dynamic_tokens(&tokens, &mut out)?,
        }
        #[cfg(debug_assertions)]
        {
            use crate::decode::gz_decoder::DeflateDecoder;
            let mut dec = DeflateDecoder::new(&out);
            let mut verify = Vec::new();
            dec.decode(&mut verify).expect("Deflate self-check failed");
            debug_assert_eq!(&verify, data, "Deflate verification mismatch");
        }
        Ok(out)
    }

    fn encode_stored(&self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let chunk = &data[offset..(offset + 0xFFFF).min(data.len())];
            let is_last = offset + chunk.len() == data.len();
            // header bits
            let mut bw = BitWriter::new();
            bw.write_bit(if is_last { 1 } else { 0 }); // BFINAL
            bw.write_bits(0, 2); // BTYPE=00
            bw.align_byte();
            out.extend_from_slice(&bw.finish());
            // LEN/NLEN
            let len = chunk.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            // data
            out.extend_from_slice(chunk);
            offset += chunk.len();
        }
        Ok(())
    }

    /// Fixed Huffman using LZ77 tokens
    fn encode_fixed_tokens(&self, tokens: &[Token], out: &mut Vec<u8>) -> io::Result<()> {
        let mut bw = BitWriter::new();
        // header bits: BFINAL=1, BTYPE=01
        bw.write_bit(1);
        bw.write_bits(1, 2);

        let lit_lens = fixed_lit_len_lens();
        let dist_lens = fixed_dist_lens();
        let lit_codes = gen_codes(&lit_lens);
        let dist_codes = gen_codes(&dist_lens);

        for token in tokens {
            match *token {
                Token::Literal(b) => {
                    if let Some((code, len)) = lit_codes[b as usize] {
                        bw.write_bits(code, len);
                    }
                }
                Token::Match { length, distance } => {
                    // length code + extra
                    let (sym, eb, base) = length_code_and_bits(length);
                    let (code, len) = lit_codes[sym].unwrap();
                    bw.write_bits(code, len);
                    bw.write_bits((length - base) as u32, eb);
                    // distance code + extra
                    let (dsym, deb, dbase) = distance_code_and_bits(distance);
                    let (dcode, dlen) = dist_codes[dsym].unwrap();
                    bw.write_bits(dcode, dlen);
                    bw.write_bits((distance - dbase) as u32, deb);
                }
            }
        }
        // EOB
        let (code, len) = lit_codes[256].unwrap();
        bw.write_bits(code, len);
        bw.align_byte();
        out.extend_from_slice(&bw.finish());
        Ok(())
    }

    /// Dynamic Huffman using LZ77 tokens
    fn encode_dynamic_tokens(&self, tokens: &[Token], out: &mut Vec<u8>) -> io::Result<()> {
        let mut bw = BitWriter::new();
        // header bits: BFINAL=1, BTYPE=10
        bw.write_bit(1);
        bw.write_bits(2, 2);

        // 1) count frequencies from tokens
        let mut lit_freq = [0u32; 286];
        let mut dist_freq = [0u32; 32];
        // ensure at least EOB and one distance
        lit_freq[256] = 1;
        dist_freq[0] = 1;
        for token in tokens {
            match *token {
                Token::Literal(b) => {
                    lit_freq[b as usize] += 1;
                }
                Token::Match { length, distance } => {
                    let (sym, _, _) = length_code_and_bits(length);
                    lit_freq[sym] += 1;
                    let (dsym, _, _) = distance_code_and_bits(distance);
                    dist_freq[dsym] += 1;
                }
            }
        }

        // 2) generate code lengths
        let mut lit_lens = huffman_code_lengths(&lit_freq, 15)?;
        let mut dist_lens = huffman_code_lengths(&dist_freq, 15)?;

        // ensure required symbols have codes
        if lit_lens[256] == 0 {
            lit_lens[256] = 1;
        }

        for token in tokens {
            if let Token::Match { length, distance } = *token {
                let (sym, _, _) = length_code_and_bits(length);
                if lit_lens[sym] == 0 {
                    lit_lens[sym] = 1;
                }
                let (dsym, _, _) = distance_code_and_bits(distance);
                if dist_lens[dsym] == 0 {
                    dist_lens[dsym] = 1;
                }
            }
        }

        // 3) write HLIT, HDIST, HCLEN
        let last_lit = find_last_nonzero(&lit_lens);
        let last_dist = find_last_nonzero(&dist_lens);
        let hlit = (last_lit + 1) - 257;
        let hdist = (last_dist + 1) - 1;
        let clens = build_clens(&lit_lens[..last_lit + 1], &dist_lens[..last_dist + 1])?;
        let last_clen = find_last_nonzero(&clens);
        let hclen = (last_clen + 1) - 4;
        bw.write_bits(hlit as u32, 5);
        bw.write_bits(hdist as u32, 5);
        bw.write_bits(hclen as u32, 4);

        // 4) emit code-length tree
        for &i in &CODE_LENGTH_ORDER[..(hclen + 4) as usize] {
            bw.write_bits(clens[i] as u32, 3);
        }
        // RLE of lengths using code-length codes
        let cl_codes = gen_codes(&clens);
        let mut combined = Vec::with_capacity(last_lit + 1 + last_dist + 1);
        combined.extend_from_slice(&lit_lens[..last_lit + 1]);
        combined.extend_from_slice(&dist_lens[..last_dist + 1]);
        rle_encode(&mut bw, &combined, &cl_codes);

        // 5) encode tokens using same bitwriter
        let lit_codes = gen_codes(&lit_lens);
        let dist_codes = gen_codes(&dist_lens);
        for token in tokens {
            match *token {
                Token::Literal(b) => {
                    let (code, len) = lit_codes[b as usize].unwrap();
                    bw.write_bits(code, len);
                }
                Token::Match { length, distance } => {
                    let (sym, eb, base) = length_code_and_bits(length);
                    let (code, len) = lit_codes[sym].unwrap();
                    bw.write_bits(code, len);
                    bw.write_bits((length - base) as u32, eb);
                    let (dsym, deb, dbase) = distance_code_and_bits(distance);
                    let (dcode, dlen) = dist_codes[dsym].unwrap();
                    bw.write_bits(dcode, dlen);
                    bw.write_bits((distance - dbase) as u32, deb);
                }
            }
        }
        // EOB
        let (code, len) = lit_codes[256].unwrap();
        bw.write_bits(code, len);
        bw.align_byte();
        out.extend_from_slice(&bw.finish());
        Ok(())
    }
}

impl GzEncoder {
    pub fn new() -> Self {
        GzEncoder {
            header: GzHeader::new(),
        }
    }

    pub fn encode(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        // 1) GZip header
        out.extend_from_slice(&self.header.to_bytes());

        let before_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "System time before epoch"))?;

        // 2) Body
        let mut deflate = DeflateEncoder::new(DeflateBlockType::DynamicHuffman);

        // Encode the data using deflate
        let deflated_data = deflate.encode(data)?;

        let after_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "System time before epoch"))?;

        if cfg!(debug_assertions) {
            println!("Encoding {} bytes with GZip took {} milliseconds", data.len(), (after_time - before_time).as_millis());
        }

        out.extend_from_slice(&deflated_data);

        // 3) Trailer
        let crc = compute_crc32(data);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());

        Ok(out)
    }
}

/// Compute length‑limited Huffman code lengths for the given symbol
/// frequencies. First a normal Huffman tree is built to obtain initial
/// lengths. If any length exceeds `max_bits`, the counts are adjusted in a
/// zlib‑style manner so that all final lengths are at most `max_bits`.
fn huffman_code_lengths(symbol_frequencies: &[u32], max_bits: usize) -> io::Result<Vec<u8>> {
    let n = symbol_frequencies.len();

    // gather symbols with non-zero frequency
    let mut symbols: Vec<(u32, usize)> = symbol_frequencies
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f > 0)
        .map(|(i, &f)| (f, i))
        .collect();

    if symbols.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "all frequencies zero",
        ));
    }
    if symbols.len() > (1 << max_bits) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many symbols for given max_bits",
        ));
    }
    if symbols.len() == 1 {
        let mut lens = vec![0u8; n];
        lens[symbols[0].1] = 1;
        return Ok(lens);
    }

    // --- build standard Huffman tree ---
    #[derive(Clone)]
    struct Node {
        freq: u32,
        left: Option<usize>,
        right: Option<usize>,
        symbol: Option<usize>,
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut heap = BinaryHeap::new();

    for &(f, idx) in &symbols {
        let id = nodes.len();
        nodes.push(Node {
            freq: f,
            left: None,
            right: None,
            symbol: Some(idx),
        });
        heap.push(Reverse((f, id)));
    }

    // ensure at least two nodes
    if heap.len() == 1 {
        let id = nodes.len();
        nodes.push(Node {
            freq: 0,
            left: None,
            right: None,
            symbol: None,
        });
        heap.push(Reverse((0, id)));
    }

    while heap.len() > 1 {
        let Reverse((f1, i1)) = heap.pop().unwrap();
        let Reverse((f2, i2)) = heap.pop().unwrap();
        let parent = nodes.len();
        nodes.push(Node {
            freq: f1 + f2,
            left: Some(i1),
            right: Some(i2),
            symbol: None,
        });
        heap.push(Reverse((f1 + f2, parent)));
    }
    let root = heap.pop().unwrap().0 .1;

    // traverse to get initial lengths
    let mut lengths = vec![0u8; n];
    fn walk(nodes: &[Node], idx: usize, depth: u8, out: &mut [u8]) {
        if let Some(sym) = nodes[idx].symbol {
            out[sym] = depth;
        } else {
            if let Some(l) = nodes[idx].left {
                walk(nodes, l, depth + 1, out);
            }
            if let Some(r) = nodes[idx].right {
                walk(nodes, r, depth + 1, out);
            }
        }
    }
    walk(&nodes, root, 0, &mut lengths);

    let mut max_len = lengths.iter().copied().max().unwrap_or(0) as usize;

    // count number of codes for each length
    let mut bl_count = vec![0usize; max_len + 1];
    for &l in &lengths {
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }

    // limit lengths greater than `max_bits`
    if max_len > max_bits {
        let mut overflow = 0usize;
        for bits in max_bits + 1..=max_len {
            overflow += bl_count[bits];
            bl_count[max_bits] += bl_count[bits];
            bl_count[bits] = 0;
        }

        while overflow > 0 {
            let mut bits = max_bits - 1;
            while bl_count[bits] == 0 {
                bits -= 1;
            }
            // move one count from the longest available length
            bl_count[bits] -= 1;
            bl_count[bits + 1] += 2;
            bl_count[max_bits] -= 1;
            overflow -= 1;
        }
        max_len = max_bits;
    }

    // assign lengths to symbols (shorter lengths for higher frequencies)
    symbols.sort_by_key(|&(f, _)| f); // ascending
    let mut result = vec![0u8; n];
    let mut idx = symbols.len();
    for bits in 1..=max_len {
        let count = bl_count[bits];
        for _ in 0..count {
            if idx == 0 {
                break;
            }
            idx -= 1;
            let sym = symbols[idx].1;
            result[sym] = bits as u8;
        }
    }

    Ok(result)
}

/// Find the last index with a non-zero length (or 0 if all are zero).
fn find_last_nonzero(lens: &[u8]) -> usize {
    lens.iter().rposition(|&l| l != 0).unwrap_or(0)
}

/// Build the 19 code-length code lengths (clens) for dynamic Huffman header.
/// lit_lens: code lengths for literal/length alphabet (257+ symbols)
/// dist_lens: code lengths for distance alphabet
/// Returns a Vec<u8> of length 19, one code length per code-length code symbol.
fn build_clens(lit_lens: &[u8], dist_lens: &[u8]) -> io::Result<Vec<u8>> {
    // 1) Combine the two length arrays
    let mut combined = Vec::with_capacity(lit_lens.len() + dist_lens.len());
    combined.extend_from_slice(lit_lens);
    combined.extend_from_slice(dist_lens);

    // 2) Run-length encode and count frequencies of CL codes 0..18
    //    0-15: literal lengths, 16: repeat prev 3-6, 17: repeat 3-10 zero, 18: repeat 11-138 zero
    let mut freqs = vec![0u32; 19];
    let mut i = 0;
    while i < combined.len() {
        let val = combined[i];
        // count run length
        let mut run = 1;
        while i + run < combined.len() && combined[i + run] == val {
            run += 1;
        }
        let mut remain = run;
        if val == 0 {
            // zeros
            // code 18 for 11-138 zeros
            while remain >= 11 {
                let chunk = remain.min(138);
                freqs[18] += 1;
                remain -= chunk;
            }
            // code 17 for 3-10 zeros
            while remain >= 3 {
                let chunk = remain.min(10);
                freqs[17] += 1;
                remain -= chunk;
            }
            // code 0 for leftover zeros
            freqs[0] += remain as u32;
        } else {
            // non-zero lengths
            // output first occurrence
            freqs[val as usize] += 1;
            remain -= 1;
            // code 16 for repeats of previous len (3-6)
            while remain >= 3 {
                let chunk = remain.min(6);
                freqs[16] += 1;
                remain -= chunk;
            }
            // leftover single repeats
            freqs[val as usize] += remain as u32;
        }
        i += run;
    }

    // 3) Compute Huffman code lengths for these 19 symbols, max 7 bits
    let clens = huffman_code_lengths(&freqs, 7)?;
    Ok(clens)
}

/// Run-length encode a sequence of code lengths and write to BitWriter
/// lens: array of code lengths (literal/length or distance)
fn rle_encode(bw: &mut BitWriter, lens: &[u8], codes: &[Option<(u32, u8)>]) {
    let mut i = 0;
    while i < lens.len() {
        let val = lens[i];
        let mut run = 1;
        while i + run < lens.len() && lens[i + run] == val {
            run += 1;
        }
        if val == 0 {
            // zeros: code 18,17,0
            let mut r = run;
            while r >= 11 {
                let chunk = r.min(138);
                let (code, len) = codes[18].unwrap();
                bw.write_bits(code, len);
                bw.write_bits((chunk - 11) as u32, 7);
                r -= chunk;
            }
            if r >= 3 {
                let chunk = r.min(10);
                let (code, len) = codes[17].unwrap();
                bw.write_bits(code, len);
                bw.write_bits((chunk - 3) as u32, 3);
                r -= chunk;
            }
            for _ in 0..r {
                let (code, len) = codes[0].unwrap();
                bw.write_bits(code, len);
            }
        } else {
            // non-zeros: code val,16
            let mut r = run;
            // first occurrence
            let (code, clen) = codes[val as usize].unwrap();
            bw.write_bits(code, clen);
            r -= 1;
            while r >= 3 {
                let chunk = r.min(6);
                let (code16, len16) = codes[16].unwrap();
                bw.write_bits(code16, len16);
                bw.write_bits((chunk - 3) as u32, 2);
                r -= chunk;
            }
            for _ in 0..r {
                let (code, clen) = codes[val as usize].unwrap();
                bw.write_bits(code, clen);
            }
        }
        i += run;
    }
}

/// Compute CRC32 for GZip trailer (using runtime-generated table)
fn compute_crc32(data: &[u8]) -> u32 {
    let table = generate_crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::gz_decoder::{DeflateDecoder, GzDecoder};
    use std::io::Read;

    // —— BitWriter tests —— //

    #[test]
    fn test_bit_writer_basic() {
        let mut bw = BitWriter::new();
        bw.write_bit(1);
        bw.write_bit(0);
        bw.write_bits(0b101, 3);
        bw.align_byte();
        let result = bw.finish();
        // LSB-first: bits are 1,0,1,0,1,0,0,0 => 0b00010101
        assert_eq!(result, vec![0b00010101]);
    }

    #[test]
    fn test_bit_writer_multiple_bytes() {
        let mut bw = BitWriter::new();
        // Write 16 bits: 0xABCD (1010_1011_1100_1101), LSB-first per byte
        bw.write_bits(0xAB, 8);
        bw.write_bits(0xCD, 8);
        let result = bw.finish();
        assert_eq!(result, vec![0xAB, 0xCD]);
    }

    // —— Deflate round‑trip tests —— //

    fn deflate_round_trip(block: DeflateBlockType, data: &[u8]) {
        let encoder = DeflateEncoder::new(block);
        let encoded = encoder.encode(data).expect("encode failed");
        let mut decoder = DeflateDecoder::new(&encoded[..]);
        let mut decoded = Vec::new();
        decoder.decode(&mut decoded).expect("Decode failed: ");
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_deflate_stored_round_trip() {
        deflate_round_trip(DeflateBlockType::Stored, b"Hello, stored!");
    }

    #[test]
    fn test_deflate_fixed_round_trip() {
        deflate_round_trip(DeflateBlockType::FixedHuffman, b"Hello, fixed!");
    }

    #[test]
    fn test_empty_input_deflate() {
        deflate_round_trip(DeflateBlockType::FixedHuffman, b"");
    }
  
    #[test]
    fn test_deflate_dynamic_round_trip() {
        deflate_round_trip(DeflateBlockType::DynamicHuffman, b"Hello, dynamic!");
    }
    // —— GZIP round‑trip tests —— //

    #[test]
    fn test_gzip_round_trip() {
        let encoder = GzEncoder::new();
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = encoder.encode(data).unwrap();
        // header magic
        assert_eq!(encoded[0], 0x1f);
        assert_eq!(encoded[1], 0x8b);

        // decode with your GzDecoder
        let decoded = GzDecoder::load(&encoded[..]).unwrap().decompress().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_empty_input_gzip() {
        let encoder = GzEncoder::new();
        let encoded = encoder.encode(&[]).unwrap();

        match GzDecoder::load(&encoded).unwrap().decompress() {
            Ok(decoded) => assert!(
                decoded.is_empty(),
                "Expected empty input to decode to empty output but got {}",
                decoded.len()
            ),
            Err(e) => panic!("Decoding empty input failed: {}", e),
        }
    }

    // —— Huffman code lengths error cases —— //

    #[test]
    fn test_huffman_code_lengths_all_zero_error() {
        let freqs = vec![0u32, 0, 0];
        assert!(huffman_code_lengths(&freqs, 15).is_err());
    }

    #[test]
    fn test_huffman_code_lengths_overflow_error() {
        let freqs = vec![1u32; 100];
        assert!(huffman_code_lengths(&freqs, 1).is_err());
    }

    // —— find_last_nonzero edge cases —— //

    #[test]
    fn test_find_last_nonzero_normal() {
        let lens = vec![1, 0, 2, 0, 3, 0];
        assert_eq!(find_last_nonzero(&lens), 4);
    }

    #[test]
    fn test_find_last_nonzero_all_zero() {
        let lens = vec![0, 0, 0];
        assert_eq!(find_last_nonzero(&lens), 0);
    }

    // —— CRC32 consistency & uniqueness —— //

    #[test]
    fn test_compute_crc32_nonzero() {
        let crc = compute_crc32(b"test");
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_crc32_consistency() {
        let a = compute_crc32(b"repeat");
        let b = compute_crc32(b"repeat");
        assert_eq!(a, b);
    }

    #[test]
    fn test_crc32_uniqueness() {
        let a = compute_crc32(b"foo");
        let b = compute_crc32(b"bar");
        assert_ne!(a, b);
    }

    #[test]
    fn test_dynamic_huffman_skewed() {
        // build highly skewed data: many 'A's and few other bytes
        let mut data = Vec::new();
        data.extend(std::iter::repeat(b'A').take(1000));
        data.extend(b"BCDE");

        // encode and decode using dynamic Huffman
        let encoder = DeflateEncoder::new(DeflateBlockType::DynamicHuffman);
        let encoded = encoder.encode(&data).expect("encode failed");
        let mut dec = DeflateDecoder::new(&encoded[..]);
        let mut out = Vec::new();
        dec.decode(&mut out).expect("decode failed");
        assert_eq!(out, data);

        // verify generated code lengths do not exceed 15 bits
        let tokens = lz77_parse(&data);
        let mut lit_freq = [0u32; 286];
        let mut dist_freq = [0u32; 32];
        lit_freq[256] = 1; // EOB
        dist_freq[0] = 1;
        for t in &tokens {
            match *t {
                Token::Literal(b) => lit_freq[b as usize] += 1,
                Token::Match { length, distance } => {
                    let (sym, _, _) = length_code_and_bits(length);
                    lit_freq[sym] += 1;
                    let (dsym, _, _) = distance_code_and_bits(distance);
                    dist_freq[dsym] += 1;
                }
            }
        }
        let ll = huffman_code_lengths(&lit_freq, 15).unwrap();
        let dl = huffman_code_lengths(&dist_freq, 15).unwrap();
        assert!(ll.iter().all(|&l| l <= 15));
        assert!(dl.iter().all(|&l| l <= 15));
    }

    // —— Compatibility with flate2 —— //

    #[test]
    fn test_encode_compatible_with_flate2_decoder() {
        use flate2::read::GzDecoder as FlateDecoder;
        use std::io::Read;

        let data = b"gzip interoperability test";
        let encoded = GzEncoder::new().encode(data).expect("encode failed");

        let mut decoder = FlateDecoder::new(&encoded[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("flate2 decode failed");
        assert_eq!(&out, data);
    }

    #[test]
    fn test_decode_flate2_encoded_data() {
        use flate2::{write::GzEncoder as FlateEncoder, Compression};
        use std::io::Write;

        let data = b"round trip via flate2";
        let mut enc = FlateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        let encoded = enc.finish().unwrap();

        let decoded = GzDecoder::load(&encoded).unwrap().decompress().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    #[ignore]
    fn bench_gzip_encode_speed() {
        let size = 288_399;
        let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let enc = GzEncoder::new();
        let now = std::time::Instant::now();
        let _ = enc.encode(&data).unwrap();
        eprintln!(
            "Encoding {} bytes took {} ms",
            size,
            now.elapsed().as_millis()
        );
    }
}
