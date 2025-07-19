use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use crate::decode::gz_shared::{fixed_dist_lens, fixed_lit_len_lens, gen_codes, generate_crc32_table, DeflateBlockType, GzHeader, CODE_LENGTH_ORDER};
use crate::decode::lz77::{distance_code_and_bits, length_code_and_bits, lz77_parse, Token};

struct BitWriter {
    out: Vec<u8>,
    bit_buf: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter { out: Vec::new(), bit_buf: 0, bit_count: 0 }
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
        Ok(out)
    }

    fn encode_stored(&self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let chunk = &data[offset..(offset+0xFFFF).min(data.len())];
            let is_last = offset+chunk.len()==data.len();
            // header bits
            let mut bw = BitWriter::new();
            bw.write_bit(if is_last{1}else{0}); // BFINAL
            bw.write_bits(0,2);                   // BTYPE=00
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
                Token::Literal(b) => { lit_freq[b as usize] += 1; }
                Token::Match { length, distance } => {
                    let (sym, _, _) = length_code_and_bits(length);
                    lit_freq[sym] += 1;
                    let (dsym, _, _) = distance_code_and_bits(distance);
                    dist_freq[dsym] += 1;
                }
            }
        }

        // 2) generate code lengths
        let lit_lens = huffman_code_lengths(&lit_freq, 15)?;
        let dist_lens = huffman_code_lengths(&dist_freq, 15)?;

        // 3) write HLIT, HDIST, HCLEN
        let last_lit = find_last_nonzero(&lit_lens);
        let last_dist = find_last_nonzero(&dist_lens);
        let hlit = (last_lit + 1) - 257;
        let hdist = (last_dist + 1) - 1;
        let clens = build_clens(&lit_lens, &dist_lens)?;
        let last_clen = find_last_nonzero(&clens);
        let hclen = (last_clen + 1) - 4;
        bw.write_bits(hlit as u32, 5);
        bw.write_bits(hdist as u32, 5);
        bw.write_bits(hclen as u32, 4);

        // 4) emit code-length tree
        for &i in &CODE_LENGTH_ORDER[..(hclen+4) as usize] {
            bw.write_bits(clens[i] as u32, 3);
        }
        // RLE of lengths using code-length codes
        let cl_codes = gen_codes(&clens);
        let mut combined = Vec::with_capacity(last_lit+1 + last_dist+1);
        combined.extend_from_slice(&lit_lens[..last_lit+1]);
        combined.extend_from_slice(&dist_lens[..last_dist+1]);
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
    pub fn new() -> Self { GzEncoder { header: GzHeader::new() } }

    pub fn encode(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        // 1) GZip header
        out.extend_from_slice(&self.header.to_bytes());

        #[cfg(debug_assertions)]
        {
            print!("GZip header: ");
            for byte in &out {
                print!("{:02x} ", byte);
            }
            println!();
        }

        // 2) Body
        let mut deflate = DeflateEncoder::new(DeflateBlockType::FixedHuffman);
        let deflated_data = deflate.encode(data)?;
        out.extend_from_slice(&deflated_data);

        #[cfg(debug_assertions)]
        {
            print!("Deflated data: ");
            for byte in &deflated_data {
                print!("{:02x} ", byte);
            }
            println!();
        }

        // 3) Trailer
        let crc = compute_crc32(data);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());

        #[cfg(debug_assertions)]
        {
            print!("GZip trailer: ");
            for byte in &out[out.len()-8..] {
                print!("{:02x} ", byte);
            }
            println!();
        }

        #[cfg(debug_assertions)]
        {
            print!("Full GZip packet: ");
            for b in &out {
                print!("{:02x} ", b);
            }
            println!();
        }

        Ok(out)
    }
}

/// Compute code lengths (depths) for Huffman coding using a simple binary-tree algorithm.
/// Symbol_frequencies: slice of symbol frequencies (length = number of symbols).
/// Max_bits: maximum allowed code length (e.g. 15 for DEFLATE).
/// Returns a Vec<u8> of code lengths per symbol, or an error if any exceed max_bits.
fn huffman_code_lengths(symbol_frequencies: &[u32], max_bits: usize) -> io::Result<Vec<u8>> {
    let n = symbol_frequencies.len();
    // Node in forest: either leaf(symbol) or internal(children)
    struct Node { freq: u32, symbol: Option<usize>, left: Option<usize>, right: Option<usize> }

    // 1) Initialize nodes and heap
    let mut nodes: Vec<Node> = Vec::new();
    let mut heap = BinaryHeap::new(); // min-heap via Reverse

    for (i, &f) in symbol_frequencies.iter().enumerate() {
        if f > 0 {
            let idx = nodes.len();
            nodes.push(Node { freq: f, symbol: Some(i), left: None, right: None });
            heap.push(Reverse((f, idx)));
        }
    }
    // Ensure at least two nodes to build a tree
    if heap.len() == 1 {
        let (f, _) = heap.peek().unwrap().0;
        let idx = nodes.len();
        nodes.push(Node { freq: 0, symbol: None, left: None, right: None });
        heap.push(Reverse((0, idx)));
    }
    if heap.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "No symbols to encode"));
    }

    // 2) Build the Huffman tree
    while heap.len() > 1 {
        let Reverse((f1, i1)) = heap.pop().unwrap();
        let Reverse((f2, i2)) = heap.pop().unwrap();
        let parent_idx = nodes.len();
        nodes.push(Node { freq: f1 + f2, symbol: None, left: Some(i1), right: Some(i2) });
        heap.push(Reverse((f1 + f2, parent_idx)));
    }
    let root = heap.pop().unwrap().0.1;

    // 3) Traverse the tree to assign lengths
    let mut lengths = vec![0u8; n];
    fn assign_depth(nodes: &Vec<Node>, idx: usize, depth: u8, lengths: &mut [u8]) {
        let node = &nodes[idx];
        if let Some(sym) = node.symbol {
            lengths[sym] = depth;
        } else {
            if let Some(l) = node.left  { assign_depth(nodes, l, depth + 1, lengths); }
            if let Some(r) = node.right { assign_depth(nodes, r, depth + 1, lengths); }
        }
    }
    assign_depth(&nodes, root, 0, &mut lengths);

    // 4) Check max_bits
    if let Some(&d) = lengths.iter().max() {
        if (d as usize) > max_bits {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Code length {} exceeds max {}", d, max_bits)));
        }
    }

    Ok(lengths)
}

/// Find the last index with a non-zero length (or 0 if all are zero).
fn find_last_nonzero(lens: &[u8]) -> usize {
    lens.iter()
        .rposition(|&l| l != 0)
        .unwrap_or(0)
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
    use std::io::Read;
    use crate::decode::gz_decoder::{DeflateDecoder, GzDecoder};

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
        decoder
            .decode(&mut decoded)
            .expect("Decode failed: ");
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
    fn test_deflate_dynamic_round_trip() {
        deflate_round_trip(DeflateBlockType::DynamicHuffman, b"Hello, dynamic!");
    }

    #[test]
    fn test_empty_input_deflate() {
        deflate_round_trip(DeflateBlockType::FixedHuffman, b"");
    }

    #[test]
    fn test_single_byte_deflate() {
        deflate_round_trip(DeflateBlockType::DynamicHuffman, b"A");
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
        let decoded = GzDecoder::load(&encoded[..])
            .unwrap()
            .decompress()
            .unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_empty_input_gzip() {
        let encoder = GzEncoder::new();
        let encoded = encoder.encode(&[]).unwrap();

        match GzDecoder::load(&encoded).unwrap().decompress() {
            Ok(decoded) => assert!(decoded.is_empty(), "Expected empty input to decode to empty output but got {}", decoded.len()),
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
}