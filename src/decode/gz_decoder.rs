use std::collections::HashMap;
use std::io;
use crate::decode::gz_shared::{
    fixed_dist_lens, fixed_lit_len_lens, build_codes, generate_crc32_table,
    compute_crc16, GzHeader, CODE_LENGTH_ORDER, DIST_BASE, LENGTH_BASE,
};
use crate::decode::lz77::{lz77_reconstruct, Token};

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, byte_pos: 0, bit_pos: 0 }
    }

    /// Read a single bit (0 or 1)
    fn read_bit(&mut self) -> io::Result<u8> {
        if self.byte_pos >= self.data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF in bitstream"));
        }
        let byte = self.data[self.byte_pos];
        let bit = (byte >> self.bit_pos) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Ok(bit)
    }

    /// Read multiple bits (little‑endian)
    fn read_bits(&mut self, mut count: u8) -> io::Result<u32> {
        let mut acc = 0u32;
        for i in 0..count {
            let b = self.read_bit()? as u32;
            acc |= b << i;
        }
        Ok(acc)
    }

    /// Move to next byte boundary
    fn align_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }
}

pub struct GzDecoder {
    pub header: GzHeader,
    pub compressed_data: Vec<u8>,
}

pub struct DeflateDecoder {
    encoded_data : Vec<u8>,
}

impl DeflateDecoder {
    pub(crate) fn new(encoded_data: &[u8]) -> DeflateDecoder {
        DeflateDecoder {
            encoded_data: encoded_data.to_vec(),
        }
    }

    pub(crate) fn decode(&mut self, out: &mut Vec<u8>) -> Result<(), io::Error> {
        // 1) DEFLATE → LZ77 token stream
        let tokens = inflate_to_tokens(&self.encoded_data)?;
        // 2) LZ77 reconstruct → raw bytes
        let reconstructed = lz77_reconstruct(&tokens);
        out.extend(reconstructed);
        Ok(())
    }
}

/// Decode the raw DEFLATE bitstream into LZ77 tokens
fn inflate_to_tokens(data: &[u8]) -> io::Result<Vec<Token>> {
    let mut br = BitReader::new(data);
    let mut tokens = Vec::new();

    loop {
        let is_last = br.read_bit()? == 1;
        let btype  = br.read_bits(2)?;
        match btype {
            0 => {
                // Stored
                br.align_byte();
                let len  = br.read_bits(16)? as usize;
                let nlen = br.read_bits(16)? as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "LEN/NLEN mismatch"));
                }
                for _ in 0..len {
                    let b = br.read_bits(8)? as u8;
                    tokens.push(Token::Literal(b));
                }
            }
            1 | 2 => {
                // Huffman
                let (ll_codes, ll_max, dist_codes, dist_max) = if btype==1 {
                    let ll = fixed_lit_len_lens();
                    let dd = fixed_dist_lens();
                    let (lc, lm) = build_codes(&ll);
                    let (dc, dm) = build_codes(&dd);
                    (lc, lm, dc, dm)
                } else {
                    // dynamic: read HLIT, HDIST, HCLEN… build codes
                    let hlit  = br.read_bits(5)? as usize + 257;
                    let hdist = br.read_bits(5)? as usize + 1;
                    let hclen = br.read_bits(4)? as usize + 4;
                    let mut clens = [0u8;19];
                    for i in 0..hclen {
                        clens[CODE_LENGTH_ORDER[i]] = br.read_bits(3)? as u8;
                    }
                    let (cl_codes, cl_max) = build_codes(&clens);
                    // read lengths
                    let mut lit_lens  = vec![0u8; hlit];
                    let mut dist_lens = vec![0u8; hdist];
                    let mut i = 0;
                    while i < hlit+hdist {
                        let sym = decode_symbol(&mut br, &cl_codes, cl_max)?;
                        match sym {
                            0..=15 => {
                                if i<hlit { lit_lens[i]=sym as u8; } else { dist_lens[i-hlit]=sym as u8; }
                                i+=1;
                            }
                            16 => {
                                if i == 0 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "Repeat code with no previous length",
                                    ));
                                }
                                let rpt = br.read_bits(2)? as usize + 3;
                                let prev = if i < hlit {
                                    lit_lens[i - 1]
                                } else {
                                    dist_lens[i - hlit - 1]
                                };
                                for _ in 0..rpt {
                                    if i < hlit {
                                        lit_lens[i] = prev;
                                    } else {
                                        dist_lens[i - hlit] = prev;
                                    }
                                    i += 1;
                                }
                            }
                            17 => {
                                let rpt = br.read_bits(3)? as usize + 3;
                                for _ in 0..rpt {
                                    if i<hlit { lit_lens[i]=0; } else { dist_lens[i-hlit]=0; }
                                    i+=1;
                                }
                            }
                            18 => {
                                let rpt = br.read_bits(7)? as usize + 11;
                                for _ in 0..rpt {
                                    if i<hlit { lit_lens[i]=0; } else { dist_lens[i-hlit]=0; }
                                    i+=1;
                                }
                            }
                            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid code-length symbol")),
                        }
                    }
                    let (lc, lm) = build_codes(&lit_lens);
                    let (dc, dm) = build_codes(&dist_lens);
                    (lc, lm, dc, dm)
                };
                // decode tokens
                loop {
                    let sym = decode_symbol(&mut br, &ll_codes, ll_max)?;
                    if sym < 256 {
                        tokens.push(Token::Literal(sym as u8));
                    } else if sym==256 {
                        break;
                    } else {
                        // length
                        let (base, extra) = LENGTH_BASE[sym-257];
                        let ext = br.read_bits(extra)? as usize;
                        let length = base + ext;
                        // distance
                        let dsym = decode_symbol(&mut br, &dist_codes, dist_max)?;
                        let (dbase, dex) = DIST_BASE[dsym];
                        let dext = br.read_bits(dex)? as usize;
                        let distance = dbase + dext;
                        tokens.push(Token::Match { length, distance });
                    }
                }
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid block type {}", btype))),
        }
        if is_last { break; }
    }
    Ok(tokens)
}

fn decode_symbol(
    br: &mut BitReader,
    codes: &std::collections::HashMap<(u32, u8), usize>,
    max_len: u8,
) -> io::Result<usize> {
    let mut acc = 0u32;
    for bit_len in 1..=max_len {
        let b = br.read_bit()? as u32;
        acc |= b << (bit_len - 1);
        if let Some(&sym) = codes.get(&(acc, bit_len)) {
            return Ok(sym);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Huffman code"))
}


/// Decode huffman-compressed sequences given literal/length and distance trees
fn decode_huffman_data(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    ll_codes: &std::collections::HashMap<(u32, u8),usize>,
    ll_max: u8,
    d_codes: &std::collections::HashMap<(u32, u8),usize>,
    d_max: u8,
) -> io::Result<()> {
    loop {
        let sym = decode_symbol(br, ll_codes, ll_max)?;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            break;
        } else {
            let (base, extra) = LENGTH_BASE[sym-257];
            let len = base + br.read_bits(extra)? as usize;
            let dsym = decode_symbol(br, d_codes, d_max)?;
            let (dbase, dextra) = DIST_BASE[dsym];
            let dist = dbase + br.read_bits(dextra)? as usize;
            let start = out.len().checked_sub(dist).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid distance"))?;
            for i in 0..len {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    Ok(())
}

impl GzDecoder {
    pub fn load(data: &[u8]) -> Result<GzDecoder, io::Error> {
        if data.len() < 10 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short"));
        }

        let mut idx = 0usize;
        let magic_number = u16::from_le_bytes([data[idx], data[idx+1]]); idx += 2;
        let compression_method = data[idx]; idx += 1;
        let flags = data[idx]; idx += 1;
        let modification_time = u32::from_le_bytes([data[idx], data[idx+1], data[idx+2], data[idx+3]]); idx += 4;
        let extra_flags = data[idx]; idx += 1;
        let operating_system = data[idx]; idx += 1;

        let is_ascii = flags & 0x01 != 0;
        let has_crc = flags & 0x02 != 0;
        let has_extra_field = flags & 0x04 != 0;
        let has_filename = flags & 0x08 != 0;
        let has_comment = flags & 0x10 != 0;

        // 2) Optional fields
        // Extra field
        let extra_field = if has_extra_field {
            if idx + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short"));
            }
            let xlen = u16::from_le_bytes([data[idx], data[idx+1]]) as usize;
            idx += 2;
            if idx + xlen > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short"));
            }
            let buf = data[idx..idx+xlen].to_vec();
            idx += xlen;
            Some(buf)
        } else {
            None
        };

        // Original filename
        let filename = if has_filename {
            let start = idx;
            while idx < data.len() && data[idx] != 0 { idx += 1; }
            if idx >= data.len() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short")); }
            let name = String::from_utf8_lossy(&data[start..idx]).into_owned();
            idx += 1; // skip null
            Some(name)
        } else {
            None
        };

        // File comment
        let comment = if has_comment {
            let start = idx;
            while idx < data.len() && data[idx] != 0 { idx += 1; }
            if idx >= data.len() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short")); }
            let c = String::from_utf8_lossy(&data[start..idx]).into_owned();
            idx += 1; // skip null
            Some(c)
        } else {
            None
        };

        // Header CRC
        if has_crc {
            if idx + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip header too short"));
            }
            let stored = u16::from_le_bytes([data[idx], data[idx+1]]);
            let calc = compute_crc16(&data[..idx]);
            if stored != calc {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Header CRC mismatch"));
            }
            idx += 2;
        }

        // 3) Remaining bytes: compressed data + 8-byte trailer
        if data.len() < idx + 8 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "GZip file too short"));
        }
        let trailer_pos = data.len() - 8;
        let compressed_data = data[idx..trailer_pos].to_vec();

        // 4) Parse trailer
        let crc32 = u32::from_le_bytes(data[trailer_pos..trailer_pos+4].try_into().unwrap());
        let isize = u32::from_le_bytes(data[trailer_pos+4..].try_into().unwrap());

        Ok(GzDecoder {
            header: GzHeader {
                magic_number,
                compression_method,
                flags,
                modification_time,
                extra_flags,
                operating_system,
                is_ascii,
                has_extra_field,
                has_filename,
                has_comment,
                has_crc,
                filename,
                extra_field,
                comment,
                crc32,
                isize,
            },
            compressed_data,
        })
    }

    pub fn decompress(&self) -> Result<Vec<u8>, io::Error> {
        // 1) DEFLATE decode
        let mut decoder = DeflateDecoder::new(&self.compressed_data[..]);
        let mut out = Vec::new();
        decoder.decode(&mut out)?;

        // 2) CRC32 verification
        if self.header.has_crc {
            let table = generate_crc32_table();
            let mut crc = 0xFFFF_FFFFu32;
            for &b in &out {
                let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
                crc = (crc >> 8) ^ table[idx];
            }
            crc ^= 0xFFFF_FFFF;
            if crc != self.header.crc32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "CRC32 mismatch"));
            }
        }

        // 3) ISIZE verification
        if (out.len() as u32) != self.header.isize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ISIZE mismatch"));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inflate_stored_block() {
        // Stored block for "ABC": header bits (BFINAL=1,BTYPE=00)
        let data = vec![
            0x01,       // 1-bit final, BTYPE=00, padded
            3, 0,       // LEN = 3
            0xFC, 0xFF, // NLEN = ~3
            b'A', b'B', b'C'
        ];
        let out = inflate_to_tokens(&data).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], Token::Literal(b'A'));
        assert_eq!(out[1], Token::Literal(b'B'));
        assert_eq!(out[2], Token::Literal(b'C'));
    }

    #[test]
    fn test_inflate_fixed_empty() {
        // Fixed block with only EOB
        let data = vec![
            0x03, // BFINAL=1,BTYPE=01, EOB bits
            0x00, // padding
        ];
        let out = inflate_to_tokens(&data).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_fixed_lit_len_lens() {
        let lens = fixed_lit_len_lens();
        assert_eq!(lens[0], 8);
        assert_eq!(lens[143], 8);
        assert_eq!(lens[144], 9);
        assert_eq!(lens[255], 9);
        assert_eq!(lens[256], 7);
        assert_eq!(lens[280], 8);
    }

    #[test]
    fn test_fixed_dist_lens() {
        let lens = fixed_dist_lens();
        for &l in &lens {
            assert_eq!(l, 5);
        }
    }

    #[test]
    fn test_crc32_table_first_entries() {
        let table = generate_crc32_table();
        assert_eq!(table[0], 0);
        assert_eq!(table[1], 0x77073096);
    }

    #[test]
    fn test_generate_crc32_and_validate() {
        // CRC32 of "hello" (lowercase) is 0x3610A686
        let table = generate_crc32_table();
        let mut crc = 0xFFFF_FFFFu32;
        for &b in b"hello" {
            let idx = ((crc ^ b as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ table[idx];
        }
        crc ^= 0xFFFF_FFFF;
        assert_eq!(crc, 0x3610A686);
    }

    #[test]
    fn test_decode_symbol_simple() {
        // One-bit codes: 0->A, 1->B
        let bits = &[0b00000010]; // bit0=0->sym0, bit1=1->sym1
        let mut br = BitReader::new(bits);
        let mut codes = std::collections::HashMap::new();
        codes.insert((0,1), 65); // 'A'
        codes.insert((1,1), 66); // 'B'
        let sym1 = decode_symbol(&mut br, &codes, 1).unwrap();
        assert_eq!(sym1, 65);
        let sym2 = decode_symbol(&mut br, &codes, 1).unwrap();
        assert_eq!(sym2, 66);
    }

    #[test]
    fn test_load_with_extra_and_crc() {
        use crate::decode::gz_encoder::DeflateEncoder;
        use crate::decode::gz_shared::{compute_crc32, compute_crc16, DeflateBlockType};

        let mut hdr = GzHeader::new();
        hdr.set_flags(0x04 | 0x02); // FEXTRA | FHCRC
        hdr.set_extra_field(vec![0xAA, 0xBB, 0xCC]);
        let header_bytes = hdr.to_bytes();

        let deflated = DeflateEncoder::new(DeflateBlockType::FixedHuffman)
            .encode(b"hi")
            .unwrap();

        let mut gzip = Vec::new();
        gzip.extend_from_slice(&header_bytes);
        gzip.extend_from_slice(&deflated);
        let crc32 = compute_crc32(b"hi");
        gzip.extend_from_slice(&crc32.to_le_bytes());
        gzip.extend_from_slice(&(2u32).to_le_bytes());

        let decoder = GzDecoder::load(&gzip).unwrap();
        assert!(decoder.header.has_extra_field);
        assert!(decoder.header.has_crc);
        assert_eq!(decoder.header.extra_field.as_ref().unwrap(), &vec![0xAA,0xBB,0xCC]);
        // verify header CRC parsed correctly by recomputing
        let calc = compute_crc16(&gzip[..header_bytes.len()-2]);
        let stored = u16::from_le_bytes([header_bytes[header_bytes.len()-2], header_bytes[header_bytes.len()-1]]);
        assert_eq!(calc, stored);

        let out = decoder.decompress().unwrap();
        assert_eq!(out, b"hi");
    }

    // —— Interoperability with flate2 —— //

    #[test]
    fn test_decode_flate2_gzip() {
        use flate2::{Compression, write::GzEncoder as FlateEncoder};
        use std::io::Write;

        let data = b"decoder compatibility";
        let mut enc = FlateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        let encoded = enc.finish().unwrap();

        let out = GzDecoder::load(&encoded).unwrap().decompress().unwrap();
        assert_eq!(&out, data);
    }

    #[test]
    fn test_flate2_can_decode_encoder_output() {
        use flate2::read::GzDecoder as FlateDecoder;
        use std::io::Read;

        let data = b"encoder compatibility";
        let encoded = super::super::gz_encoder::GzEncoder::new()
            .encode(data)
            .unwrap();

        let mut dec = FlateDecoder::new(&encoded[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).expect("flate2 decode");
        assert_eq!(&out, data);
    }

    #[test]
    fn test_repeat_code_length_without_previous() {
        // Craft dynamic block where the first code-length symbol is 16,
        // which should result in an error instead of a panic.
        let data = vec![0x05, 0x00, 0x02, 0x00];
        let res = inflate_to_tokens(&data);
        assert!(res.is_err());
    }
}