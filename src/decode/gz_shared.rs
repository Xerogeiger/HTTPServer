/// For length codes 257–285:
/// (base length, # extra bits)
pub const LENGTH_BASE: [(usize, u8); 29] = [
    (3, 0),  (4, 0),  (5, 0),  (6, 0),   // 257–260
    (7, 0),  (8, 0),  (9, 0),  (10, 0),  // 261–264
    (11, 1), (13, 1), (15, 1), (17, 1),  // 265–268
    (19, 2), (23, 2), (27, 2), (31, 2),  // 269–272
    (35, 3), (43, 3), (51, 3), (59, 3),  // 273–276
    (67, 4), (83, 4), (99, 4), (115, 4), // 277–280
    (131, 5),(163, 5),(195, 5),(227, 5), // 281–284
    (258, 0),                         // 285 (no extra bits)
];

/// For distance codes 0–31:
/// (base distance, # extra bits)
pub const DIST_BASE: [(usize, u8); 30] = [
    (1, 0),   (2, 0),   (3, 0),   (4, 0),   // 0–3
    (5, 1),   (7, 1),   (9, 2),   (13, 2),  // 4–7
    (17, 3),  (25, 3),  (33, 4),  (49, 4),  // 8–11
    (65, 5),  (97, 5),  (129, 6), (193, 6), // 12–15
    (257, 7), (385, 7), (513, 8), (769, 8), // 16–19
    (1025, 9),(1537, 9),(2049,10),(3073,10),// 20–23
    (4097,11),(6145,11),(8193,12),(12289,12),// 24–27
    (16385,13),(24577,13)
];

/// Order for reading code‑length code lengths
pub const CODE_LENGTH_ORDER: [usize; 19] = [
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
];

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DeflateBlockType {
    Stored = 0,
    FixedHuffman = 1,
    DynamicHuffman = 2,
}

pub struct GzHeader {
    pub magic_number: u16,
    pub compression_method: u8,
    pub flags: u8,
    pub modification_time: u32,
    pub extra_flags: u8,
    pub operating_system: u8,

    pub is_ascii: bool,
    pub has_extra_field: bool,
    pub has_filename: bool,
    pub has_comment: bool,
    pub has_crc: bool,

    pub filename: Option<String>,
    pub extra_field: Option<Vec<u8>>,
    pub comment: Option<String>,
    pub crc32: u32,
    pub isize: u32,
}

impl GzHeader {
    pub fn new() -> Self {
        GzHeader {
            magic_number: 0x8b1f,
            compression_method: 8, // Deflate
            flags: 0,
            modification_time: 0,
            extra_flags: 0,
            operating_system: 255, // Unknown

            is_ascii: false,
            has_extra_field: false,
            has_filename: false,
            has_comment: false,
            has_crc: false,

            filename: None,
            extra_field: None,
            comment: None,
            crc32: 0,
            isize: 0,
        }
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
        self.is_ascii = (flags & 0x01) != 0;
        self.has_extra_field = (flags & 0x04) != 0;
        self.has_filename = (flags & 0x08) != 0;
        self.has_comment = (flags & 0x10) != 0;
        self.has_crc = (flags & 0x02) != 0;
    }

    pub fn set_filename(&mut self, filename: String) {
        self.filename = Some(filename);
        self.has_filename = true;
    }

    pub fn set_extra_field(&mut self, extra_field: Vec<u8>) {
        self.extra_field = Some(extra_field);
        self.has_extra_field = true;
    }

    pub fn set_comment(&mut self, comment: String) {
        self.comment = Some(comment);
        self.has_comment = true;
    }

    pub fn set_crc32(&mut self, crc32: u32) {
        self.crc32 = crc32;
        self.has_crc = true;
    }

    pub fn set_isize(&mut self, isize: u32) {
        self.isize = isize;
    }

    pub fn is_valid(&self) -> bool {
        self.magic_number == 0x8b1f && self.compression_method == 8
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend(&self.magic_number.to_le_bytes());
        header.push(self.compression_method);
        header.push(self.flags);
        header.extend(&self.modification_time.to_le_bytes());
        header.push(self.extra_flags);
        header.push(self.operating_system);

        if self.has_extra_field {
            if let Some(ref extra_field) = self.extra_field {
                let xlen = extra_field.len() as u16;
                header.extend(&xlen.to_le_bytes());
                header.extend(extra_field);
            } else {
                header.extend(&0u16.to_le_bytes());
            }
        }

        if self.has_filename {
            if let Some(ref filename) = self.filename {
                header.extend(filename.as_bytes());
            }
            header.push(0);
        }

        if self.has_comment {
            if let Some(ref comment) = self.comment {
                header.extend(comment.as_bytes());
            }
            header.push(0);
        }

        if self.has_crc {
            let crc = compute_crc16(&header);
            header.extend(&crc.to_le_bytes());
        }

        header
    }
}

const fn generate_crc32_table_const() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

pub const CRC32_TABLE: [u32; 256] = generate_crc32_table_const();

pub fn generate_crc32_table() -> [u32; 256] {
    CRC32_TABLE
}

pub fn compute_crc32(data: &[u8]) -> u32 {
    let table = &CRC32_TABLE;
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

pub fn compute_crc16(data: &[u8]) -> u16 {
    (compute_crc32(data) & 0xFFFF) as u16
}

/// Build a canonical Huffman `code → symbol` lookup table.
///
/// The returned map is keyed by `(code, bit_length)` where `code` is stored in
/// the DEFLATE bit order (least significant bit first).  The second value in
/// the tuple is the maximum code length present in `lens`.
pub fn build_codes(
    lens: &[u8],
) -> (std::collections::HashMap<(u32, u8), usize>, u8) {
    use std::collections::HashMap;
    // 1) Count how many codes of each length
    let max_bits = *lens.iter().max().unwrap_or(&0) as usize;
    let mut bl_count = vec![0u32; max_bits + 1];
    for &l in lens {
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }

    // 2) Determine the first code for each length
    let mut next_code = vec![0u32; max_bits + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    // 3) Build map: for each symbol, assign code if length > 0
    let mut table = HashMap::new();
    let mut max_len = 0u8;
    for (symbol, &len) in lens.iter().enumerate() {
        if len > 0 {
            let c = next_code[len as usize];
            let mut rev = 0u32;
            for i in 0..len {
                rev |= ((c >> i) & 1) << (len - 1 - i);
            }
            table.insert((rev, len), symbol);
            next_code[len as usize] += 1;
            if len > max_len { max_len = len; }
        }
    }

    (table, max_len)
}

/// Given a slice of code‐lengths `lens` (in bits) for each symbol,
/// produce a Vec of Option<(code, length)> where `code` is the
/// canonical Huffman code (LSB‐first) for that symbol.
pub fn gen_codes(lens: &[u8]) -> Vec<Option<(u32, u8)>> {
    // 1) Count how many codes of each length there are
    let max_bits = *lens.iter().max().unwrap() as usize;
    let mut bl_count = vec![0usize; max_bits + 1];
    for &l in lens {
        if l != 0 {
            bl_count[l as usize] += 1;
        }
    }

    // 2) Determine the first code for each length
    //    code = 0
    //    for bits = 1..=max_bits:
    //      code = (code + bl_count[bits-1]) << 1
    //      next_code[bits] = code
    let mut next_code = vec![0u32; max_bits + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code;
    }

    // 3) Assign codes to symbols in *symbol order*
    //    (i.e. ascending symbol index)
    let mut codes = Vec::with_capacity(lens.len());
    for &length in lens {
        if length == 0 {
            codes.push(None);
        } else {
            let mut c = next_code[length as usize];
            // Reverse bits for DEFLATE bit order
            let mut rev = 0u32;
            for i in 0..length {
                rev |= ((c >> i) & 1) << (length - 1 - i);
            }
            codes.push(Some((rev, length)));
            next_code[length as usize] += 1;
        }
    }

    codes
}

pub fn fixed_lit_len_lens() -> [u8; 288] {
    let mut lens = [0u8; 288];
    // 0–143 : 8 bits
    for i in 0..=143 { lens[i] = 8; }
    // 144–255 : 9 bits
    for i in 144..=255 { lens[i] = 9; }
    // 256–279 : 7 bits
    for i in 256..=279 { lens[i] = 7; }
    // 280–287 : 8 bits
    for i in 280..=287 { lens[i] = 8; }
    lens
}

pub fn fixed_dist_lens() -> [u8; 32] {
    [5u8; 32]
}