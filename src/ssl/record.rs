pub type ContentType = u8;

#[derive(Debug)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None; // Not enough data for header
        }
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);
        Some(RecordHeader {
            content_type,
            version,
            length,
        })
    }

    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = self.content_type;
        bytes[1..3].copy_from_slice(&self.version.to_be_bytes());
        bytes[3..5].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }
}