
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Certificate = 0x0b,
    ServerKeyExchange = 0x0c,
    CertificateRequest = 0x0d,
    ServerHelloDone = 0x0e,
    CertificateVerify = 0x0f,
    ClientKeyExchange = 0x10,
    Finished = 0x14,
}

impl TryFrom<u8> for HandshakeType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(HandshakeType::HelloRequest),
            0x01 => Ok(HandshakeType::ClientHello),
            0x02 => Ok(HandshakeType::ServerHello),
            0x0b => Ok(HandshakeType::Certificate),
            0x0c => Ok(HandshakeType::ServerKeyExchange),
            0x0d => Ok(HandshakeType::CertificateRequest),
            0x0e => Ok(HandshakeType::ServerHelloDone),
            0x0f => Ok(HandshakeType::CertificateVerify),
            0x10 => Ok(HandshakeType::ClientKeyExchange),
            0x14 => Ok(HandshakeType::Finished),
            _ => Err("Invalid Handshake Type"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub handshake_type: HandshakeType,
    pub message: Vec<u8>,
}

impl HandshakeMessage {
    pub fn new(handshake_type: HandshakeType, message: Vec<u8>) -> Self {
        HandshakeMessage {
            handshake_type,
            message,
        }
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None; // No data to parse
        }

        let handshake_type = HandshakeType::try_from(data[0]).ok();
        let length = ((data[1] as usize) << 16)
            | ((data[2] as usize) << 8)
            |  (data[3] as usize);
        if data.len() < 4 + length {
            return None; // Not enough data for the message
        }
        let message = data[4..4 + length].to_vec();
        if let Some(handshake_type) = handshake_type {
            Some((
                HandshakeMessage::new(handshake_type, message),
                4 + length, // Return the total length of the parsed message
            ))
        } else {
            None // Invalid handshake type
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.message.len());
        bytes.push(self.handshake_type as u8);
        let len = self.message.len();
        bytes.push(((len >> 16) & 0xff) as u8);
        bytes.push(((len >>  8) & 0xff) as u8);
        bytes.push(( len        & 0xff) as u8);
        bytes.extend_from_slice(&self.message);
        bytes
    }
}