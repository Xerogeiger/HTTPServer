
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

/// Extension type for Server Name Indication (SNI).
pub const EXTENSION_SERVER_NAME: u16 = 0x0000;

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

/// TLS 1.2 ClientHello handshake payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    /// Extension type and raw data pairs.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&((self.cipher_suites.len() as u16 * 2).to_be_bytes()));
        for cs in &self.cipher_suites {
            out.extend_from_slice(&cs.to_be_bytes());
        }
        out.push(self.compression_methods.len() as u8);
        out.extend_from_slice(&self.compression_methods);
        let mut ext_bytes = Vec::new();
        for (ty, data) in &self.extensions {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(data);
        }
        out.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&ext_bytes);
        out
    }

    /// Return the first host name from the SNI extension if present.
    pub fn get_sni_hostname(&self) -> Option<String> {
        for (ty, data) in &self.extensions {
            if *ty == EXTENSION_SERVER_NAME {
                if data.len() < 2 { return None; }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + list_len || list_len == 0 { return None; }
                let mut idx = 2;
                if idx + 3 > data.len() { return None; }
                let name_type = data[idx];
                idx += 1;
                let len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
                idx += 2;
                if name_type != 0 || idx + len > data.len() { return None; }
                return std::str::from_utf8(&data[idx..idx + len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }
        None
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 34 { return None; }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);
        let mut idx = 34;
        let sid_len = data.get(idx)? as &u8;
        let sid_len = *sid_len as usize;
        idx += 1;
        if data.len() < idx + sid_len + 2 { return None; }
        let session_id = data[idx..idx + sid_len].to_vec();
        idx += sid_len;
        let cs_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + cs_len + 1 { return None; }
        let mut cipher_suites = Vec::new();
        for chunk in data[idx..idx + cs_len].chunks(2) {
            if chunk.len() != 2 { return None; }
            cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        idx += cs_len;
        let comp_len = data[idx] as usize;
        idx += 1;
        if data.len() < idx + comp_len { return None; }
        let compression_methods = data[idx..idx + comp_len].to_vec();
        idx += comp_len;
        if data.len() < idx + 2 { return None; }
        let ext_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + ext_len { return None; }
        let mut ext_idx = idx;
        let mut extensions = Vec::new();
        while ext_idx < idx + ext_len {
            if ext_idx + 4 > data.len() { return None; }
            let ty = u16::from_be_bytes([data[ext_idx], data[ext_idx + 1]]);
            let len = u16::from_be_bytes([data[ext_idx + 2], data[ext_idx + 3]]) as usize;
            ext_idx += 4;
            if ext_idx + len > data.len() { return None; }
            extensions.push((ty, data[ext_idx..ext_idx + len].to_vec()));
            ext_idx += len;
        }
        Some(ClientHello {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

/// TLS 1.2 ServerHello handshake payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
}

impl ServerHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.push(self.compression_method);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 38 { return None; }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);
        let mut idx = 34;
        let sid_len = data[idx] as usize;
        idx += 1;
        if data.len() < idx + sid_len + 3 { return None; }
        let session_id = data[idx..idx + sid_len].to_vec();
        idx += sid_len;
        let cipher_suite = u16::from_be_bytes([data[idx], data[idx + 1]]);
        idx += 2;
        let compression_method = data[idx];
        Some(ServerHello {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
        })
    }
}

/// TLS Certificate chain payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePayload {
    pub certificates: Vec<Vec<u8>>,
}

impl CertificatePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut chain_len = 0usize;
        for c in &self.certificates {
            chain_len += 3 + c.len();
        }
        let mut out = Vec::new();
        out.extend_from_slice(&((chain_len as u32).to_be_bytes()[1..]));
        for c in &self.certificates {
            out.extend_from_slice(&((c.len() as u32).to_be_bytes()[1..]));
            out.extend_from_slice(c);
        }
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 { return None; }
        let total_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
        if data.len() < 3 + total_len { return None; }
        let mut idx = 3;
        let mut certificates = Vec::new();
        while idx < 3 + total_len {
            if idx + 3 > data.len() { return None; }
            let len = ((data[idx] as usize) << 16) | ((data[idx + 1] as usize) << 8) | data[idx + 2] as usize;
            idx += 3;
            if idx + len > data.len() { return None; }
            certificates.push(data[idx..idx + len].to_vec());
            idx += len;
        }
        Some(CertificatePayload { certificates })
    }
}

/// TLS server key exchange parameters for ephemeral Diffie-Hellman.
///
/// The structure includes the hash and signature algorithm identifiers as
/// required by TLS 1.2. Only SHA-256 and RSA are supported, so the fields are
/// fixed to those values when sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchangeDH {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub public_key: Vec<u8>,
    pub hash: u8,
    pub sign: u8,
    pub signature: Vec<u8>,
}

impl ServerKeyExchangeDH {
    /// Serialize the structure including the signature fields.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.p);
        out.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.g);
        out.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.push(self.hash);
        out.push(self.sign);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Serialize without the signature components.
    pub fn to_bytes_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.p);
        out.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.g);
        out.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut idx = 0;
        if data.len() < 2 { return None; }
        let p_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + p_len + 2 { return None; }
        let p = data[idx..idx + p_len].to_vec();
        idx += p_len;
        let g_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + g_len + 2 { return None; }
        let g = data[idx..idx + g_len].to_vec();
        idx += g_len;
        let pub_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + pub_len + 4 { return None; }
        let public_key = data[idx..idx + pub_len].to_vec();
        idx += pub_len;
        let hash = data[idx];
        idx += 1;
        let sign = data[idx];
        idx += 1;
        let sig_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        if data.len() < idx + sig_len { return None; }
        let signature = data[idx..idx + sig_len].to_vec();
        Some(ServerKeyExchangeDH { p, g, public_key, hash, sign, signature })
    }
}

/// TLS client key exchange parameters for ephemeral Diffie-Hellman.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyExchangeDH {
    pub public_key: Vec<u8>,
}

impl ClientKeyExchangeDH {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 { return None; }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len { return None; }
        Some(ClientKeyExchangeDH { public_key: data[2..2 + len].to_vec() })
    }
}

/// TLS Finished message payload containing the verify_data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Return the serialized bytes of the verify_data.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verify_data.clone()
    }

    /// Parse a Finished payload from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Some(Finished { verify_data: data.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let hello = ClientHello {
            version: 0x0303,
            random: [1u8; 32],
            session_id: vec![1, 2, 3],
            cipher_suites: vec![0x0067],
            compression_methods: vec![0],
            extensions: vec![(0, vec![0, 5, 0, 3, 0, 1, b'a'])],
        };
        let bytes = hello.to_bytes();
        let parsed = ClientHello::parse(&bytes).unwrap();
        assert_eq!(hello, parsed);
    }

    #[test]
    fn server_hello_roundtrip() {
        let hello = ServerHello {
            version: 0x0303,
            random: [2u8; 32],
            session_id: vec![],
            cipher_suite: 0x0067,
            compression_method: 0,
        };
        let bytes = hello.to_bytes();
        let parsed = ServerHello::parse(&bytes).unwrap();
        assert_eq!(hello, parsed);
    }
}