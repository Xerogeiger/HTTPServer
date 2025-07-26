use std::io::{Read, Write};
use std::net::TcpStream;

use super::aes::AesCipher;
use super::record::{decrypt_record, encrypt_record, ContentType, RecordHeader, TLS_VERSION_1_2};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TlsState {
    Plain,     // No TLS, plain text communication
    Handshake, // TLS handshake in progress
    Encrypted, // TLS established, encrypted communication
    Closed,    // TLS connection closed
}

pub struct TlsSession {
    stream: TcpStream,
    state: TlsState,
    buffer: Vec<u8>, // Buffer for incoming data
    cipher: Option<AesCipher>,
    mac_key: Vec<u8>,
    iv: [u8; 16],
    read_cipher: Option<AesCipher>,
    read_mac_key: Vec<u8>,
    read_iv: [u8; 16],
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_iv: [u8; 16],
    server_iv: [u8; 16],
    write_seq: u64,
    read_seq: u64,
    write_encrypted: bool,
    read_encrypted: bool,
}

impl Clone for TlsSession {
    fn clone(&self) -> Self {
        TlsSession {
            stream: self.stream.try_clone().expect("Failed to clone stream"),
            state: self.state,
            buffer: self.buffer.clone(),
            cipher: self.cipher.clone(),
            mac_key: self.mac_key.clone(),
            iv: self.iv,
            read_cipher: self.read_cipher.clone(),
            read_mac_key: self.read_mac_key.clone(),
            read_iv: self.read_iv,
            client_mac_key: self.client_mac_key.clone(),
            server_mac_key: self.server_mac_key.clone(),
            client_iv: self.client_iv,
            server_iv: self.server_iv,
            write_seq: self.write_seq,
            read_seq: self.read_seq,
            write_encrypted: self.write_encrypted,
            read_encrypted: self.read_encrypted,
        }
    }
}

impl TlsSession {
    /// Create a new `TlsSession` in plaintext mode.
    pub fn new(stream: TcpStream) -> Self {
        TlsSession {
            stream,
            state: TlsState::Plain,
            buffer: Vec::new(),
            cipher: None,
            mac_key: Vec::new(),
            iv: [0u8; 16],
            read_cipher: None,
            read_mac_key: Vec::new(),
            read_iv: [0u8; 16],
            client_mac_key: Vec::new(),
            server_mac_key: Vec::new(),
            client_iv: [0u8; 16],
            server_iv: [0u8; 16],
            write_seq: 0,
            read_seq: 0,
            write_encrypted: false,
            read_encrypted: false,
        }
    }

    /// Enable encrypted mode using the provided cipher, MAC key and IV.
    pub fn enable_encryption(
        &mut self,
        write_cipher: AesCipher,
        write_mac_key: Vec<u8>,
        write_iv: [u8; 16],
        read_cipher: AesCipher,
        read_mac_key: Vec<u8>,
        read_iv: [u8; 16],
    ) {
        self.cipher = Some(write_cipher);
        self.mac_key = write_mac_key;
        self.iv = write_iv;
        self.read_cipher = Some(read_cipher);
        self.read_mac_key = read_mac_key;
        self.read_iv = read_iv;
        self.write_seq = 0;
        self.read_seq = 0;
        self.write_encrypted = true;
        self.read_encrypted = true;
        self.state = TlsState::Encrypted;
    }

    /// Get the current read sequence number.
    pub fn get_read_seq(&self) -> u64 {
        self.read_seq
    }

    /// Manually set the read sequence number.
    pub fn set_read_seq(&mut self, seq: u64) {
        self.read_seq = seq;
    }

    /// Configure only the read-side encryption parameters without
    /// switching the connection state to `Encrypted`.
    pub fn set_read_encryption(
        &mut self,
        read_cipher: AesCipher,
        read_mac_key: Vec<u8>,
        read_iv: [u8; 16],
    ) {
        self.read_cipher = Some(read_cipher);
        self.read_mac_key = read_mac_key;
        self.read_iv = read_iv;
        self.read_encrypted = true;
    }

    /// Configure only the write-side encryption parameters without changing
    /// the read cipher or connection state.
    pub fn set_write_encryption(
        &mut self,
        write_cipher: AesCipher,
        write_mac_key: Vec<u8>,
        write_iv: [u8; 16],
    ) {
        self.cipher = Some(write_cipher);
        self.mac_key = write_mac_key;
        self.iv = write_iv;
        self.write_encrypted = true;
    }

    /// Store key material derived during handshake.
    pub fn set_key_material(
        &mut self,
        client_mac: Vec<u8>,
        server_mac: Vec<u8>,
        client_iv: [u8; 16],
        server_iv: [u8; 16],
    ) {
        self.client_mac_key = client_mac;
        self.server_mac_key = server_mac;
        self.client_iv = client_iv;
        self.server_iv = server_iv;
    }

    /// Update the internal TLS state machine.
    pub fn set_state(&mut self, state: TlsState) {
        self.state = state;
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.local_addr()
    }

    /// Send a TLS record with the given `content_type` and `payload`.
    pub fn send(&mut self, content_type: ContentType, payload: &[u8]) -> std::io::Result<()> {
        let data = if self.write_encrypted {
            let cipher = self.cipher.as_ref().expect("cipher not set");
            let out = encrypt_record(content_type, payload, cipher, &self.mac_key, self.write_seq);
            self.write_seq = self.write_seq.wrapping_add(1);
            out
        } else {
            let header = RecordHeader {
                content_type,
                version: TLS_VERSION_1_2,
                length: payload.len() as u16,
            };
            let mut out = Vec::new();
            out.extend_from_slice(&header.to_bytes());
            out.extend_from_slice(payload);
            out
        };
        self.stream.write_all(&data)
    }

    /// Receive the next TLS record from the stream.
    pub fn recv(&mut self) -> std::io::Result<(ContentType, Vec<u8>)> {
        let mut header_buf = [0u8; 5];
        self.stream.read_exact(&mut header_buf)?;
        let header = RecordHeader::parse(&header_buf).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header")
        })?;
        let mut payload = vec![0u8; header.length as usize];
        self.stream.read_exact(&mut payload)?;
        let decrypt = self.read_encrypted;
        if decrypt {
            let cipher = self.read_cipher.as_ref().expect("cipher not set");
            let record = decrypt_record(&header, &payload, cipher, &self.read_mac_key, self.read_seq)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "MAC check failed")
                })?;
            self.read_seq = self.read_seq.wrapping_add(1);
            Ok((record.header.content_type, record.payload))
        } else {
            Ok((header.content_type, payload))
        }
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.state = TlsState::Closed;
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

impl Read for TlsSession {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            let (ct, data) = self.recv()?;
            if ct != 23 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected content type",
                ));
            }
            self.buffer = data;
        }
        let n = std::cmp::min(buf.len(), self.buffer.len());
        buf[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.drain(0..n);
        Ok(n)
    }
}

impl Write for TlsSession {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(23, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn session_send_recv_encrypted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(socket);
            let cipher = AesCipher::new_128(&[0u8; 16]);
            server.enable_encryption(
                cipher.clone(),
                b"mac-key".to_vec(),
                [1u8; 16],
                cipher.clone(),
                b"mac-key".to_vec(),
                [1u8; 16],
            );
            let (ct, data) = server.recv().unwrap();
            assert_eq!(ct, 23);
            assert_eq!(data, b"secret");
            server.send(23, b"ack").unwrap();
        });

        let client_socket = TcpStream::connect(addr).unwrap();
        let mut client = TlsSession::new(client_socket);
        let cipher = AesCipher::new_128(&[0u8; 16]);
        client.enable_encryption(
            cipher.clone(),
            b"mac-key".to_vec(),
            [1u8; 16],
            cipher.clone(),
            b"mac-key".to_vec(),
            [1u8; 16],
        );
        client.send(23, b"secret").unwrap();
        let (ct, resp) = client.recv().unwrap();
        assert_eq!(ct, 23);
        assert_eq!(resp, b"ack");

        handle.join().unwrap();
    }
}
