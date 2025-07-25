use std::net::TcpStream;

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
}
