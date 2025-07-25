use std::net::TcpStream;
use crate::ssl::crypto::CipherContext;

pub enum TlsState {
    Plain, // No TLS, plain text communication
    Handshake, // TLS handshake in progress
    Encrypted { cipher: CipherContext }, // TLS established, encrypted communication
    Closed, // TLS connection closed
}

pub struct TlsSession {
    stream: TcpStream,
    state: TlsState,
    buffer: Vec<u8>, // Buffer for incoming data
}