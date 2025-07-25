use std::io;

use super::aes::AesCipher;
use super::bigint::BigUint;
use super::dh::{generate_prime, DiffieHellman};
use super::handshake::{HandshakeMessage, HandshakeType};
use super::prf::TlsPrfSha256;
use super::record::ContentType;
use super::rng::secure_random_bytes;
use super::state::{TlsSession, TlsState};

/// TLS record content type for handshake messages.
const CONTENT_TYPE_HANDSHAKE: ContentType = 22;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: ContentType = 20;

/// Perform the client side of the Diffie-Hellman handshake.
pub fn client_handshake(session: &mut TlsSession) -> io::Result<()> {
    session.set_state(TlsState::Handshake);

    // -------- ClientHello --------
    let client_random = secure_random_bytes(32)?;
    let hello = HandshakeMessage::new(HandshakeType::ClientHello, client_random.clone());
    session.send(CONTENT_TYPE_HANDSHAKE, &hello.to_bytes())?;

    // -------- ServerHello --------
    let (_, data) = session.recv()?;
    let (server_hello, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server hello"))?;
    if server_hello.handshake_type != HandshakeType::ServerHello {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerHello"));
    }
    let server_random = server_hello.message.clone();

    // -------- Certificate --------
    let (_, data) = session.recv()?;
    let (cert_msg, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad certificate"))?;
    if cert_msg.handshake_type != HandshakeType::Certificate {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Certificate"));
    }
    // certificate bytes are in cert_msg.message but we don't verify

    // -------- ServerKeyExchange --------
    let (_, data) = session.recv()?;
    let (ske, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server key exchange"))?;
    if ske.handshake_type != HandshakeType::ServerKeyExchange {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerKeyExchange"));
    }
    let mut idx = 0;
    let p_len = u16::from_be_bytes([ske.message[idx], ske.message[idx + 1]]) as usize;
    idx += 2;
    let p = BigUint::from_bytes_be(&ske.message[idx..idx + p_len]);
    idx += p_len;
    let g_len = u16::from_be_bytes([ske.message[idx], ske.message[idx + 1]]) as usize;
    idx += 2;
    let g = BigUint::from_bytes_be(&ske.message[idx..idx + g_len]);
    idx += g_len;
    let pub_len = u16::from_be_bytes([ske.message[idx], ske.message[idx + 1]]) as usize;
    idx += 2;
    let server_pub = BigUint::from_bytes_be(&ske.message[idx..idx + pub_len]);

    // -------- ServerHelloDone --------
    let (_, data) = session.recv()?;
    let (shd, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server hello done"))?;
    if shd.handshake_type != HandshakeType::ServerHelloDone {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerHelloDone"));
    }

    // -------- ClientKeyExchange --------
    let dh = DiffieHellman::new(p, g);
    let priv_key = DiffieHellman::generate_private_key_secure(128)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let mut payload = Vec::new();
    let pub_bytes = pub_key.to_bytes_be();
    payload.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&pub_bytes);
    let cke = HandshakeMessage::new(HandshakeType::ClientKeyExchange, payload);
    session.send(CONTENT_TYPE_HANDSHAKE, &cke.to_bytes())?;

    let shared = dh.compute_shared_secret(&priv_key, &server_pub);
    let pre_master = shared.to_bytes_be();
    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    let master = TlsPrfSha256::derive(&pre_master, b"master secret", &seed, 48);
    let key_block = TlsPrfSha256::derive(&master, b"key expansion", &seed, 64);
    let aes_key: [u8; 16] = key_block[0..16].try_into().unwrap();
    let mac_key = key_block[16..48].to_vec();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key_block[48..64]);

    // -------- ChangeCipherSpec --------
    session.send(CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1])?;
    session.enable_encryption(AesCipher::new_128(&aes_key), mac_key, iv);

    // -------- Finished --------
    let fin = HandshakeMessage::new(HandshakeType::Finished, Vec::new());
    session.send(CONTENT_TYPE_HANDSHAKE, &fin.to_bytes())?;

    // -------- Wait for Server ChangeCipherSpec --------
    let (ct, _) = session.recv()?;
    if ct != CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ChangeCipherSpec"));
    }
    let (_, data) = session.recv()?;
    let (fin2, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin2.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Finished"));
    }

    Ok(())
}

/// Perform the server side of the Diffie-Hellman handshake.
pub fn server_handshake(session: &mut TlsSession, cert: &[u8]) -> io::Result<()> {
    session.set_state(TlsState::Handshake);

    // -------- ClientHello --------
    let (_, data) = session.recv()?;
    let (client_hello, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client hello"))?;
    if client_hello.handshake_type != HandshakeType::ClientHello {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ClientHello"));
    }
    let client_random = client_hello.message.clone();

    // -------- ServerHello --------
    let server_random = secure_random_bytes(32)?;
    let hello = HandshakeMessage::new(HandshakeType::ServerHello, server_random.clone());
    session.send(CONTENT_TYPE_HANDSHAKE, &hello.to_bytes())?;

    // -------- Certificate --------
    let cert_msg = HandshakeMessage::new(HandshakeType::Certificate, cert.to_vec());
    session.send(CONTENT_TYPE_HANDSHAKE, &cert_msg.to_bytes())?;

    // -------- ServerKeyExchange --------
    let mut seed = 1u64;
    let p = generate_prime(32, &mut seed);
    let g = BigUint::from_bytes_be(&[2]);
    let dh = DiffieHellman::new(p.clone(), g.clone());
    let priv_key = DiffieHellman::generate_private_key_secure(128)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let mut payload = Vec::new();
    let p_bytes = p.to_bytes_be();
    payload.extend_from_slice(&(p_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&p_bytes);
    let g_bytes = g.to_bytes_be();
    payload.extend_from_slice(&(g_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&g_bytes);
    let pub_bytes = pub_key.to_bytes_be();
    payload.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&pub_bytes);
    let ske = HandshakeMessage::new(HandshakeType::ServerKeyExchange, payload);
    session.send(CONTENT_TYPE_HANDSHAKE, &ske.to_bytes())?;

    // -------- ServerHelloDone --------
    let shd = HandshakeMessage::new(HandshakeType::ServerHelloDone, Vec::new());
    session.send(CONTENT_TYPE_HANDSHAKE, &shd.to_bytes())?;

    // -------- ClientKeyExchange --------
    let (_, data) = session.recv()?;
    let (cke, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client key exchange"))?;
    if cke.handshake_type != HandshakeType::ClientKeyExchange {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ClientKeyExchange"));
    }
    let mut idx = 0;
    let pub_len = u16::from_be_bytes([cke.message[idx], cke.message[idx + 1]]) as usize;
    idx += 2;
    let client_pub = BigUint::from_bytes_be(&cke.message[idx..idx + pub_len]);
    let shared = dh.compute_shared_secret(&priv_key, &client_pub);
    let pre_master = shared.to_bytes_be();
    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    let master = TlsPrfSha256::derive(&pre_master, b"master secret", &seed, 48);
    let key_block = TlsPrfSha256::derive(&master, b"key expansion", &seed, 64);
    let aes_key: [u8; 16] = key_block[0..16].try_into().unwrap();
    let mac_key = key_block[16..48].to_vec();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key_block[48..64]);

    // -------- ChangeCipherSpec --------
    let (ct, _) = session.recv()?;
    if ct != CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ChangeCipherSpec"));
    }
    session.enable_encryption(AesCipher::new_128(&aes_key), mac_key, iv);
    let (_, data) = session.recv()?;
    let (fin1, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin1.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Finished"));
    }

    // send ChangeCipherSpec and Finished
    session.send(CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1])?;
    let fin = HandshakeMessage::new(HandshakeType::Finished, Vec::new());
    session.send(CONTENT_TYPE_HANDSHAKE, &fin.to_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn diffie_hellman_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            server_handshake(&mut server, include_bytes!("../../tests/test.cer")).unwrap();
            let (ct, data) = server.recv().unwrap();
            assert_eq!(ct, 23);
            assert_eq!(data, b"hello");
            server.send(23, b"world").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        client_handshake(&mut client).unwrap();
        client.send(23, b"hello").unwrap();
        let (_, resp) = client.recv().unwrap();
        assert_eq!(resp, b"world");

        handle.join().unwrap();
    }

    #[test]
    fn tls_stream_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(socket);
            server_handshake(&mut server, include_bytes!("../../tests/test.cer")).unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        client_handshake(&mut client).unwrap();
        client.write_all(b"ping").unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"pong");

        handle.join().unwrap();
    }
}
