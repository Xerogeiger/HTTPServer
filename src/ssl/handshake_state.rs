use std::io;

use super::aes::AesCipher;
use super::bigint::BigUint;
use super::dh::{generate_prime, DiffieHellman};
use super::handshake::{
    CertificatePayload, ClientHello, ClientKeyExchangeDH, HandshakeMessage, HandshakeType,
    ServerHello, ServerKeyExchangeDH,
};
use super::prf::TlsPrfSha256;
use super::record::ContentType;
use super::rng::secure_random_bytes;
use super::rsa::{parse_private_key, RsaPublicKey};
use super::state::{TlsSession, TlsState};

/// TLS record content type for handshake messages.
const CONTENT_TYPE_HANDSHAKE: ContentType = 22;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: ContentType = 20;

/// Perform the client side of the Diffie-Hellman handshake.
pub fn client_handshake(session: &mut TlsSession, host: &str) -> io::Result<()> {
    session.set_state(TlsState::Handshake);

    // -------- ClientHello --------
    let client_random = secure_random_bytes(32)?;
    let mut rand_arr = [0u8; 32];
    rand_arr.copy_from_slice(&client_random);
    let ch = ClientHello {
        version: super::record::TLS_VERSION_1_2,
        random: rand_arr,
        session_id: Vec::new(),
        cipher_suites: vec![0x0033],
        compression_methods: vec![0],
    };
    let hello = HandshakeMessage::new(HandshakeType::ClientHello, ch.to_bytes());
    session.send(CONTENT_TYPE_HANDSHAKE, &hello.to_bytes())?;

    // -------- ServerHello --------
    let (_, data) = session.recv()?;
    let (server_hello, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server hello"))?;
    if server_hello.handshake_type != HandshakeType::ServerHello {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHello",
        ));
    }
    let sh = ServerHello::parse(&server_hello.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server hello payload"))?;
    let server_random = sh.random.to_vec();

    // -------- Certificate --------
    let (_, data) = session.recv()?;
    let (cert_msg, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad certificate"))?;
    if cert_msg.handshake_type != HandshakeType::Certificate {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Certificate",
        ));
    }
    // parse and verify certificate chain
    let mut server_rsa: Option<RsaPublicKey> = None;
    if !cert_msg.message.is_empty() {
        use super::x509::CertificateChain;
        let payload = CertificatePayload::parse(&cert_msg.message)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad certificate payload"))?;
        let chain = CertificateChain::parse(&payload.to_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        chain
            .verify(host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if let Some(cert) = chain.certificates.first() {
            server_rsa = Some(RsaPublicKey::new(
                cert.modulus.clone(),
                cert.exponent.clone(),
            ));
        }
    }

    // -------- ServerKeyExchange --------
    let (_, data) = session.recv()?;
    let (ske, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server key exchange"))?;
    if ske.handshake_type != HandshakeType::ServerKeyExchange {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerKeyExchange",
        ));
    }
    let params = ServerKeyExchangeDH::parse(&ske.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad key exchange payload"))?;
    if let Some(rsa) = &server_rsa {
        let mut signed = Vec::new();
        signed.extend_from_slice(&client_random);
        signed.extend_from_slice(&server_random);
        signed.extend_from_slice(
            &ServerKeyExchangeDH {
                signature: Vec::new(),
                ..params.clone()
            }
            .to_bytes(),
        );
        if !rsa
            .verify_pkcs1_v1_5_sha256(&signed, &params.signature)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad signature"));
        }
    }
    let p = BigUint::from_bytes_be(&params.p);
    let g = BigUint::from_bytes_be(&params.g);
    let server_pub = BigUint::from_bytes_be(&params.public_key);

    // -------- ServerHelloDone --------
    let (_, data) = session.recv()?;
    let (shd, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad server hello done"))?;
    if shd.handshake_type != HandshakeType::ServerHelloDone {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHelloDone",
        ));
    }

    // -------- ClientKeyExchange --------
    let dh = DiffieHellman::new(p, g);
    let priv_key = DiffieHellman::generate_private_key_secure(128)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let pub_bytes = pub_key.to_bytes_be();
    let cke_payload = ClientKeyExchangeDH {
        public_key: pub_bytes.clone(),
    };
    let cke = HandshakeMessage::new(HandshakeType::ClientKeyExchange, cke_payload.to_bytes());
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ChangeCipherSpec",
        ));
    }
    let (_, data) = session.recv()?;
    let (fin2, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin2.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Finished",
        ));
    }

    Ok(())
}

/// Perform the server side of the Diffie-Hellman handshake.
pub fn server_handshake(session: &mut TlsSession, cert: &[u8], key: &[u8]) -> io::Result<()> {
    session.set_state(TlsState::Handshake);

    // -------- ClientHello --------
    let (_, data) = session.recv()?;
    let (client_hello, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client hello"))?;
    if client_hello.handshake_type != HandshakeType::ClientHello {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ClientHello",
        ));
    }
    let ch = ClientHello::parse(&client_hello.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client hello payload"))?;
    let client_random = ch.random.to_vec();

    // -------- ServerHello --------
    let server_random = secure_random_bytes(32)?;
    let mut rand_arr = [0u8; 32];
    rand_arr.copy_from_slice(&server_random);
    let sh = ServerHello {
        version: super::record::TLS_VERSION_1_2,
        random: rand_arr,
        session_id: Vec::new(),
        cipher_suite: 0x0033,
        compression_method: 0,
    };
    let hello = HandshakeMessage::new(HandshakeType::ServerHello, sh.to_bytes());
    session.send(CONTENT_TYPE_HANDSHAKE, &hello.to_bytes())?;

    // -------- Certificate --------
    let cert_payload = if !cert.is_empty() {
        CertificatePayload {
            certificates: vec![cert.to_vec()],
        }
        .to_bytes()
    } else {
        CertificatePayload {
            certificates: vec![],
        }
        .to_bytes()
    };
    let cert_msg = HandshakeMessage::new(HandshakeType::Certificate, cert_payload);
    session.send(CONTENT_TYPE_HANDSHAKE, &cert_msg.to_bytes())?;

    // -------- ServerKeyExchange --------
    let mut seed = 1u64;
    let p = generate_prime(32, &mut seed);
    let g = BigUint::from_bytes_be(&[2]);
    let dh = DiffieHellman::new(p.clone(), g.clone());
    let priv_key = DiffieHellman::generate_private_key_secure(128)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let p_bytes = p.to_bytes_be();
    let g_bytes = g.to_bytes_be();
    let pub_bytes = pub_key.to_bytes_be();
    let mut ske_payload = ServerKeyExchangeDH {
        p: p_bytes,
        g: g_bytes,
        public_key: pub_bytes,
        signature: Vec::new(),
    };
    let rsa_key =
        parse_private_key(key).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut signed = Vec::new();
    signed.extend_from_slice(&client_random);
    signed.extend_from_slice(&server_random);
    signed.extend_from_slice(&ske_payload.to_bytes());
    ske_payload.signature = rsa_key.sign_pkcs1_v1_5_sha256(&signed);
    let ske = HandshakeMessage::new(HandshakeType::ServerKeyExchange, ske_payload.to_bytes());
    session.send(CONTENT_TYPE_HANDSHAKE, &ske.to_bytes())?;

    // -------- ServerHelloDone --------
    let shd = HandshakeMessage::new(HandshakeType::ServerHelloDone, Vec::new());
    session.send(CONTENT_TYPE_HANDSHAKE, &shd.to_bytes())?;

    // -------- ClientKeyExchange --------
    let (_, data) = session.recv()?;
    let (cke, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client key exchange"))?;
    if cke.handshake_type != HandshakeType::ClientKeyExchange {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ClientKeyExchange",
        ));
    }
    let cke_payload = ClientKeyExchangeDH::parse(&cke.message).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "bad client key exchange payload",
        )
    })?;
    let client_pub = BigUint::from_bytes_be(&cke_payload.public_key);
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ChangeCipherSpec",
        ));
    }
    session.enable_encryption(AesCipher::new_128(&aes_key), mac_key, iv);
    let (_, data) = session.recv()?;
    let (fin1, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin1.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Finished",
        ));
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
            let cert =
                crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let key = include_bytes!("../../tests/test_key.pem");
            server_handshake(&mut server, &cert, key).unwrap();
            let (ct, data) = server.recv().unwrap();
            assert_eq!(ct, 23);
            assert_eq!(data, b"hello");
            server.send(23, b"world").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        client_handshake(&mut client, "localhost").unwrap();
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
            let cert =
                crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let key = include_bytes!("../../tests/test_key.pem");
            server_handshake(&mut server, &cert, key).unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        client_handshake(&mut client, "localhost").unwrap();
        client.write_all(b"ping").unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"pong");

        handle.join().unwrap();
    }
}
