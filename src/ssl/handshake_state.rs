use std::io;

use super::aes::AesCipher;
use super::bigint::BigUint;
use super::dh::{generate_prime, DiffieHellman};
use super::handshake::{
    CertificatePayload, ClientHello, ClientKeyExchangeDH, Finished, HandshakeMessage,
    HandshakeType, ServerHello, ServerKeyExchangeDH, EXTENSION_SERVER_NAME,
};
use super::crypto::sha256;
use super::prf::TlsPrfSha256;
use super::record::ContentType;
use super::rng::secure_random_bytes;
use super::rsa::{parse_private_key, RsaPublicKey};
use super::state::{TlsSession, TlsState};
use crate::http::server::TlsConfig;
use std::time::{SystemTime, UNIX_EPOCH};

/// TLS record content type for handshake messages.
const CONTENT_TYPE_HANDSHAKE: ContentType = 22;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: ContentType = 20;

/// Mapping of human-readable cipher suite names to numeric codes.
///
/// The codebase currently only implements a single TLS 1.2 suite using
/// ephemeral Diffie-Hellman with RSA authentication and AES-128-CBC with SHA-256.
const SUPPORTED_CIPHER_SUITES: &[(&str, u16)] =
    &[("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x0067)];

fn cipher_name_to_code(name: &str) -> Option<u16> {
    SUPPORTED_CIPHER_SUITES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
}

fn cipher_code_supported(code: u16) -> bool {
    SUPPORTED_CIPHER_SUITES.iter().any(|(_, c)| *c == code)
}

/// Generate a 32-byte random value prefixed with the current Unix timestamp.
fn random_with_timestamp() -> io::Result<[u8; 32]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "System time before epoch"))?;
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
    let rand_tail = secure_random_bytes(28)?;
    out[4..].copy_from_slice(&rand_tail);
    Ok(out)
}

/// Perform the client side of the Diffie-Hellman handshake.
pub fn client_handshake(
    session: &mut TlsSession,
    host: &str,
    trusted_roots: &[super::x509::X509Certificate],
) -> io::Result<()> {
    session.set_state(TlsState::Handshake);
    let mut transcript = Vec::new();

    // -------- ClientHello --------
    let rand_arr = random_with_timestamp()?;
    let client_random = rand_arr.to_vec();
    let mut sni_ext = Vec::new();
    let host_bytes = host.as_bytes();
    sni_ext.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0); // host_name
    sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(host_bytes);
    let ch = ClientHello {
        version: super::record::TLS_VERSION_1_2,
        random: rand_arr,
        session_id: Vec::new(),
        cipher_suites: vec![0x0067],
        compression_methods: vec![0],
        extensions: vec![(super::handshake::EXTENSION_SERVER_NAME, sni_ext)],
    };
    let hello = HandshakeMessage::new(HandshakeType::ClientHello, ch.to_bytes());
    let hello_bytes = hello.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &hello_bytes)?;
    transcript.extend_from_slice(&hello_bytes);

    // -------- ServerHello --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
    if sh.version != super::record::TLS_VERSION_1_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported TLS version",
        ));
    }
    let server_random = sh.random.to_vec();

    // -------- Certificate --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
    if cert_msg.message.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty certificate chain",
        ));
    }
    use super::x509::CertificateChain;
    let payload = CertificatePayload::parse(&cert_msg.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad certificate payload"))?;
    if payload.certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty certificate chain",
        ));
    }
    let chain = CertificateChain::parse(&payload.to_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    chain
        .verify(host, trusted_roots)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(cert) = chain.certificates.first() {
        server_rsa = Some(RsaPublicKey::new(
            cert.modulus.clone(),
            cert.exponent.clone(),
        ));
    }

    // -------- ServerKeyExchange --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
                hash: params.hash,
                sign: params.sign,
                signature: Vec::new(),
                ..params.clone()
            }
            .to_bytes_unsigned(),
        );
        if !rsa
            .verify_pkcs1_v1_5_sha256(&signed, &params.signature)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad signature"));
        }
    }
    if params.hash != 4 || params.sign != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported signature algorithm"));
    }
    let p = BigUint::from_bytes_be(&params.p);
    let g = BigUint::from_bytes_be(&params.g);
    let server_pub = BigUint::from_bytes_be(&params.public_key);

    if !super::dh::is_prime(&p)
        || !super::dh::in_range_2_to_p_minus_2(&g, &p)
        || !super::dh::in_range_2_to_p_minus_2(&server_pub, &p)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DH parameters"));
    }

    // -------- ServerHelloDone --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
    // Use at least a 256-bit private key for stronger forward secrecy
    let priv_key = DiffieHellman::generate_private_key_secure(256)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let pub_bytes = pub_key.to_bytes_be();
    let cke_payload = ClientKeyExchangeDH {
        public_key: pub_bytes.clone(),
    };
    let cke = HandshakeMessage::new(HandshakeType::ClientKeyExchange, cke_payload.to_bytes());
    let cke_bytes = cke.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &cke_bytes)?;
    transcript.extend_from_slice(&cke_bytes);

    let shared = dh.compute_shared_secret(&priv_key, &server_pub);
    let mut pre_master = shared.to_bytes_be();
    let p_len = dh.p.to_bytes_be().len();
    if pre_master.len() < p_len {
        let mut pad = vec![0u8; p_len - pre_master.len()];
        pad.extend_from_slice(&pre_master);
        pre_master = pad;
    }
    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    let master = TlsPrfSha256::derive(&pre_master, b"master secret", &seed, 48);

    let mut seed2 = Vec::new();
    seed2.extend_from_slice(&server_random);
    seed2.extend_from_slice(&client_random);
    // TLS 1.2 with CBC ciphers uses explicit per-record IVs, so the key block
    // only contains MAC and encryption keys.
    let key_block = TlsPrfSha256::derive(&master, b"key expansion", &seed2, 96);

    let client_mac_key = key_block[0..32].to_vec();
    let server_mac_key = key_block[32..64].to_vec();
    let client_key: [u8; 16] = key_block[64..80].try_into().unwrap();
    let server_key: [u8; 16] = key_block[80..96].try_into().unwrap();
    let client_iv = [0u8; 16];
    let server_iv = [0u8; 16];

    session.set_key_material(client_mac_key.clone(), server_mac_key.clone(), client_iv, server_iv);

    let mac_key = client_mac_key;
    let iv = client_iv;
    let read_cipher = AesCipher::new_128(&server_key);
    let read_mac = server_mac_key.clone();
    let read_iv = server_iv;

    // -------- ChangeCipherSpec --------
    session.send(CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1])?;
    session.set_write_encryption(AesCipher::new_128(&client_key), mac_key, iv);

    // -------- Finished --------
    let handshake_hash = sha256::hash(&transcript);
    let verify_data = TlsPrfSha256::derive(&master, b"client finished", &handshake_hash, 12);
    let fin_payload = Finished { verify_data };
    let fin = HandshakeMessage::new(HandshakeType::Finished, fin_payload.to_bytes());
    let fin_bytes = fin.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &fin_bytes)?;
    transcript.extend_from_slice(&fin_bytes);

    // -------- Wait for Server ChangeCipherSpec --------
    let (ct, _) = session.recv_record()?;
    if ct != CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ChangeCipherSpec",
        ));
    }
    session.set_read_encryption(read_cipher, read_mac, read_iv);
    let data = session.recv_handshake_message()?;
    let (fin2, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin2.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Finished",
        ));
    }
    let fin2_payload = Finished::parse(&fin2.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished payload"))?;
    let handshake_hash = sha256::hash(&transcript);
    let expected = TlsPrfSha256::derive(&master, b"server finished", &handshake_hash, 12);
    if fin2_payload.verify_data != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "verify_data mismatch"));
    }
    transcript.extend_from_slice(&data);
    session.set_state(TlsState::Encrypted);

    Ok(())
}

/// Perform the server side of the Diffie-Hellman handshake.
pub fn server_handshake(session: &mut TlsSession, cfg: &TlsConfig) -> io::Result<()> {
    session.set_state(TlsState::Handshake);
    let mut transcript = Vec::new();

    // -------- ClientHello --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
    if ch.version != super::record::TLS_VERSION_1_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported TLS version",
        ));
    }
    let sni_host = ch.get_sni_hostname();
    let client_random = ch.random.to_vec();

    let chosen_cipher = ch
        .cipher_suites
        .iter()
        .find_map(|cs| {
            if cfg.ciphers.is_empty() {
                if cipher_code_supported(*cs) {
                    Some(*cs)
                } else {
                    None
                }
            } else {
                for name in &cfg.ciphers {
                    if let Some(code) = cipher_name_to_code(name) {
                        if code == *cs {
                            return Some(code);
                        }
                    }
                }
                None
            }
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no shared cipher"))?;

    // -------- ServerHello --------
    let rand_arr = random_with_timestamp()?;
    let server_random = rand_arr.to_vec();
    let sh = ServerHello {
        version: super::record::TLS_VERSION_1_2,
        random: rand_arr,
        session_id: Vec::new(),
        cipher_suite: chosen_cipher,
        compression_method: 0,
    };
    let hello = HandshakeMessage::new(HandshakeType::ServerHello, sh.to_bytes());
    let hello_bytes = hello.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &hello_bytes)?;
    transcript.extend_from_slice(&hello_bytes);

    // -------- Certificate --------
    let (cert_bytes_raw, key_bytes_raw) = if let Some(host) = sni_host.as_deref() {
        cfg.sni.get(host).cloned().unwrap_or((cfg.cert.clone(), cfg.key.clone()))
    } else {
        (cfg.cert.clone(), cfg.key.clone())
    };

    if cert_bytes_raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificate configured",
        ));
    }
    let cert_payload = CertificatePayload {
        certificates: vec![cert_bytes_raw.clone()],
    }
    .to_bytes();
    let cert_msg = HandshakeMessage::new(HandshakeType::Certificate, cert_payload);
    let cert_bytes = cert_msg.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &cert_bytes)?;
    transcript.extend_from_slice(&cert_bytes);

    // -------- ServerKeyExchange --------
    let mut seed = 1u64;
    // use a much larger prime for stronger security
    let p = generate_prime(2048, &mut seed);
    let g = BigUint::from_bytes_be(&[2]);
    let dh = DiffieHellman::new(p.clone(), g.clone());
    // Use at least a 256-bit private key for stronger forward secrecy
    let priv_key = DiffieHellman::generate_private_key_secure(256)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pub_key = dh.compute_public_key(&priv_key);
    let p_bytes = p.to_bytes_be();
    let g_bytes = g.to_bytes_be();
    let pub_bytes = pub_key.to_bytes_be();
    let mut ske_payload = ServerKeyExchangeDH {
        p: p_bytes,
        g: g_bytes,
        public_key: pub_bytes,
        hash: 4,
        sign: 1,
        signature: Vec::new(),
    };
    let rsa_key =
        parse_private_key(&key_bytes_raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut signed = Vec::new();
    signed.extend_from_slice(&client_random);
    signed.extend_from_slice(&server_random);
    signed.extend_from_slice(&ske_payload.to_bytes_unsigned());
    ske_payload.signature = rsa_key.sign_pkcs1_v1_5_sha256(&signed);
    let ske = HandshakeMessage::new(HandshakeType::ServerKeyExchange, ske_payload.to_bytes());
    let ske_bytes = ske.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &ske_bytes)?;
    transcript.extend_from_slice(&ske_bytes);

    // -------- ServerHelloDone --------
    let shd = HandshakeMessage::new(HandshakeType::ServerHelloDone, Vec::new());
    let shd_bytes = shd.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &shd_bytes)?;
    transcript.extend_from_slice(&shd_bytes);

    // -------- ClientKeyExchange --------
    let data = session.recv_handshake_message()?;
    transcript.extend_from_slice(&data);
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
    if !super::dh::in_range_2_to_p_minus_2(&client_pub, &p) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid client public key"));
    }
    let shared = dh.compute_shared_secret(&priv_key, &client_pub);
    let mut pre_master = shared.to_bytes_be();
    let p_len = dh.p.to_bytes_be().len();
    if pre_master.len() < p_len {
        let mut pad = vec![0u8; p_len - pre_master.len()];
        pad.extend_from_slice(&pre_master);
        pre_master = pad;
    }
    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    let master = TlsPrfSha256::derive(&pre_master, b"master secret", &seed, 48);

    let mut seed2 = Vec::new();
    seed2.extend_from_slice(&server_random);
    seed2.extend_from_slice(&client_random);
    // As above, TLS 1.2 CBC suites do not use fixed IVs in the key block.
    let key_block = TlsPrfSha256::derive(&master, b"key expansion", &seed2, 96);

    let client_mac_key = key_block[0..32].to_vec();
    let server_mac_key = key_block[32..64].to_vec();
    let client_key: [u8; 16] = key_block[64..80].try_into().unwrap();
    let server_key: [u8; 16] = key_block[80..96].try_into().unwrap();
    let client_iv = [0u8; 16];
    let server_iv = [0u8; 16];

    session.set_key_material(client_mac_key.clone(), server_mac_key.clone(), client_iv, server_iv);

    let mac_key = server_mac_key.clone();
    let iv = server_iv;
    let read_cipher = AesCipher::new_128(&client_key);
    let read_mac = client_mac_key.clone();
    let read_iv = client_iv;

    // -------- ChangeCipherSpec --------
    let (ct, _) = session.recv_record()?;
    if ct != CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ChangeCipherSpec",
        ));
    }
    session.set_read_encryption(read_cipher, read_mac.clone(), read_iv);
    let data = session.recv_handshake_message()?;
    let (fin1, _) = HandshakeMessage::parse(&data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished"))?;
    if fin1.handshake_type != HandshakeType::Finished {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Finished",
        ));
    }
    let fin1_payload = Finished::parse(&fin1.message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad finished payload"))?;
    let handshake_hash = sha256::hash(&transcript);
    let expected = TlsPrfSha256::derive(&master, b"client finished", &handshake_hash, 12);
    if fin1_payload.verify_data != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "verify_data mismatch"));
    }
    transcript.extend_from_slice(&data);

    // send ChangeCipherSpec and Finished
    session.send(CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1])?;
    session.set_write_encryption(
        AesCipher::new_128(&server_key),
        server_mac_key.clone(),
        server_iv,
    );
    let handshake_hash = sha256::hash(&transcript);
    let verify_data = TlsPrfSha256::derive(&master, b"server finished", &handshake_hash, 12);
    let fin_payload = Finished { verify_data };
    let fin = HandshakeMessage::new(HandshakeType::Finished, fin_payload.to_bytes());
    let fin_bytes = fin.to_bytes();
    session.send(CONTENT_TYPE_HANDSHAKE, &fin_bytes)?;
    transcript.extend_from_slice(&fin_bytes);
    session.set_state(TlsState::Encrypted);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use crate::http::server::TlsConfig;

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
            let cfg = crate::http::server::TlsConfig {
                cert,
                key: key.to_vec(),
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni: std::collections::HashMap::new(),
            };
            server_handshake(&mut server, &cfg).unwrap();
            let (ct, data) = server.recv().unwrap();
            assert_eq!(ct, 23);
            assert_eq!(data, b"hello");
            server.send(23, b"world").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem"))
                .unwrap(),
        )
        .unwrap()];
        client_handshake(&mut client, "localhost", &roots).unwrap();
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
            let cfg = crate::http::server::TlsConfig {
                cert,
                key: key.to_vec(),
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni: std::collections::HashMap::new(),
            };
            server_handshake(&mut server, &cfg).unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem"))
                .unwrap(),
        )
        .unwrap()];
        client_handshake(&mut client, "localhost", &roots).unwrap();
        client.write_all(b"ping").unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"pong");

        handle.join().unwrap();
    }

    #[test]
    fn sni_certificate_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            let default_cert = crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let default_key = include_bytes!("../../tests/test_key.pem").to_vec();
            let alt_cert = crate::ssl::rsa::pem_to_der(include_str!("../../tests/localhost_cert.pem")).unwrap();
            let alt_key = include_bytes!("../../tests/localhost_key.pem").to_vec();
            let mut sni = std::collections::HashMap::new();
            sni.insert("localhost".to_string(), (alt_cert, alt_key));
            let cfg = crate::http::server::TlsConfig {
                cert: default_cert,
                key: default_key,
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni,
            };
            server_handshake(&mut server, &cfg).unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/localhost_cert.pem")).unwrap(),
        )
        .unwrap()];
        client_handshake(&mut client, "localhost", &roots).unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn server_handshake_requires_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            let cfg = TlsConfig {
                cert: Vec::new(),
                key: include_bytes!("../../tests/test_key.pem").to_vec(),
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni: std::collections::HashMap::new(),
            };
            let err = server_handshake(&mut server, &cfg).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        });

        // Send a minimal ClientHello to trigger the server handshake
        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let rand_arr = super::random_with_timestamp().unwrap();
        let ch = ClientHello {
            version: crate::ssl::record::TLS_VERSION_1_2,
            random: rand_arr,
            session_id: Vec::new(),
            cipher_suites: vec![0x0067],
            compression_methods: vec![0],
            extensions: Vec::new(),
        };
        let hello = HandshakeMessage::new(HandshakeType::ClientHello, ch.to_bytes());
        client.send(super::CONTENT_TYPE_HANDSHAKE, &hello.to_bytes()).unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn client_fails_on_empty_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            // Receive ClientHello
            let data = server.recv_handshake_message().unwrap();
            let _ = HandshakeMessage::parse(&data).unwrap();

            // Send minimal ServerHello
            let rand_arr = super::random_with_timestamp().unwrap();
            let sh = ServerHello {
                version: crate::ssl::record::TLS_VERSION_1_2,
                random: rand_arr,
                session_id: Vec::new(),
                cipher_suite: 0x0067,
                compression_method: 0,
            };
            let sh_msg = HandshakeMessage::new(HandshakeType::ServerHello, sh.to_bytes());
            server.send(super::CONTENT_TYPE_HANDSHAKE, &sh_msg.to_bytes()).unwrap();

            // Send empty Certificate message
            let cert_payload = CertificatePayload { certificates: Vec::new() }.to_bytes();
            let cert_msg = HandshakeMessage::new(HandshakeType::Certificate, cert_payload);
            server.send(super::CONTENT_TYPE_HANDSHAKE, &cert_msg.to_bytes()).unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap(),
        )
        .unwrap()];
        let res = client_handshake(&mut client, "localhost", &roots);
        assert!(res.is_err());

        handle.join().unwrap();
    }

    #[test]
    fn client_rejects_invalid_dh_params() {
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            // Receive ClientHello and capture random
            let data = server.recv_handshake_message().unwrap();
            let (msg, _) = HandshakeMessage::parse(&data).unwrap();
            let ch = ClientHello::parse(&msg.message).unwrap();
            let client_random = ch.random;

            // Send minimal ServerHello
            let server_rand = super::random_with_timestamp().unwrap();
            let sh = ServerHello {
                version: crate::ssl::record::TLS_VERSION_1_2,
                random: server_rand,
                session_id: Vec::new(),
                cipher_suite: 0x0067,
                compression_method: 0,
            };
            let sh_msg = HandshakeMessage::new(HandshakeType::ServerHello, sh.to_bytes());
            server.send(super::CONTENT_TYPE_HANDSHAKE, &sh_msg.to_bytes()).unwrap();

            // Send certificate
            let cert = crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let cert_payload = CertificatePayload { certificates: vec![cert.clone()] }.to_bytes();
            let cert_msg = HandshakeMessage::new(HandshakeType::Certificate, cert_payload);
            server.send(super::CONTENT_TYPE_HANDSHAKE, &cert_msg.to_bytes()).unwrap();

            // Construct invalid DH parameters (non-prime p)
            let p = BigUint::from_bytes_be(&[15]);
            let g = BigUint::from_bytes_be(&[2]);
            let dh = DiffieHellman::new(p.clone(), g.clone());
            let mut seed = 1u64;
            let priv_key = DiffieHellman::generate_private_key(16, &mut seed);
            let pub_key = dh.compute_public_key(&priv_key);
            let mut ske_payload = ServerKeyExchangeDH {
                p: p.to_bytes_be(),
                g: g.to_bytes_be(),
                public_key: pub_key.to_bytes_be(),
                hash: 4,
                sign: 1,
                signature: Vec::new(),
            };
            let key = parse_private_key(include_bytes!("../../tests/test_key.pem")).unwrap();
            let mut signed = Vec::new();
            signed.extend_from_slice(&client_random);
            signed.extend_from_slice(&server_rand);
            signed.extend_from_slice(&ske_payload.to_bytes_unsigned());
            ske_payload.signature = key.sign_pkcs1_v1_5_sha256(&signed);
            let ske = HandshakeMessage::new(HandshakeType::ServerKeyExchange, ske_payload.to_bytes());
            server.send(super::CONTENT_TYPE_HANDSHAKE, &ske.to_bytes()).unwrap();

            // Send ServerHelloDone
            let shd = HandshakeMessage::new(HandshakeType::ServerHelloDone, Vec::new());
            server.send(super::CONTENT_TYPE_HANDSHAKE, &shd.to_bytes()).unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap(),
        )
        .unwrap()];
        let res = client_handshake(&mut client, "localhost", &roots);
        assert!(res.is_err());

        handle.join().unwrap();
    }

    #[test]
    fn server_rejects_invalid_client_key() {
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            let cert = crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let key = include_bytes!("../../tests/test_key.pem");
            let cfg = TlsConfig {
                cert,
                key: key.to_vec(),
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni: std::collections::HashMap::new(),
            };
            let res = server_handshake(&mut server, &cfg);
            assert!(res.is_err());
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let rand_arr = super::random_with_timestamp().unwrap();
        let ch = ClientHello {
            version: crate::ssl::record::TLS_VERSION_1_2,
            random: rand_arr,
            session_id: Vec::new(),
            cipher_suites: vec![0x0067],
            compression_methods: vec![0],
            extensions: Vec::new(),
        };
        let hello = HandshakeMessage::new(HandshakeType::ClientHello, ch.to_bytes());
        client.send(super::CONTENT_TYPE_HANDSHAKE, &hello.to_bytes()).unwrap();

        // consume server hello sequence
        let _ = client.recv_handshake_message().unwrap();
        let _ = client.recv_handshake_message().unwrap();
        let _ = client.recv_handshake_message().unwrap();
        let _ = client.recv_handshake_message().unwrap();

        // send invalid client public key (value 1)
        let cke_payload = ClientKeyExchangeDH { public_key: vec![1] };
        let cke = HandshakeMessage::new(HandshakeType::ClientKeyExchange, cke_payload.to_bytes());
        client.send(super::CONTENT_TYPE_HANDSHAKE, &cke.to_bytes()).unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn client_rejects_wrong_tls_version() {
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            // Receive ClientHello
            let data = server.recv_handshake_message().unwrap();
            let _ = HandshakeMessage::parse(&data).unwrap();

            // Send ServerHello with unsupported version
            let rand_arr = super::random_with_timestamp().unwrap();
            let sh = ServerHello {
                version: 0x0301,
                random: rand_arr,
                session_id: Vec::new(),
                cipher_suite: 0x0067,
                compression_method: 0,
            };
            let sh_msg = HandshakeMessage::new(HandshakeType::ServerHello, sh.to_bytes());
            server.send(super::CONTENT_TYPE_HANDSHAKE, &sh_msg.to_bytes()).unwrap();
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let roots = vec![crate::ssl::x509::X509Certificate::parse(
            &crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap(),
        )
        .unwrap()];
        let res = client_handshake(&mut client, "localhost", &roots);
        assert!(res.is_err());

        handle.join().unwrap();
    }

    #[test]
    fn server_rejects_wrong_tls_version() {
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut server = TlsSession::new(sock);
            let cert = crate::ssl::rsa::pem_to_der(include_str!("../../tests/test_cert.pem")).unwrap();
            let key = include_bytes!("../../tests/test_key.pem");
            let cfg = TlsConfig {
                cert,
                key: key.to_vec(),
                ciphers: vec!["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".into()],
                sni: std::collections::HashMap::new(),
            };
            let res = server_handshake(&mut server, &cfg);
            assert!(res.is_err());
        });

        let mut client = TlsSession::new(TcpStream::connect(addr).unwrap());
        let rand_arr = super::random_with_timestamp().unwrap();
        let ch = ClientHello {
            version: 0x0301,
            random: rand_arr,
            session_id: Vec::new(),
            cipher_suites: vec![0x0067],
            compression_methods: vec![0],
            extensions: Vec::new(),
        };
        let hello = HandshakeMessage::new(HandshakeType::ClientHello, ch.to_bytes());
        client.send(super::CONTENT_TYPE_HANDSHAKE, &hello.to_bytes()).unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn dh_prime_size() {
        let mut seed = 1u64;
        let p = generate_prime(2048, &mut seed);
        assert!(p.to_bytes_be().len() >= 256);
    }

    #[test]
    fn random_timestamp_prefix() {
        let r = super::random_with_timestamp().unwrap();
        let ts = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(now >= ts && now - ts < 5);
    }

    #[test]
    fn random_bytes_not_zero() {
        let r = super::random_with_timestamp().unwrap();
        assert!(r[4..].iter().any(|&b| b != 0));
    }

    #[test]
    fn fragmented_handshake_message() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut session = TlsSession::new(sock);
            let data = session.recv_handshake_message().unwrap();
            let (msg, _) = HandshakeMessage::parse(&data).unwrap();
            assert_eq!(msg.handshake_type, HandshakeType::HelloRequest);
            assert_eq!(msg.message, b"abc");
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let msg = HandshakeMessage::new(HandshakeType::HelloRequest, b"abc".to_vec()).to_bytes();
        use crate::ssl::record::{RecordHeader, TLS_VERSION_1_2};
        let mut r1 = RecordHeader { content_type: 22, version: TLS_VERSION_1_2, length: 2 }.to_bytes().to_vec();
        r1.extend_from_slice(&msg[..2]);
        stream.write_all(&r1).unwrap();
        let mut r2 = RecordHeader { content_type: 22, version: TLS_VERSION_1_2, length: (msg.len() - 2) as u16 }.to_bytes().to_vec();
        r2.extend_from_slice(&msg[2..]);
        stream.write_all(&r2).unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn coalesced_handshake_messages() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut session = TlsSession::new(sock);
            let d1 = session.recv_handshake_message().unwrap();
            let (m1, _) = HandshakeMessage::parse(&d1).unwrap();
            assert_eq!(m1.message, b"hi");
            let d2 = session.recv_handshake_message().unwrap();
            let (m2, _) = HandshakeMessage::parse(&d2).unwrap();
            assert_eq!(m2.message, b"ok");
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let m1 = HandshakeMessage::new(HandshakeType::HelloRequest, b"hi".to_vec()).to_bytes();
        let m2 = HandshakeMessage::new(HandshakeType::HelloRequest, b"ok".to_vec()).to_bytes();
        let payload: Vec<u8> = [m1.clone(), m2.clone()].concat();
        use crate::ssl::record::{RecordHeader, TLS_VERSION_1_2};
        let mut r = RecordHeader { content_type: 22, version: TLS_VERSION_1_2, length: payload.len() as u16 }.to_bytes().to_vec();
        r.extend_from_slice(&payload);
        stream.write_all(&r).unwrap();

        handle.join().unwrap();
    }
}
