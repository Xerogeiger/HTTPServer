use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ssl::bigint::BigUint;
use crate::ssl::crypto::sha256;

/// A DER TLV object
#[derive(Debug)]
pub struct DerObject {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<u8>,
}

impl DerObject {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.tag];
        if self.length < 0x80 {
            bytes.push(self.length as u8);
        } else {
            let len_bytes = (self.length as u32).to_be_bytes();
            let num_length_bytes = len_bytes.iter().take_while(|&&b| b == 0).count();
            bytes.push(0x80 | (len_bytes.len() - num_length_bytes) as u8);
            bytes.extend_from_slice(&len_bytes[num_length_bytes..]);
        }
        bytes.extend_from_slice(&self.value);
        bytes
    }
}

/// A streaming DER reader
pub struct DerReader<R: Read> {
    reader: R,
}

/// Representation of an X.509 certificate with extracted RSA key
pub struct X509Certificate {
    pub version: u32,
    pub tbs: Vec<u8>,
    pub serial: Vec<u8>,
    pub sig_alg_inner: String,
    pub issuer: Vec<u8>,
    pub not_before: String,
    pub not_after: String,
    pub subject: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub modulus: BigUint,        // RSA modulus n
    pub exponent: BigUint,       // RSA public exponent e
    pub sig_alg_outer: String,
    pub signature: Vec<u8>,
}

/// A chain of certificates as sent in a TLS Certificate message
pub struct CertificateChain {
    pub certificates: Vec<X509Certificate>,
}

impl<R: Read> DerReader<R> {
    pub fn new(reader: R) -> Self {
        DerReader { reader }
    }

    /// Read a single DER TLV object
    pub fn read_object(&mut self) -> std::io::Result<DerObject> {
        let mut tag_buf = [0u8; 1];
        self.reader.read_exact(&mut tag_buf)?;
        let tag = tag_buf[0];

        let mut length_buf = [0u8; 1];
        self.reader.read_exact(&mut length_buf)?;
        let length = if length_buf[0] & 0x80 == 0 {
            length_buf[0] as usize
        } else {
            let num_bytes = (length_buf[0] & 0x7F) as usize;
            if num_bytes > 8 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unsupported DER length",
                ));
            }
            let mut buf = vec![0u8; num_bytes];
            self.reader.read_exact(&mut buf)?;
            buf.into_iter().fold(0usize, |acc, b| (acc << 8) | (b as usize))
        };

        if length > 1_000_000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DER length too large",
            ));
        }
        let mut value = vec![0u8; length];
        self.reader.read_exact(&mut value)?;

        Ok(DerObject { tag, length, value })
    }
}

impl X509Certificate {
    pub fn parse(der: &[u8]) -> std::io::Result<Self> {
        let mut reader = DerReader::new(Cursor::new(der));

        // Outer Certificate sequence
        let sequence = reader.read_object()?;
        if sequence.tag != 0x30 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected SEQUENCE"));
        }
        let mut cert_reader = DerReader::new(Cursor::new(&sequence.value));

        // tbsCertificate
        let tbs_sequence = cert_reader.read_object()?;
        let tbs_bytes = tbs_sequence.to_bytes();
        let mut tbs_reader = DerReader::new(Cursor::new(&tbs_sequence.value));

        // Version & Serial
        let first = tbs_reader.read_object()?;
        let (version, serial_obj) = if first.tag == 0xA0 {
            let mut vr = DerReader::new(Cursor::new(&first.value));
            let ver_obj = vr.read_object()?;
            let version = ver_obj.value.iter().fold(0, |acc, &b| (acc << 8) | (b as u32)) + 1;
            let serial_obj = tbs_reader.read_object()?;
            (version, serial_obj)
        } else {
            (1, first)
        };
        let serial_number = serial_obj.value.clone();

        // Inner signatureAlgorithm
        let sig_alg_obj = tbs_reader.read_object()?;
        let sig_alg_inner = parse_oid_sequence(&sig_alg_obj.value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Issuer
        let issuer_obj = tbs_reader.read_object()?;
        let issuer = issuer_obj.value.clone();

        // Validity
        let val_obj = tbs_reader.read_object()?;
        let mut vr = DerReader::new(Cursor::new(&val_obj.value));
        let nb = vr.read_object()?;
        let na = vr.read_object()?;
        let not_before = String::from_utf8_lossy(&nb.value).to_string();
        let not_after  = String::from_utf8_lossy(&na.value).to_string();

        // Subject
        let subj_obj = tbs_reader.read_object()?;
        let subject = subj_obj.value.clone();

        // SubjectPublicKeyInfo
        let spki_obj = tbs_reader.read_object()?;
        if spki_obj.tag != 0x30 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected SubjectPublicKeyInfo SEQUENCE",
            ));
        }
        let pubkey_der = spki_obj.value.clone();
        // Parse RSA key
        let (modulus, exponent) = {
            // spki_rdr parses the SubjectPublicKeyInfo fields
            let mut spki_rdr = DerReader::new(Cursor::new(&pubkey_der));

            // AlgorithmIdentifier SEQUENCE
            let alg_seq = spki_rdr.read_object()?;
            if alg_seq.tag != 0x30 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected AlgorithmIdentifier SEQUENCE",
                ));
            }

            let mut alg_rdr = DerReader::new(Cursor::new(&alg_seq.value));
            let oid_obj = alg_rdr.read_object()?;
            if oid_obj.tag != 0x06 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected OID in AlgorithmIdentifier",
                ));
            }
            let _ = parse_oid_sequence(&oid_obj.value);
            // Skip optional NULL
            if let Ok(param) = alg_rdr.read_object() {
                if param.tag != 0x05 {
                    // ignore unknown params
                }
            }

            // BIT STRING with the public key
            let bs = spki_rdr.read_object()?;
            if bs.tag != 0x03 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Expected BIT STRING, found 0x{:02X}", bs.tag),
                ));
            }
            // Drop the first “unused bits” byte
            let rsa_bytes = &bs.value[1..];

            // 4) Parse the inner RSAPublicKey SEQUENCE
            let mut rsa_rdr = DerReader::new(Cursor::new(rsa_bytes));
            let rsa_seq = rsa_rdr.read_object()?;
            if rsa_seq.tag != 0x30 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected RSA SEQUENCE",
                ));
            }
            let mut rsa_inner = DerReader::new(Cursor::new(&rsa_seq.value));

            // 5) Modulus INTEGER
            let mobj = rsa_inner.read_object()?;
            if mobj.tag != 0x02 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected INTEGER for modulus",
                ));
            }
            let modulus = BigUint::from_bytes_be(&mobj.value);

            // 6) Exponent INTEGER
            let eobj = rsa_inner.read_object()?;
            if eobj.tag != 0x02 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected INTEGER for exponent",
                ));
            }
            let exponent = BigUint::from_bytes_be(&eobj.value);

            (modulus, exponent)
        };

        // Outer signatureAlgorithm
        let outer_sig_obj = cert_reader.read_object()?;
        let sig_alg_outer = parse_oid_sequence(&outer_sig_obj.value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Signature BIT STRING
        let signature_value = cert_reader.read_object()?;
        if signature_value.tag != 0x03 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected BIT STRING"));
        }
        let signature = signature_value.value[1..].to_vec();

        Ok(X509Certificate {
            version,
            tbs: tbs_bytes,
            serial: serial_number,
            sig_alg_inner,
            issuer,
            not_before,
            not_after,
            subject,
            pubkey: pubkey_der,
            modulus,
            exponent,
            sig_alg_outer,
            signature,
        })
    }

    /// Verify RSA/SHA-256 signature
    pub fn verify(&self) -> Result<bool, String> {
        if self.sig_alg_inner != "1.2.840.113549.1.1.11" {
            return Err(format!("Unsupported sigalg: {}", self.sig_alg_inner));
        }
        let digest = sha256::hash(&self.tbs);
        let sig_int = BigUint::from_bytes_be(&self.signature);
        let m_int = sig_int.modpow(&self.exponent, &self.modulus);

        // PKCS#1 v1.5 padding: result should be same length as modulus
        let k = self.modulus.to_bytes_be().len();
        let mut em = m_int.to_bytes_be();
        if em.len() < k {
            let mut padded = vec![0u8; k - em.len()];
            padded.extend_from_slice(&em);
            em = padded;
        }

        // Validate padding 0x00 0x01 FF.. 0x00
        let mut i = 0;
        if em[i] == 0 { i += 1; }
        if em.get(i) != Some(&0x01) { return Err("Invalid padding".into()); }
        i += 1;
        while i < em.len() && em[i] == 0xFF { i += 1; }
        if i >= em.len() || em[i] != 0x00 { return Err("Invalid padding".into()); }
        i += 1;

        let mut rdr = DerReader::new(Cursor::new(&em[i..]));
        let seq = rdr.read_object().map_err(|e| e.to_string())?;
        let mut inner = DerReader::new(Cursor::new(&seq.value));
        let _ = inner.read_object().map_err(|e| e.to_string())?;
        let oct = inner.read_object().map_err(|e| e.to_string())?;
        if oct.tag != 0x04 { return Err("Expected OCTET STRING".into()); }
        Ok(oct.value == digest)
    }

    /// Verify this certificate's signature using the issuer's public key
    pub fn verify_with(&self, issuer: &X509Certificate) -> Result<bool, String> {
        if self.issuer != issuer.subject {
            return Err("Issuer mismatch".into());
        }
        if self.sig_alg_inner != "1.2.840.113549.1.1.11" {
            return Err(format!("Unsupported sigalg: {}", self.sig_alg_inner));
        }
        let digest = sha256::hash(&self.tbs);
        let sig_int = BigUint::from_bytes_be(&self.signature);
        let m_int = sig_int.modpow(&issuer.exponent, &issuer.modulus);

        let k = issuer.modulus.to_bytes_be().len();
        let mut em = m_int.to_bytes_be();
        if em.len() < k {
            let mut padded = vec![0u8; k - em.len()];
            padded.extend_from_slice(&em);
            em = padded;
        }

        let mut i = 0;
        if em[i] == 0 { i += 1; }
        if em.get(i) != Some(&0x01) { return Err("Invalid padding".into()); }
        i += 1;
        while i < em.len() && em[i] == 0xFF { i += 1; }
        if i >= em.len() || em[i] != 0x00 { return Err("Invalid padding".into()); }
        i += 1;

        let mut rdr = DerReader::new(Cursor::new(&em[i..]));
        let seq = rdr.read_object().map_err(|e| e.to_string())?;
        let mut inner = DerReader::new(Cursor::new(&seq.value));
        let _ = inner.read_object().map_err(|e| e.to_string())?;
        let oct = inner.read_object().map_err(|e| e.to_string())?;
        if oct.tag != 0x04 { return Err("Expected OCTET STRING".into()); }
        Ok(oct.value == digest)
    }

    /// Parse the common name from the subject field
    fn subject_cn(&self) -> Option<String> {
        let mut rdr = DerReader::new(Cursor::new(&self.subject));
        let seq = rdr.read_object().ok()?;
        if seq.tag != 0x30 { return None; }
        let mut sr = DerReader::new(Cursor::new(&seq.value));
        while let Ok(set) = sr.read_object() {
            let mut set_rdr = DerReader::new(Cursor::new(&set.value));
            if let Ok(attr_seq) = set_rdr.read_object() {
                let mut ar = DerReader::new(Cursor::new(&attr_seq.value));
                let oid = ar.read_object().ok()?;
                if decode_oid(&oid.value) == "2.5.4.3" {
                    if let Ok(cn_obj) = ar.read_object() {
                        return Some(String::from_utf8_lossy(&cn_obj.value).into_owned());
                    }
                }
            }
        }
        None
    }

    /// Extract DNS names from the Subject Alternative Name extension
    fn subject_alt_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut rdr = DerReader::new(Cursor::new(&self.tbs));
        let seq = match rdr.read_object() {
            Ok(o) => o,
            Err(_) => return names,
        };
        let mut tr = DerReader::new(Cursor::new(&seq.value));

        // Skip until after SubjectPublicKeyInfo
        let first = match tr.read_object() { Ok(o) => o, Err(_) => return names };
        if first.tag == 0xA0 { if tr.read_object().is_err() { return names; } }
        for _ in 0..5 { if tr.read_object().is_err() { return names; } }
        if let Ok(obj) = tr.read_object() {
            if obj.tag == 0xA3 {
                let mut ext_rdr = DerReader::new(Cursor::new(&obj.value));
                if let Ok(ext_seq) = ext_rdr.read_object() {
                    let mut es = DerReader::new(Cursor::new(&ext_seq.value));
                    while let Ok(ext) = es.read_object() {
                        let mut er = DerReader::new(Cursor::new(&ext.value));
                        let oid = match er.read_object() { Ok(o) => o, Err(_) => return names };
                        let oid_str = decode_oid(&oid.value);
                        let val_obj = match er.read_object() {
                            Ok(o) if o.tag == 0x01 => match er.read_object() { Ok(v) => v, Err(_) => return names },
                            Ok(o) => o,
                            Err(_) => return names,
                        };
                        if oid_str == "2.5.29.17" {
                            let mut val_rdr = DerReader::new(Cursor::new(&val_obj.value));
                            if let Ok(gn_seq) = val_rdr.read_object() {
                                let mut gn_rdr = DerReader::new(Cursor::new(&gn_seq.value));
                                while let Ok(name) = gn_rdr.read_object() {
                                    if name.tag == 0x82 { // dNSName [2]
                                        names.push(String::from_utf8_lossy(&name.value).into_owned());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        names
    }

    /// Check if the certificate is valid at `time`
    pub fn is_valid_at(&self, time: SystemTime) -> bool {
        let nb = parse_time(&self.not_before);
        let na = parse_time(&self.not_after);
        match (nb, na) {
            (Some(nb), Some(na)) => time >= nb && time <= na,
            _ => false,
        }
    }

    /// Check if certificate matches the given hostname
    pub fn matches_hostname(&self, host: &str) -> bool {
        for name in self.subject_alt_names() {
            if dns_matches(host, &name) { return true; }
        }
        if let Some(cn) = self.subject_cn() {
            if dns_matches(host, &cn) { return true; }
        }
        false
    }
}

/// Parse OID sequence
fn parse_oid_sequence(data: &[u8]) -> Result<String, String> {
    let mut rdr = DerReader::new(Cursor::new(data));
    let first = rdr.read_object().map_err(|e| e.to_string())?;
    if first.tag == 0x30 {
        let mut inner = DerReader::new(Cursor::new(&first.value));
        let oid = inner.read_object().map_err(|e| e.to_string())?;
        if oid.tag != 0x06 { return Err("Expected OID".into()); }
        Ok(decode_oid(&oid.value))
    } else if first.tag == 0x06 {
        Ok(decode_oid(&first.value))
    } else {
        Err("Expected SEQUENCE or OID".into())
    }
}

/// Decode DER OID to dotted string
fn decode_oid(bytes: &[u8]) -> String {
    let mut nodes = Vec::new();
    nodes.push((bytes[0] / 40).to_string());
    nodes.push((bytes[0] % 40).to_string());
    let mut val = 0u32;
    for &b in &bytes[1..] {
        val = (val << 7) | (b & 0x7F) as u32;
        if b & 0x80 == 0 {
            nodes.push(val.to_string());
            val = 0;
        }
    }
    nodes.join(".")
}

/// Convert ASN.1 time string into SystemTime
fn parse_time(s: &str) -> Option<SystemTime> {
    if !s.ends_with('Z') { return None; }
    let bytes = s.as_bytes();
    match bytes.len() {
        13 => { // UTCTime YYMMDDHHMMSSZ
            let year = std::str::from_utf8(&bytes[0..2]).ok()?.parse::<i32>().ok()?;
            let year = if year < 50 { 2000 + year } else { 1900 + year };
            parse_components(year, &bytes[2..])
        }
        15 => { // GeneralizedTime YYYYMMDDHHMMSSZ
            let year = std::str::from_utf8(&bytes[0..4]).ok()?.parse::<i32>().ok()?;
            parse_components(year, &bytes[4..])
        }
        _ => None,
    }
}

fn parse_components(year: i32, rest: &[u8]) -> Option<SystemTime> {
    let month = std::str::from_utf8(&rest[0..2]).ok()?.parse::<u32>().ok()?;
    let day = std::str::from_utf8(&rest[2..4]).ok()?.parse::<u32>().ok()?;
    let hour = std::str::from_utf8(&rest[4..6]).ok()?.parse::<u32>().ok()?;
    let min = std::str::from_utf8(&rest[6..8]).ok()?.parse::<u32>().ok()?;
    let sec = std::str::from_utf8(&rest[8..10]).ok()?.parse::<u32>().ok()?;
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64;
    if secs < 0 { None } else { Some(UNIX_EPOCH + Duration::from_secs(secs as u64)) }
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if m < 1 || m > 12 || d == 0 || d > 31 { return None; }
    let y = y - (m <= 2) as i32;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m as i32 + if m > 2 { -3 } else { 9 }) + 2) / 5 + d as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) as i64)
}

fn dns_matches(host: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[2..].to_ascii_lowercase();
        if let Some(pos) = host.find('.') {
            return host[pos+1..].eq_ignore_ascii_case(suffix);
        }
        false
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

impl CertificateChain {
    /// Parse certificate chain from TLS Certificate message payload
    pub fn parse(data: &[u8]) -> std::io::Result<Self> {
        if data.len() < 3 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated")); }
        let total_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
        if total_len + 3 != data.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad length")); }
        let mut idx = 3;
        let mut certs = Vec::new();
        while idx < data.len() {
            if idx + 3 > data.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated")); }
            let len = ((data[idx] as usize) << 16) | ((data[idx+1] as usize) << 8) | (data[idx+2] as usize);
            idx += 3;
            if idx + len > data.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated")); }
            let cert = X509Certificate::parse(&data[idx..idx+len])?;
            certs.push(cert);
            idx += len;
        }
        Ok(CertificateChain { certificates: certs })
    }

    /// Verify the certificate chain against `trusted_roots` and the `hostname`.
    pub fn verify(&self, hostname: &str, trusted_roots: &[X509Certificate]) -> Result<(), String> {
        if self.certificates.is_empty() { return Err("empty chain".into()); }
        let now = SystemTime::now();
        for cert in &self.certificates {
            if !cert.is_valid_at(now) { return Err("certificate expired".into()); }
        }
        for i in 0..self.certificates.len()-1 {
            let cert = &self.certificates[i];
            let issuer = &self.certificates[i+1];
            if !cert.verify_with(issuer)? { return Err("signature check failed".into()); }
        }
        // ensure the last certificate in the chain is issued by a trusted root
        let last = self.certificates.last().unwrap();
        let mut trusted = false;
        for root in trusted_roots {
            if last.issuer == root.subject {
                if last.verify_with(root)? {
                    trusted = true;
                    break;
                }
            }
        }
        if !trusted {
            return Err("untrusted root".into());
        }
        if !self.certificates[0].matches_hostname(hostname) {
            return Err("hostname mismatch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_x509() {
        let der = include_bytes!("../../tests/test.cer"); // Replace with actual DER file
        let cert = X509Certificate::parse(der).expect("Failed to parse X509 certificate");
        // Print the parsed certificate details
        println!("Version: {}", cert.version);
        println!("Serial: {:?}", cert.serial);
        println!("Signature Algorithm Inner: {}", cert.sig_alg_inner);
        println!("Issuer: {:?}", cert.issuer);
        println!("Not Before: {}", cert.not_before);
        println!("Not After: {}", cert.not_after);
        println!("Subject: {:?}", cert.subject);
        println!("Public Key: {:?}", cert.pubkey);
        println!("Signature Algorithm Outer: {}", cert.sig_alg_outer);
        println!("Signature: {:?}", cert.signature);
        println!("Modulus bytes: {}", cert.modulus.to_bytes_be().len());
        println!("Exponent: {}", cert.exponent);
        // Verify the signature
        let verified = cert.verify().expect("Signature verification failed");
        println!("verified? {}", verified);
        // Add more assertions as needed to validate the parsed data
        assert!(!cert.serial.is_empty(), "Serial number should not be empty");
        assert!(!cert.issuer.is_empty(), "Issuer should not be empty");
        assert!(!cert.subject.is_empty(), "Subject should not be empty");
        assert!(!cert.pubkey.is_empty(), "Public key should not be empty");
        assert!(!cert.signature.is_empty(), "Signature should not be empty");
    }

    #[test]
    fn test_certificate_chain_verify() {
        let der = include_bytes!("../../tests/test.cer");
        // Build TLS certificate message payload with single certificate
        let mut chain = Vec::new();
        chain.extend_from_slice(&((der.len() as u32).to_be_bytes()[1..]));
        chain.extend_from_slice(der);
        let mut payload = Vec::new();
        payload.extend_from_slice(&((chain.len() as u32).to_be_bytes()[1..]));
        payload.extend_from_slice(&chain);
        let chain = CertificateChain::parse(&payload).expect("parse chain");
        assert_eq!(chain.certificates.len(), 1);
        let roots = vec![X509Certificate::parse(include_bytes!("../../tests/test.cer")).unwrap()];
        chain.verify("localhost", &roots).expect("verify chain");
        assert!(chain.certificates[0].matches_hostname("myapp.local"));
        assert!(!chain.certificates[0].matches_hostname("example.com"));
    }
}