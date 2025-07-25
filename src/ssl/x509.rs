use std::io::{Cursor, Read};
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
}