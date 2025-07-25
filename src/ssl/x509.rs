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
            let mut buf = vec![0u8; num_bytes];
            self.reader.read_exact(&mut buf)?;
            buf.into_iter().fold(0, |acc, b| (acc << 8) | (b as usize))
        };

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
        let tbs_bytes = tbs_sequence.value.clone();
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
        let pubkey_der = spki_obj.value.clone();
        // Parse RSA key
        let (modulus, exponent) = {
            // pubkey_der is the raw bytes of SubjectPublicKeyInfo.value
            let mut spki_rdr = DerReader::new(Cursor::new(&pubkey_der));

            // 1) Read the SPKI SEQUENCE
            let spki_seq = spki_rdr.read_object()?;
            if spki_seq.tag != 0x30 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected SPKI SEQUENCE",
                ));
            }

            let mut spki_inner = DerReader::new(Cursor::new(&spki_seq.value));

            // 2) Read AlgorithmIdentifier (either SEQUENCE or direct OID)
            let alg_id = spki_inner.read_object()?;
            let oid_bytes = if alg_id.tag == 0x30 {
                let mut seq_rdr = DerReader::new(Cursor::new(&alg_id.value));
                let oid_obj = seq_rdr.read_object()?;
                if oid_obj.tag != 0x06 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Expected OID inside AlgorithmIdentifier",
                    ));
                }
                oid_obj.value
            } else if alg_id.tag == 0x06 {
                alg_id.value.clone()
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Expected AlgorithmIdentifier, found tag 0x{:02X}", alg_id.tag),
                ));
            };
            let _ = parse_oid_sequence(&oid_bytes); // discard or use
            // Optionally skip NULL params
            if let Ok(param) = spki_inner.read_object() {
                if param.tag != 0x05 {
                    // put back or ignore
                }
            }

            // 3) Now read the BIT STRING containing the RSA key
            let bs = spki_inner.read_object()?;
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
        let mut bytes = m_int.to_bytes_be();
        let mut rdr = DerReader::new(Cursor::new(&bytes));
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
        println!("Modulus: {}", cert.modulus);
        println!("Exponent: {}", cert.exponent);
        // Verify the signature
        assert!(cert.verify().expect("Signature verification failed"), "Signature verification should succeed");
        // Add more assertions as needed to validate the parsed data
        assert!(!cert.serial.is_empty(), "Serial number should not be empty");
        assert!(!cert.issuer.is_empty(), "Issuer should not be empty");
        assert!(!cert.subject.is_empty(), "Subject should not be empty");
        assert!(!cert.pubkey.is_empty(), "Public key should not be empty");
        assert!(!cert.signature.is_empty(), "Signature should not be empty");
    }
}