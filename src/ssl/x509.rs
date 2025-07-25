use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct DerObject {
    pub tag: u8,
    pub length: usize,
    pub value: Vec<u8>,
}

pub struct DerReader<R: Read> {
    reader: R,
}

pub struct X509Certificate {
    pub version: u32,
    pub serial: Vec<u8>,
    pub sig_alg_inner: String,  // e.g. "1.2.840.113549.1.1.11"
    pub issuer: Vec<u8>,        // raw DER of RDNSequence
    pub not_before: String,     // e.g. "YYMMDDhhmmssZ"
    pub not_after: String,
    pub subject: Vec<u8>,
    pub pubkey: Vec<u8>,        // SubjectPublicKeyInfo DER
    pub sig_alg_outer: String,
    pub signature: Vec<u8>,     // raw signature bytes
}

impl <R: Read> DerReader<R> {
    pub fn new(reader: R) -> Self {
        DerReader { reader }
    }

    pub fn read_object(&mut self) -> std::io::Result<DerObject> {
        let mut tag_buf = [0u8; 1];
        self.reader.read_exact(&mut tag_buf)?;
        let tag = tag_buf[0];

        let mut length_buf = [0u8; 1];
        self.reader.read_exact(&mut length_buf)?;
        let length = if length_buf[0] & 0x80 == 0 {
            length_buf[0] as usize
        } else {
            let num_length_bytes = length_buf[0] & 0x7F;
            let mut length_bytes = vec![0u8; num_length_bytes as usize];
            self.reader.read_exact(&mut length_bytes)?;
            length_bytes
                .into_iter()
                .fold(0, |acc, b| (acc << 8) | (b as usize))
        };

        let mut value = vec![0u8; length];
        self.reader.read_exact(&mut value)?;

        Ok(DerObject {
            tag,
            length,
            value,
        })
    }
}

impl X509Certificate {
    pub fn parse(der: &[u8]) -> std::io::Result<Self> {
        let mut reader = DerReader::new(Cursor::new(der));

        // Read the outer sequence
        let sequence = reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        if sequence.tag != 0x30 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected SEQUENCE tag"));
        }

        // Now we need a new reader to parse the tbsCertificate
        let mut cert_reader = DerReader::new(Cursor::new(&sequence.value));

        // Read the tbsCertificate
        let tbs_sequence = cert_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut tbs_reader = DerReader::new(Cursor::new(&tbs_sequence.value));

        // Inside tbsCertificate, we expect the version, serial number, issuer, subject, and public key
        {
            let first = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let (version, serial_obj) = if first.tag == 0xA0 {
                let mut vr = DerReader::new(Cursor::new(&first.value));
                let version_obj = vr.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let version = version_obj.value.iter().fold(0, |acc, &b| (acc << 8) | (b as u32)) + 1;
                let serial_obj = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                (version, serial_obj)
            } else {
                (1, first)
            };

            let serial_number = serial_obj.value.clone();

            let signature_algorithm = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let signature_algorithm_inner = parse_oid_sequence(&signature_algorithm.value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let issuer = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let validity = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let mut vr = DerReader::new(Cursor::new(&validity.value));
            //Not before and not after objects
            let nb = vr.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let na = vr.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let not_before= String::from_utf8_lossy(&nb.value).to_string();
            let not_after = String::from_utf8_lossy(&na.value).to_string();

            let subject = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let public_key = tbs_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let outer_signature_object = cert_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let outer_signature_algorithm = parse_oid_sequence(&outer_signature_object.value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let signature_value = cert_reader.read_object().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            if signature_value.tag != 0x03 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected BIT STRING for signature value"));
            }

            // Skip the first byte which is the unused bits count
            let signature = signature_value.value[1..].to_vec();

            Ok(X509Certificate {
                version,
                serial: serial_number,
                sig_alg_inner: signature_algorithm_inner,
                issuer: issuer.value,
                not_before,
                not_after,
                subject: subject.value,
                pubkey: public_key.value,
                sig_alg_outer: outer_signature_algorithm,
                signature,
            })
        }
    }
}

/// Parse an AlgorithmIdentifier SEQUENCE (OID + optional params) into the OID string.
fn parse_oid_sequence(data: &[u8]) -> Result<String, String> {
    let mut rdr = DerReader::new(Cursor::new(data));

    let first = rdr.read_object().map_err(|e| e.to_string())?;
    if first.tag == 0x30 {
        let mut inner = DerReader::new(Cursor::new(&first.value));
        let oid_obj = inner.read_object().map_err(|e| e.to_string())?;
        if oid_obj.tag != 0x06 { return Err("Expected OID".into()); }
        Ok(decode_oid(&oid_obj.value))
    } else if first.tag == 0x06 {
        Ok(decode_oid(&first.value))
    } else {
        Err("Expected SEQUENCE or OID".into())
    }
}

/// Convert DER OID bytes → "1.2.840.…" form.
fn decode_oid(bytes: &[u8]) -> String {
    let mut nodes = Vec::new();
    // first byte = 40*X + Y
    nodes.push((bytes[0] / 40).to_string());
    nodes.push((bytes[0] % 40).to_string());
    let mut value = 0u32;
    for &b in &bytes[1..] {
        value = (value << 7) | (u32::from(b) & 0x7F);
        if b & 0x80 == 0 {
            nodes.push(value.to_string());
            value = 0;
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
        // Add more assertions as needed to validate the parsed data
        assert!(!cert.serial.is_empty(), "Serial number should not be empty");
        assert!(!cert.issuer.is_empty(), "Issuer should not be empty");
        assert!(!cert.subject.is_empty(), "Subject should not be empty");
        assert!(!cert.pubkey.is_empty(), "Public key should not be empty");
        assert!(!cert.signature.is_empty(), "Signature should not be empty");
    }
}