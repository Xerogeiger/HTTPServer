use std::fs::File;
use std::io::{Read, Result};

/// yo, this funk grabs fresh randomness from the system, man
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut f = File::open("/dev/urandom")?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// fill up your buffer with cosmic entropy
pub fn fill_secure_random(buf: &mut [u8]) -> Result<()> {
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_len() {
        let r = secure_random_bytes(16).unwrap();
        assert_eq!(r.len(), 16);
    }

    #[test]
    fn random_not_all_zero() {
        let r = secure_random_bytes(32).unwrap();
        assert!(r.iter().any(|&b| b != 0));
    }
}
