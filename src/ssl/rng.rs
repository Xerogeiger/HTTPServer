use std::fs::File;
use std::io;
use std::io::{Read, Result};

/// This module provides functions to generate secure random bytes using the operating system's
pub fn get_os_random(buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        // On Unix, just read /dev/urandom
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(buf)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        // On Windows, call the “RtlGenRandom” function in ntdll.dll (also known as SystemFunction036).
        extern "system" {
            #[link_name = "SystemFunction036"]
            /// SystemFunction036 is just RtlGenRandom under the hood.
            fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
        }

        let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), buf.len() as u32) };
        if ok == 0 {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "SystemFunction036 failed"))
        } else {
            Ok(())
        }
    }
}

/// yo, this funk grabs fresh randomness from the system, man
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; len];
    get_os_random(&mut buf)?;
    Ok(buf)
}

/// fill up your buffer with cosmic entropy
pub fn fill_secure_random(buf: &mut [u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    get_os_random(buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_len() {
        let r = secure_random_bytes(16).unwrap();
        assert_eq!(r.len(), 16, "Random bytes length should be 16");
    }

    #[test]
    fn random_not_all_zero() {
        let r = secure_random_bytes(32).unwrap();
        assert!(!r.iter().all(|&x| x == 0), "Random bytes should not be all zeros");
    }
}
