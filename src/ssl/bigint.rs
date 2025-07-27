use std::cmp::Ordering;
use std::fmt;

/// A simple big-unsigned-integer for modular arithmetic (base 2³² limbs).
#[derive(Clone, Debug)]
pub struct BigUint(Vec<u32>);

impl BigUint {
    /// Create a new BigUint trimming leading zeros.
    fn new(limbs: Vec<u32>) -> Self {
        let mut i = 0;
        while i + 1 < limbs.len() && limbs[i] == 0 { i += 1; }
        if i == limbs.len() { return BigUint(vec![0]); }
        BigUint(limbs[i..].to_vec())
    }

    /// Zero constant
    fn zero() -> Self {
        BigUint(vec![0])
    }

    /// One constant
    fn one() -> Self {
        BigUint(vec![1])
    }

    /// Check if value is zero
    fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }

    /// Multiply by a single 32-bit digit.
    fn mul_u32(&self, rhs: u32) -> BigUint {
        if rhs == 0 { return BigUint::zero(); }
        let mut res = vec![0u32; self.0.len() + 1];
        let mut carry: u64 = 0;
        for i in (0..self.0.len()).rev() {
            let prod = self.0[i] as u64 * rhs as u64 + carry;
            res[i + 1] = prod as u32;
            carry = prod >> 32;
        }
        res[0] = carry as u32;
        BigUint::new(res)
    }

    /// Multiply two BigUints.
    fn mul(&self, other: &BigUint) -> BigUint {
        if self.0.iter().all(|&x| x == 0) || other.0.iter().all(|&x| x == 0) {
            return BigUint::zero();
        }
        let len = self.0.len() + other.0.len();
        let mut res = vec![0u32; len];
        for (ia, &a) in self.0.iter().rev().enumerate() {
            let mut carry: u64 = 0;
            for (ib, &b) in other.0.iter().rev().enumerate() {
                let idx = len - 1 - (ia + ib);
                let prod = a as u64 * b as u64 + res[idx] as u64 + carry;
                res[idx] = prod as u32;
                carry = prod >> 32;
            }
            res[len - 1 - (ia + other.0.len())] = carry as u32;
        }
        BigUint::new(res)
    }

    /// Compute self modulo m via long division.
    pub fn rem(&self, m: &BigUint) -> BigUint {
        if self.cmp(m) == Ordering::Less {
            return self.clone();
        }
        let (mut q, mut r) = (Vec::new(), BigUint::zero());
        for &limb in &self.0 {
            if !(r.0.len() == 1 && r.0[0] == 0) {
                r.0.push(limb);
            } else {
                r.0[0] = limb;
            }
            let mut low: u64 = 0;
            let mut high: u64 = 0xFFFF_FFFF;
            while low <= high {
                let mid = ((low + high) >> 1) as u32;
                let candidate = m.mul_u32(mid);
                if candidate.cmp(&r) == Ordering::Greater {
                    if mid == 0 {
                        break;
                    }
                    high = mid as u64 - 1;
                } else {
                    low = mid as u64 + 1;
                }
            }
            let qdigit = high as u32;
            if qdigit > 0 {
                let sub = m.mul_u32(qdigit);
                r = r.sub(&sub);
            }
            q.push(qdigit);
        }
        r
    }
}

impl BigUint {
    /// Construct from big-endian bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> BigUint {
        let mut limbs = Vec::new();
        let rem = bytes.len() % 4;
        let mut i = 0;
        if rem != 0 {
            let mut buf = [0u8; 4];
            buf[4 - rem..].copy_from_slice(&bytes[..rem]);
            limbs.push(u32::from_be_bytes(buf));
            i += rem;
        }
        while i < bytes.len() {
            limbs.push(u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()));
            i += 4;
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
        BigUint::new(limbs)
    }

    /// Compare two BigUint.
    pub fn cmp(&self, other: &BigUint) -> Ordering {
        let a = &self.0;
        let b = &other.0;
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for (x, y) in a.iter().zip(b.iter()) {
            if x != y {
                return x.cmp(y);
            }
        }
        Ordering::Equal
    }

    /// Add two BigUint.
    pub fn add(&self, other: &BigUint) -> BigUint {
        let al = self.0.len();
        let bl = other.0.len();
        let len = al.max(bl) + 1;
        let mut res = vec![0u32; len];
        let mut carry: u64 = 0;
        for i in 0..len {
            let ai = if al > i { self.0[al - 1 - i] as u64 } else { 0 };
            let bi = if bl > i { other.0[bl - 1 - i] as u64 } else { 0 };
            let s = ai + bi + carry;
            res[len - 1 - i] = s as u32;
            carry = s >> 32;
        }
        BigUint::new(res)
    }

    /// Subtract other from self (assumes self ≥ other).
    pub fn sub(&self, other: &BigUint) -> BigUint {
        let al = self.0.len();
        let bl = other.0.len();
        let mut res = vec![0u32; al];
        let mut borrow: i64 = 0;
        for i in 0..al {
            let av = self.0[al - 1 - i] as i64;
            let bv = if bl > i { other.0[bl - 1 - i] as i64 } else { 0 };
            let mut d = av - bv - borrow;
            if d < 0 { d += 1 << 32; borrow = 1; } else { borrow = 0; }
            res[al - 1 - i] = d as u32;
        }
        BigUint::new(res)
    }

    /// Compute (self + other) mod m.
    pub fn add_mod(&self, other: &BigUint, m: &BigUint) -> BigUint {
        let sum = self.add(other);
        if sum.cmp(m) != Ordering::Less {
            sum.sub(m)
        } else {
            sum
        }
    }

    /// Compute (self * other) mod m using schoolbook multiplication.
    pub fn mul_mod(&self, other: &BigUint, m: &BigUint) -> BigUint {
        let prod = self.mul(other);
        prod.rem(m)
    }

    /// Modular exponentiation: self^exp mod m.
    pub fn modpow(&self, exp: &BigUint, m: &BigUint) -> BigUint {
        let mut result = BigUint::from_bytes_be(&[1]);
        let base = self.rem(m);
        for &digit in exp.0.iter() {
            for i in (0..32).rev() {
                result = result.mul_mod(&result, m);
                if (digit >> i) & 1 == 1 {
                    result = result.mul_mod(&base, m);
                }
            }
        }
        result
    }

    /// Divide by a small integer, returning (quotient, remainder).
    fn div_rem_u32(&self, rhs: u32) -> (BigUint, u32) {
        assert!(rhs != 0);
        let mut rem: u64 = 0;
        let mut quo_limbs = Vec::with_capacity(self.0.len());
        for &limb in &self.0 {
            let acc = (rem << 32) | limb as u64;
            let q = (acc / rhs as u64) as u32;
            rem = acc % rhs as u64;
            quo_limbs.push(q);
        }
        let mut i = 0;
        while i + 1 < quo_limbs.len() && quo_limbs[i] == 0 {
            i += 1;
        }
        (BigUint(quo_limbs[i..].to_vec()), rem as u32)
    }

    /// Divide by a small integer, discarding the remainder.
    pub fn div_u32(&self, rhs: u32) -> BigUint {
        self.div_rem_u32(rhs).0
    }

    /// Emit big-endian bytes.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 4);
        for &limb in &self.0 {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        let mut i = 0;
        while i + 1 < out.len() && out[i] == 0 {
            i += 1;
        }
        out[i..].to_vec()
    }
}

/// Implement decimal display for BigUint
impl fmt::Display for BigUint {
    /// Formats the BigUint as a base-10 string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Special case zero
        if self.0.iter().all(|&limb| limb == 0) {
            return write!(f, "0");
        }
        // Repeatedly divide by 10 to collect digits
        let mut digits = Vec::new();
        let mut cur = self.clone();
        while !cur.0.iter().all(|&l| l == 0) {
            let (q, r) = cur.div_rem_u32(10);
            digits.push((b'0' + (r as u8)) as char);
            cur = q;
        }
        // Digits are in little-endian order
        for ch in digits.iter().rev() {
            write!(f, "{}", ch)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modpow_small() {
        let a = BigUint::from_bytes_be(&[2]);
        let e = BigUint::from_bytes_be(&[5]);
        let m = BigUint::from_bytes_be(&[7]);
        let r = a.modpow(&e, &m);
        assert_eq!(r.to_bytes_be(), vec![4]);
    }

    #[test]
    fn test_mul_mod_basic() {
        let a = BigUint::from_bytes_be(&123456789u32.to_be_bytes());
        let b = BigUint::from_bytes_be(&987654321u32.to_be_bytes());
        let m = BigUint::from_bytes_be(&1000000007u32.to_be_bytes());
        let r = a.mul_mod(&b, &m);
        assert_eq!(r.to_bytes_be(), vec![0x0F, 0x71, 0xA8, 0x2B]); // 259106859
    }
}
