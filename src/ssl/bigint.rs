use std::cmp::Ordering;
use std::fmt;

/// A simple big-unsigned-integer for modular arithmetic (base 2³² limbs).
#[derive(Clone, Debug)]
pub struct BigUint(Vec<u32>);

impl BigUint {
    /// Create a new BigUint trimming leading zeros.
    fn new(mut limbs: Vec<u32>) -> Self {
        while limbs.len() > 1 && limbs[0] == 0 {
            limbs.remove(0);
        }
        BigUint(limbs)
    }

    /// Zero constant
    fn zero() -> Self {
        BigUint(vec![0])
    }

    /// Multiply by a single 32-bit digit.
    fn mul_u32(&self, rhs: u32) -> BigUint {
        if rhs == 0 {
            return BigUint::zero();
        }
        let mut res_rev = Vec::with_capacity(self.0.len() + 1);
        let mut carry: u64 = 0;
        for &limb in self.0.iter().rev() {
            let prod = limb as u64 * rhs as u64 + carry;
            res_rev.push((prod & 0xFFFF_FFFF) as u32);
            carry = prod >> 32;
        }
        if carry > 0 {
            res_rev.push(carry as u32);
        }
        res_rev.reverse();
        BigUint::new(res_rev)
    }

    /// Multiply two BigUints.
    fn mul(&self, other: &BigUint) -> BigUint {
        let mut result = BigUint::zero();
        for (i, &digit) in other.0.iter().rev().enumerate() {
            if digit == 0 {
                continue;
            }
            let mut part = self.mul_u32(digit).0;
            part.extend(std::iter::repeat(0).take(i));
            result = result.add(&BigUint::new(part));
        }
        result
    }

    /// Compute self modulo m via long division.
    fn rem(&self, m: &BigUint) -> BigUint {
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
        let a = &self.0;
        let b = &other.0;
        let mut res = Vec::with_capacity(a.len().max(b.len()) + 1);
        let mut carry = 0u64;
        let mut i = 0;
        while i < a.len() || i < b.len() || carry > 0 {
            let av = *a.get(a.len().wrapping_sub(1).wrapping_sub(i)).unwrap_or(&0) as u64;
            let bv = *b.get(b.len().wrapping_sub(1).wrapping_sub(i)).unwrap_or(&0) as u64;
            let sum = av + bv + carry;
            res.push((sum & 0xFFFF_FFFF) as u32);
            carry = sum >> 32;
            i += 1;
        }
        res.reverse();
        BigUint::new(res)
    }

    /// Subtract other from self (assumes self ≥ other).
    pub fn sub(&self, other: &BigUint) -> BigUint {
        let a = &self.0;
        let b = &other.0;
        let mut res = Vec::with_capacity(a.len());
        let mut borrow = 0i64;
        let mut i = 0;
        while i < a.len() {
            let av = a[a.len().wrapping_sub(1).wrapping_sub(i)] as i64;
            let bv = *b.get(b.len().wrapping_sub(1).wrapping_sub(i)).unwrap_or(&0) as i64;
            let mut diff = av - bv - borrow;
            if diff < 0 {
                diff += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            res.push(diff as u32);
            i += 1;
        }
        res.reverse();
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
        // Trim leading zeros
        let first_non_zero = quo_limbs
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(quo_limbs.len() - 1);
        let quo = quo_limbs[first_non_zero..].to_vec();
        (BigUint(quo), rem as u32)
    }

    /// Emit big-endian bytes.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for &limb in &self.0 {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        // remove leading zeros
        while out.len() > 1 && out[0] == 0 {
            out.remove(0);
        }
        out
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
