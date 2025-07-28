use std::cmp::Ordering;
use std::fmt;

/// A simple big-unsigned-integer for modular arithmetic (base 2³² limbs).
#[derive(Clone, Debug)]
pub struct BigUint(Vec<u32>);

/// Threshold above which Karatsuba multiplication is used.
const KARATSUBA_THRESHOLD: usize = 32;

// Helper functions for Karatsuba multiplication
fn trim_be(mut v: Vec<u32>) -> Vec<u32> {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    if i > 0 {
        v.drain(0..i);
    }
    if v.is_empty() {
        v.push(0);
    }
    v
}

fn add_be(a: &[u32], b: &[u32]) -> Vec<u32> {
    let len = a.len().max(b.len()) + 1;
    let mut res = vec![0u32; len];
    let mut carry: u64 = 0;
    for i in 0..len {
        let ai = if a.len() > i {
            a[a.len() - 1 - i] as u64
        } else {
            0
        };
        let bi = if b.len() > i {
            b[b.len() - 1 - i] as u64
        } else {
            0
        };
        let s = ai + bi + carry;
        res[len - 1 - i] = s as u32;
        carry = s >> 32;
    }
    trim_be(res)
}

fn sub_be(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut res = vec![0u32; a.len()];
    let mut borrow: i64 = 0;
    for i in 0..a.len() {
        let av = a[a.len() - 1 - i] as i64;
        let bv = if b.len() > i {
            b[b.len() - 1 - i] as i64
        } else {
            0
        };
        let mut d = av - bv - borrow;
        if d < 0 {
            d += 1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        res[a.len() - 1 - i] = d as u32;
    }
    trim_be(res)
}

fn shl_be(a: &[u32], n: usize) -> Vec<u32> {
    if a.is_empty() || (a.len() == 1 && a[0] == 0) {
        return vec![0];
    }
    let mut res = Vec::with_capacity(a.len() + n);
    res.extend_from_slice(a);
    res.extend(std::iter::repeat(0).take(n));
    res
}

fn schoolbook_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return vec![0];
    }
    let al = a.len();
    let bl = b.len();
    let mut res = vec![0u32; al + bl];
    for ia in (0..al).rev() {
        let aval = a[ia] as u64;
        let mut carry = 0u64;
        let mut idx = res.len() - 1 - (al - 1 - ia);
        for ib in (0..bl).rev() {
            let pos = idx - (bl - 1 - ib);
            let tmp = aval * b[ib] as u64 + res[pos] as u64 + carry;
            res[pos] = tmp as u32;
            carry = tmp >> 32;
        }
        res[idx - bl] = (res[idx - bl] as u64 + carry) as u32;
    }
    trim_be(res)
}

fn karatsuba_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return vec![0];
    }
    let n = a.len().max(b.len());
    if n <= KARATSUBA_THRESHOLD {
        return schoolbook_mul(a, b);
    }
    let m = n / 2;
    let (ah, al) = if a.len() > m {
        (&a[..a.len() - m], &a[a.len() - m..])
    } else {
        (&[][..], a)
    };
    let (bh, bl) = if b.len() > m {
        (&b[..b.len() - m], &b[b.len() - m..])
    } else {
        (&[][..], b)
    };
    let z0 = karatsuba_mul(al, bl);
    let z2 = karatsuba_mul(ah, bh);
    let sum_a = add_be(al, ah);
    let sum_b = add_be(bl, bh);
    let mut z1 = karatsuba_mul(&sum_a, &sum_b);
    z1 = sub_be(&z1, &z0);
    z1 = sub_be(&z1, &z2);
    let mut res = shl_be(&z2, m * 2);
    res = add_be(&res, &shl_be(&z1, m));
    res = add_be(&res, &z0);
    trim_be(res)
}

// ---- Montgomery helpers ---------------------------------------------------

fn inv32(a: u32) -> u32 {
    let mut x = a;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

fn to_le_padded(v: &[u32], len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let val = if i < v.len() { v[v.len() - 1 - i] } else { 0 };
        out.push(val);
    }
    out
}

fn cmp_le(a: &[u32], b: &[u32]) -> Ordering {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

fn sub_le(a: &mut [u32], b: &[u32]) {
    let mut borrow: i64 = 0;
    for i in 0..a.len() {
        let av = a[i] as i64;
        let bv = b[i] as i64;
        let mut d = av - bv - borrow;
        if d < 0 {
            d += 1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = d as u32;
    }
}

fn montgomery_mul_raw(a: &BigUint, b: &BigUint, m: &BigUint, n0_inv: u32) -> BigUint {
    let n = m.0.len();
    let a_le = to_le_padded(&a.0, n);
    let b_le = to_le_padded(&b.0, n);
    let m_le = to_le_padded(&m.0, n);

    let mut t = vec![0u32; n + 1];
    for i in 0..n {
        let ai = a_le[i] as u64;
        let mut carry = 0u64;
        for j in 0..n {
            let u = t[j] as u64 + ai * b_le[j] as u64 + carry;
            t[j] = u as u32;
            carry = u >> 32;
        }
        let mut u = t[n] as u64 + carry;
        t[n] = u as u32;

        let m_i = t[0].wrapping_mul(n0_inv);
        let mut carry2 = 0u64;
        for j in 0..n {
            let u2 = t[j] as u64 + (m_i as u64) * m_le[j] as u64 + carry2;
            t[j] = u2 as u32;
            carry2 = u2 >> 32;
        }
        u = t[n] as u64 + carry2;
        t[n] = u as u32;
        let carry_hi = u >> 32;

        for j in 0..n {
            t[j] = t[j + 1];
        }
        t[n] = carry_hi as u32;
    }

    let mut res = t[..n].to_vec();
    if t[n] != 0 || cmp_le(&res, &m_le) != Ordering::Less {
        sub_le(&mut res, &m_le);
    }
    let res_be: Vec<u32> = res.into_iter().rev().collect();
    BigUint::new(res_be)
}


impl BigUint {
    /// Create a new BigUint trimming leading zeros.
    fn new(limbs: Vec<u32>) -> Self {
        let mut i = 0;
        while i + 1 < limbs.len() && limbs[i] == 0 {
            i += 1;
        }
        if i == limbs.len() {
            return BigUint(vec![0]);
        }
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
        if rhs == 0 {
            return BigUint::zero();
        }
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

    /// Multiply two BigUints using schoolbook multiplication.
    pub fn mul(&self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }
        if self.0.len() > KARATSUBA_THRESHOLD && other.0.len() > KARATSUBA_THRESHOLD {
            BigUint::new(karatsuba_mul(&self.0, &other.0))
        } else {
            let al = self.0.len();
            let bl = other.0.len();
            let mut res = vec![0u32; al + bl];
            for ia in (0..al).rev() {
                let a = self.0[ia] as u64;
                let mut carry = 0u64;
                let mut idx = res.len() - 1 - (al - 1 - ia);
                for ib in (0..bl).rev() {
                    let pos = idx - (bl - 1 - ib);
                    let tmp = a * other.0[ib] as u64 + res[pos] as u64 + carry;
                    res[pos] = tmp as u32;
                    carry = tmp >> 32;
                }
                res[idx - bl] = (res[idx - bl] as u64 + carry) as u32;
            }
            BigUint::new(res)
        }
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
            let bi = if bl > i {
                other.0[bl - 1 - i] as u64
            } else {
                0
            };
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
            let bv = if bl > i {
                other.0[bl - 1 - i] as i64
            } else {
                0
            };
            let mut d = av - bv - borrow;
            if d < 0 {
                d += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
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

    /// Compute (self * other) mod m using a basic schoolbook approach.
    pub fn mul_mod_montgomery(&self, other: &BigUint, m: &BigUint) -> BigUint {
        assert!(m.0.last().unwrap() % 2 == 1, "modulus must be odd");

        let n = m.0.len();
        let mut r_digits = vec![0u32; n + 1];
        r_digits[0] = 1;
        let r = BigUint::new(r_digits);
        let r2 = r.mul(&r);
        let r2_mod = r2.rem(m);

        let mut n0_inv = inv32(*m.0.last().unwrap());
        n0_inv = n0_inv.wrapping_neg();

        let a_m = montgomery_mul_raw(self, &r2_mod, m, n0_inv);
        let b_m = montgomery_mul_raw(other, &r2_mod, m, n0_inv);
        let prod = montgomery_mul_raw(&a_m, &b_m, m, n0_inv);
        montgomery_mul_raw(&prod, &BigUint::one(), m, n0_inv)
    }

    /// Modular exponentiation: self^exp mod m.
    pub fn modpow(&self, exp: &BigUint, m: &BigUint) -> BigUint {
        assert!(m.0.last().unwrap() % 2 == 1, "modulus must be odd");

        let n = m.0.len();
        let mut r_digits = vec![0u32; n + 1];
        r_digits[0] = 1;
        let r = BigUint::new(r_digits);
        let r2 = r.mul(&r);
        let r2_mod = r2.rem(m);

        let mut n0_inv = inv32(*m.0.last().unwrap());
        n0_inv = n0_inv.wrapping_neg();

        let mut base = montgomery_mul_raw(self, &r2_mod, m, n0_inv);
        let mut result = montgomery_mul_raw(&BigUint::one(), &r2_mod, m, n0_inv);

        for &digit in exp.0.iter() {
            for i in (0..32).rev() {
                result = montgomery_mul_raw(&result, &result, m, n0_inv);
                if (digit >> i) & 1 == 1 {
                    result = montgomery_mul_raw(&result, &base, m, n0_inv);
                }
            }
        }

        montgomery_mul_raw(&result, &BigUint::one(), m, n0_inv)
    }

    /// Divide by a small integer, returning (quotient, remainder).
    pub fn div_rem_u32(&self, rhs: u32) -> (BigUint, u32) {
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

    #[test]
    fn test_mul_mod_montgomery_basic() {
        let a = BigUint::from_bytes_be(&123456789u32.to_be_bytes());
        let b = BigUint::from_bytes_be(&987654321u32.to_be_bytes());
        let m = BigUint::from_bytes_be(&1000000007u32.to_be_bytes());
        let r = a.mul_mod_montgomery(&b, &m);
        assert_eq!(r.to_bytes_be(), vec![0x0F, 0x71, 0xA8, 0x2B]);
    }

    #[test]
    fn test_add_sub_roundtrip() {
        let a = BigUint::from_bytes_be(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let b = BigUint::from_bytes_be(&[11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff.to_bytes_be(), a.to_bytes_be());
    }

    #[test]
    fn test_mul_div_roundtrip() {
        let a = BigUint::from_bytes_be(&[10, 20, 30, 40]);
        let b = 123u32;
        let prod = a.mul_u32(b);
        let (q, r) = prod.div_rem_u32(b);
        assert_eq!(r, 0);
        assert_eq!(q.to_bytes_be(), a.to_bytes_be());
    }

    #[test]
    fn test_modpow_large() {
        let base = BigUint::from_bytes_be(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        let exp = BigUint::from_bytes_be(&[5]);
        let m = BigUint::from_bytes_be(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let mut expected = BigUint::one();
        for _ in 0..5 {
            expected = expected.mul_mod(&base, &m);
        }
        let r = base.modpow(&exp, &m);
        assert_eq!(r.to_bytes_be(), expected.to_bytes_be());
    }

    #[test]
    fn test_mul_mod_montgomery_large() {
        let a = BigUint::from_bytes_be(&[0xAB; 64]);
        let b = BigUint::from_bytes_be(&[0xCD; 64]);
        let m = BigUint::from_bytes_be(&[0xEF; 65]);
        let r_school = a.mul_mod(&b, &m);
        let r_mont = a.mul_mod_montgomery(&b, &m);
        assert_eq!(r_school.to_bytes_be(), r_mont.to_bytes_be());
    }

    #[test]
    fn test_karatsuba_large_mul() {
        use num_bigint::BigUint as NumBigUint;

        let a_bytes = vec![0x12u8; 200];
        let b_bytes = vec![0x34u8; 200];

        let a = BigUint::from_bytes_be(&a_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);
        let prod = a.mul(&b);

        let na = NumBigUint::from_bytes_be(&a_bytes);
        let nb = NumBigUint::from_bytes_be(&b_bytes);
        let expected = na * nb;

        assert_eq!(prod.to_bytes_be(), expected.to_bytes_be());
    }

    #[test]
    fn biguint_ops_sanity() {
        let a = BigUint::from_bytes_be(&[1, 2, 3, 4]);
        let b = BigUint::from_bytes_be(&[4, 3, 2, 1]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff.to_bytes_be(), a.to_bytes_be());
    }
}
