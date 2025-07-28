use crate::ssl::bigint::BigUint;
use crate::ssl::rng::secure_random_bytes;
use std::cmp::Ordering;
use std::io;

#[derive(Clone, Debug)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
    pub infinity: bool,
}

impl Point {
    fn infinity() -> Self {
        Point {
            x: BigUint::from_bytes_be(&[0]),
            y: BigUint::from_bytes_be(&[0]),
            infinity: true,
        }
    }
}

const P_BYTES: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff
];
const A_BYTES: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xfc
];
const B_BYTES: [u8; 32] = [
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,
    0xbc,0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,
    0x60,0x4b
];
const GX_BYTES: [u8; 32] = [
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,
    0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,
    0xc2,0x96
];
const GY_BYTES: [u8; 32] = [
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,
    0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,
    0x51,0xf5
];
const N_BYTES: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,
    0x25,0x51
];

fn p() -> BigUint { BigUint::from_bytes_be(&P_BYTES) }
fn a() -> BigUint { BigUint::from_bytes_be(&A_BYTES) }
fn b() -> BigUint { BigUint::from_bytes_be(&B_BYTES) }
fn gx() -> BigUint { BigUint::from_bytes_be(&GX_BYTES) }
fn gy() -> BigUint { BigUint::from_bytes_be(&GY_BYTES) }
fn n() -> BigUint { BigUint::from_bytes_be(&N_BYTES) }

fn add_mod(x: &BigUint, y: &BigUint) -> BigUint {
    x.add_mod(y, &p())
}

fn sub_mod(x: &BigUint, y: &BigUint) -> BigUint {
    if x.cmp(y) != Ordering::Less {
        x.sub(y)
    } else {
        let tmp = y.sub(x);
        p().sub(&tmp)
    }
}

fn mul_mod(x: &BigUint, y: &BigUint) -> BigUint {
    x.mul_mod(y, &p())
}

fn inv_mod(x: &BigUint) -> BigUint {
    let two = BigUint::from_bytes_be(&[2]);
    let exp = p().sub(&two);
    x.modpow(&exp, &p())
}

fn point_double(pt: &Point) -> Point {
    if pt.infinity {
        return pt.clone();
    }
    let zero = BigUint::from_bytes_be(&[0]);
    if pt.y.cmp(&zero) == Ordering::Equal {
        return Point::infinity();
    }
    let three = BigUint::from_bytes_be(&[3]);
    let two = BigUint::from_bytes_be(&[2]);
    let xx = mul_mod(&pt.x, &pt.x);
    let mut num = mul_mod(&xx, &three);
    num = add_mod(&num, &a());
    let denom = mul_mod(&pt.y, &two);
    let s = mul_mod(&num, &inv_mod(&denom));
    let s2 = mul_mod(&s, &s);
    let two_x = mul_mod(&pt.x, &two);
    let x3 = sub_mod(&s2, &two_x);
    let y3 = sub_mod(&mul_mod(&s, &sub_mod(&pt.x, &x3)), &pt.y);
    Point { x: x3, y: y3, infinity: false }
}

fn point_add(p1: &Point, p2: &Point) -> Point {
    if p1.infinity { return p2.clone(); }
    if p2.infinity { return p1.clone(); }

    if p1.x.cmp(&p2.x) == Ordering::Equal {
        let sum = add_mod(&p1.y, &p2.y);
        let zero = BigUint::from_bytes_be(&[0]);
        if sum.cmp(&zero) == Ordering::Equal {
            return Point::infinity();
        } else {
            return point_double(p1);
        }
    }
    let num = sub_mod(&p2.y, &p1.y);
    let denom = sub_mod(&p2.x, &p1.x);
    let s = mul_mod(&num, &inv_mod(&denom));
    let s2 = mul_mod(&s, &s);
    let x3 = sub_mod(&sub_mod(&s2, &p1.x), &p2.x);
    let y3 = sub_mod(&mul_mod(&s, &sub_mod(&p1.x, &x3)), &p1.y);
    Point { x: x3, y: y3, infinity: false }
}

fn scalar_mul(base: &Point, scalar: &BigUint) -> Point {
    let mut result = Point::infinity();
    for byte in scalar.to_bytes_be() {
        for i in (0..8).rev() {
            result = point_double(&result);
            if (byte >> i) & 1 == 1 {
                result = point_add(&result, base);
            }
        }
    }
    result
}

fn on_curve(pt: &Point) -> bool {
    if pt.infinity { return true; }
    if pt.x.cmp(&p()) != Ordering::Less || pt.y.cmp(&p()) != Ordering::Less {
        return false;
    }
    let y2 = mul_mod(&pt.y, &pt.y);
    let x3 = mul_mod(&mul_mod(&pt.x, &pt.x), &pt.x);
    let ax = mul_mod(&a(), &pt.x);
    let rhs = add_mod(&add_mod(&x3, &ax), &b());
    y2.cmp(&rhs) == Ordering::Equal
}

pub fn generate_keypair_p256() -> io::Result<(BigUint, Point)> {
    let order = n();
    loop {
        let bytes = secure_random_bytes(32)?;
        let priv_key = BigUint::from_bytes_be(&bytes);
        let zero = BigUint::from_bytes_be(&[0]);
        if priv_key.cmp(&zero) != Ordering::Equal && priv_key.cmp(&order) == Ordering::Less {
            let base = Point { x: gx(), y: gy(), infinity: false };
            let pub_point = scalar_mul(&base, &priv_key);
            return Ok((priv_key, pub_point));
        }
    }
}

pub fn compute_shared_secret(priv_key: &BigUint, peer: &Point) -> Option<BigUint> {
    if !on_curve(peer) { return None; }
    let res = scalar_mul(peer, priv_key);
    if res.infinity { None } else { Some(res.x) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_order() {
        let base = Point { x: gx(), y: gy(), infinity: false };
        let r = scalar_mul(&base, &n());
        assert!(r.infinity);
    }

    #[test]
    fn shared_secret_agreement() {
        let d1 = BigUint::from_bytes_be(&[0x01]);
        let d2 = BigUint::from_bytes_be(&[0x02]);
        let base = Point { x: gx(), y: gy(), infinity: false };
        let q1 = scalar_mul(&base, &d1);
        let q2 = scalar_mul(&base, &d2);
        let s1 = scalar_mul(&q2, &d1);
        let s2 = scalar_mul(&q1, &d2);
        assert_eq!(s1.x.to_bytes_be(), s2.x.to_bytes_be());
        assert_eq!(s1.y.to_bytes_be(), s2.y.to_bytes_be());
    }

    #[test]
    fn keypair_generation() {
        let (privk, pubk) = generate_keypair_p256().unwrap();
        assert!(privk.cmp(&BigUint::from_bytes_be(&[0])) == Ordering::Greater);
        assert!(privk.cmp(&n()) == Ordering::Less);
        assert!(on_curve(&pubk));
    }
}
