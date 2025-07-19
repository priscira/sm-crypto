use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero};
use std::rc::Rc;

/// 计算 a 在 mod m 下的乘法逆元，即 a⁻¹ mod m
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
  let mut mn = (m.clone(), a.clone());
  let mut xy = (BigUint::zero(), BigUint::one());

  while mn.1 != BigUint::zero() {
    let q = &mn.0 / &mn.1;
    mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
    xy = (xy.1.clone(), &xy.0 - &q * &xy.1);
  }

  if mn.0 != BigUint::one() {
    return None; // 无逆元
  }

  Some(xy.0 % m)
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECFieldElementFp {
  q: BigUint,
  x: BigUint,
}


impl ECFieldElementFp {
  pub fn new(q: BigUint, x: BigUint) -> Self {
    Self {
      x: x % &q,
      q,
    }
  }

  pub fn to_biguint(&self) -> &BigUint {
    &self.x
  }

  pub fn negate(&self) -> Self {
    Self::new(self.q.clone(), (&self.q - &self.x) % &self.q)
  }

  pub fn add(&self, other: &Self) -> Self {
    Self::new(self.q.clone(), (&self.x + &other.x) % &self.q)
  }

  pub fn subtract(&self, other: &Self) -> Self {
    let q = &self.q;
    Self::new(q.clone(), (&self.x + q - &other.x) % q)
  }

  pub fn multiply(&self, other: &Self) -> Self {
    Self::new(self.q.clone(), (&self.x * &other.x) % &self.q)
  }

  pub fn divide(&self, other: &Self) -> Self {
    let inv = modinv(&other.x, &self.q).expect("No modular inverse");
    Self::new(self.q.clone(), (&self.x * inv) % &self.q)
  }

  pub fn square(&self) -> Self {
    Self::new(self.q.clone(), (&self.x * &self.x) % &self.q)
  }
}


#[derive(Debug, Clone)]
pub struct ECPointFp {
  curve: Rc<ECCurveFp>,
  x: Option<ECFieldElementFp>,
  y: Option<ECFieldElementFp>,
  z: BigUint,
  zinv: Option<BigUint>,
}


impl ECPointFp {
  pub fn new(curve: Rc<ECCurveFp>, x: Option<ECFieldElementFp>, y: Option<ECFieldElementFp>, z: Option<BigUint>) -> Self {
    Self {
      curve,
      x,
      y,
      z: z.unwrap_or_else(BigUint::one),
      zinv: None,
    }
  }

  pub fn is_infinity(&self) -> bool {
    self.x.is_none() && self.y.is_none()
  }

  pub fn negate(&self) -> Self {
    Self::new(
      self.curve.clone(),
      self.x.clone(),
      self.y.as_ref().map(|y| y.negate()),
      Some(self.z.clone()),
    )
  }

  pub fn add(&self, b: &Self) -> Self {
    if self.is_infinity() {
      return b.clone();
    }
    if b.is_infinity() {
      return self.clone();
    }

    let q = &self.curve.q;
    let x1 = self.x.as_ref().unwrap().to_biguint();
    let y1 = self.y.as_ref().unwrap().to_biguint();
    let z1 = &self.z;
    let x2 = b.x.as_ref().unwrap().to_biguint();
    let y2 = b.y.as_ref().unwrap().to_biguint();
    let z2 = &b.z;

    let w1 = (x1 * z2) % q;
    let w2 = (x2 * z1) % q;
    let w3 = (&w1 + q - &w2) % q;
    let w4 = (y1 * z2) % q;
    let w5 = (y2 * z1) % q;
    let w6 = (&w4 + q - &w5) % q;

    if w3.is_zero() {
      if w6.is_zero() {
        return self.twice();
      }
      return self.curve.infinity();
    }

    let w7 = (&w1 + &w2) % q;
    let w8 = (z1 * z2) % q;
    let w9 = (&w3 * &w3) % q;
    let w10 = (&w3 * &w9) % q;
    let w6_squared = (&w6 * &w6) % q;
    let w11 = (&w8 * &w6_squared + q - (&w7 * &w9) % q) % q;

    let x3 = (&w3 * &w11) % q;
    let y3 = (&w6 * ((&w9 * &w1 + q - &w11) % q) + q - (&w4 * &w10) % q) % q;
    let z3 = (&w10 * &w8) % q;

    Self::new(
      self.curve.clone(),
      Some(self.curve.from_biguint(x3)),
      Some(self.curve.from_biguint(y3)),
      Some(z3),
    )
  }

  pub fn twice(&self) -> Self {
    if self.is_infinity() {
      return self.clone();
    }
    if self.y.as_ref().unwrap().to_biguint().is_zero() {
      return self.curve.infinity();
    }

    let q = &self.curve.q;
    let a = self.curve.a.to_biguint();
    let x1 = self.x.as_ref().unwrap().to_biguint();
    let y1 = self.y.as_ref().unwrap().to_biguint();
    let z1 = &self.z;

    let three = 3.to_biguint().unwrap();
    let w1 = ((x1 * x1 * &three) + a * z1 * z1) % q;
    let w2 = (y1 << 1) * z1 % q;
    let w3 = y1 * y1 % q;
    let w4 = (&w3 * x1 * z1) % q;
    let w5 = (&w2 * &w2) % q;
    let eight_w4 = (&w4 << 3) % q;
    let w6 = (&w1 * &w1 + q - eight_w4) % q;

    let x3 = (&w2 * &w6) % q;

    let w4_4 = (&w4 << 2) % q;
    let term1 = (&w1 * ((&w4_4 + q - &w6) % q)) % q;
    let term2 = ((&w5 << 1) * &w3) % q;
    let y3 = (term1 + q - term2) % q;

    let z3 = (&w2 * &w5) % q;

    Self::new(
      self.curve.clone(),
      Some(self.curve.from_biguint(x3)),
      Some(self.curve.from_biguint(y3)),
      Some(z3),
    )
  }

  pub fn multiply(&self, k: &BigUint) -> Self {
    if self.is_infinity() {
      return self.clone();
    }
    if k.is_zero() {
      return self.curve.infinity();
    }

    let three = 3.to_biguint().unwrap();
    let k3 = k * &three;
    let mut q = self.clone();
    let neg = self.negate();

    for i in (1..k3.bits()).rev() {
      q = q.twice();
      let k3_bit = k3.bit(i);
      let k_bit = k.bit(i);

      if k3_bit != k_bit {
        q = q.add(if k3_bit { self } else { &neg });
      }
    }

    q
  }
}


#[derive(Debug, Clone)]
pub struct ECCurveFp {
  pub q: BigUint,
  pub a: ECFieldElementFp,
  pub b: ECFieldElementFp,
  inf: Option<ECPointFp>,
}


impl ECCurveFp {
  pub fn new(q: BigUint, a: BigUint, b: BigUint) -> Rc<Self> {
    let curve = Rc::new(Self {
      q: q.clone(),
      a: ECFieldElementFp::new(q.clone(), a),
      b: ECFieldElementFp::new(q.clone(), b),
      inf: None,
    });
    Rc::get_mut(&mut Rc::clone(&curve)).unwrap().inf = Some(ECPointFp::new(curve.clone(), None, None, None));
    curve
  }

  pub fn infinity(&self) -> ECPointFp {
    self.inf.clone().unwrap()
  }

  pub fn from_biguint(&self, x: BigUint) -> ECFieldElementFp {
    ECFieldElementFp::new(self.q.clone(), x)
  }
}


trait BitCheck {
  fn bit(&self, n: usize) -> bool;
}


impl BitCheck for BigUint {
  fn bit(&self, n: usize) -> bool {
    (self >> n) & BigUint::one() == BigUint::one()
  }
}
