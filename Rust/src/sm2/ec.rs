use std::rc::Rc;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero};


/// 计算`dial`在`mod inv_mod`下的乘法逆元，即$dial ^ {-1} \mod inv\_mod$。
pub fn calculate_inverse_mod(dial: &BigUint, inv_mod: &BigUint) -> Option<BigUint> {
  let mut mn = (inv_mod.clone(), dial.clone());
  let mut xy = (BigUint::zero(), BigUint::one());

  while mn.1 != BigUint::zero() {
    let q = &mn.0 / &mn.1;
    mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
    xy = (xy.1.clone(), &xy.0 - &q * &xy.1);
  }

  if mn.0 != BigUint::one() { None } else { Some(xy.0 % inv_mod) }
}


/// 椭圆曲线域元素
/// - `q`: `BigUint`，椭圆曲线所基于的素数字段（有限域）的大素数模数
/// - `x`: `BigUint`，有限域中的一个元素（模`q`后的整数）
#[derive(Clone, Debug)]
pub struct ECFieldElementFp {
  pub q: BigUint,
  pub x: BigUint,
}


impl ECFieldElementFp {
  /// 构造一个椭圆曲线域元素，不会对`q`是否是素数做检查
  /// - `q`: `BigUint`，椭圆曲线所基于的素数字段（有限域）的大素数模数
  /// - `x`: `BigUint`，有限域中的一个元素（模`q`后的整数）
  pub fn new(q: BigUint, x: BigUint) -> Self {
    Self {
      x: x % &q,
      q,
    }
  }

  /// 返回有限域元素的整数值（对阶取模）
  pub fn furnish_x_big_uint(&self) -> BigUint {
    self.x.clone()
  }

  /// 取反
  pub fn negate(&self) -> Self {
    // this.x.negate().mod(this.q)
    // js的BigInteger.mod()始终返回正数余数，此处在new()的时候已经约定了$x \in [0, q - 1]$。
    Self::new(self.q.clone(), (&self.q - &self.x) % &self.q)
  }

  /// 加法
  pub fn add(&self, other: &Self) -> Self {
    assert_eq!(self.q, other.q);
    Self::new(self.q.clone(), (&self.x + &other.x) % &self.q)
  }

  /// 减法
  pub fn sub(&self, other: &Self) -> Self {
    assert_eq!(self.q, other.q);
    Self::new(self.q.clone(), (&self.x + &self.q - &other.x) % &self.q)
  }

  /// 乘法
  pub fn mul(&self, other: &Self) -> Self {
    assert_eq!(self.q, other.q);
    Self::new(self.q.clone(), (&self.x * &other.x) % &self.q)
  }

  /// 除法
  pub fn dvd(&self, other: &Self) -> Self {
    let inv = calculate_inverse_mod(&other.x, &self.q).expect("No modular inverse");
    Self::new(self.q.clone(), (&self.x * inv) % &self.q)
  }

  /// 平方
  pub fn sqr(&self) -> Self {
    Self::new(self.q.clone(), (&self.x * &self.x) % &self.q)
  }

  /// 平方根
  pub fn modpow(&self, exp: &BigUint) -> Self {
    Self::new(self.q.clone(), self.x.modpow(exp, &self.q))
  }
}


impl PartialEq for ECFieldElementFp {
  /// 判断两个椭圆曲线域元素是否相等
  fn eq(&self, other: &Self) -> bool {
    // this.q.equals(other.q) && this.x.equals(other.x)
    self.q == other.q && self.x == other.x
  }
}


impl Eq for ECFieldElementFp {}


/// 椭圆曲线点
#[derive(Clone, Debug)]
pub struct ECPointFp {
  pub cv: Rc<ECCurveFp>,
  x: Option<ECFieldElementFp>,
  y: Option<ECFieldElementFp>,
  z: BigUint,
  zinv: Option<BigUint>,
}


impl ECPointFp {
  pub fn new(
    cv: Rc<ECCurveFp>, x: Option<ECFieldElementFp>, y: Option<ECFieldElementFp>, z: Option<BigUint>,
  ) -> Self {
    Self {
      cv,
      x,
      y,
      z: z.unwrap_or_else(BigUint::one),
      zinv: None,
    }
  }

  pub fn furnish_x(&mut self) -> Option<ECFieldElementFp> {
    let x = self.x.as_ref()?.furnish_x_big_uint();
    // z == 1，当前点是仿射形式，直接返回
    if self.z == BigUint::one() {
      return Some(self.x.clone()?);
    }

    if self.zinv.is_none() {
      self.zinv = calculate_inverse_mod(&self.z, &self.cv.q)
    }

    let zinv = self.zinv.as_ref()?;
    Some(self.cv.furnish_ec_field_from_biguint((x * zinv) % &self.cv.q))
  }

  pub fn furnish_y(&mut self) -> Option<ECFieldElementFp> {
    let y = self.y.as_ref()?.furnish_x_big_uint();
    // z == 1，当前点是仿射形式，直接返回
    if self.z == BigUint::one() {
      return Some(self.y.clone()?);
    }

    if self.zinv.is_none() {
      self.zinv = calculate_inverse_mod(&self.z, &self.cv.q)
    }

    let zinv = self.zinv.as_ref()?;
    Some(self.cv.furnish_ec_field_from_biguint((y * zinv) % &self.cv.q))
  }

  /// 是否是无穷远点
  pub fn judge_infty(&self) -> bool {
    if self.x.is_none() && self.y.is_none() {
      return true;
    }
    // z == 0且y != 0，兼容投影坐标
    if self.z.is_zero() {
      if let Some(y) = &self.y {
        return !y.furnish_x_big_uint().is_zero();
      }
    }
    false
  }

  /// 取反，即`x`轴对称点
  pub fn negate(&self) -> Self {
    Self::new(self.cv.clone(), self.x.clone(), self.y.as_ref().map(|y| y.negate()), Some(self.z.clone()))
  }

  /// 自增
  pub fn twice(&self) -> Self {
    if self.judge_infty() {
      return self.clone();
    }
    if self.y.as_ref().unwrap().furnish_x_big_uint().is_zero() {
      return self.cv.furnish_infty();
    }

    let x1 = self.x.as_ref().unwrap().furnish_x_big_uint();
    let y1 = self.y.as_ref().unwrap().furnish_x_big_uint();
    let z1 = &self.z;
    let q = &self.cv.q;
    let a = self.cv.a.furnish_x_big_uint();

    // w1 = x1.square().multiply(THREE).add(a.multiply(z1.square())).mod(q)
    let w1 = ((&x1 * &x1 * 3.to_biguint().unwrap()) + a * z1 * z1) % q;
    // w2 = y1.shiftLeft(1).multiply(z1).mod(q)
    let w2 = (&y1 << 1) * z1 % q;
    // w3 = y1.square().mod(q)
    let w3 = &y1 * &y1 % q;
    // w4 = w3.multiply(x1).multiply(z1).mod(q)
    let w4 = (&w3 * x1 * z1) % q;
    // w5 = w2.square().mod(q)
    let w5 = (&w2 * &w2) % q;
    // w6 = w1.square().subtract(w4.shiftLeft(3)).mod(q)
    let w6 = (&w1 * &w1 + q - (&w4 << 3) % q) % q;

    // x3 = w2.multiply(w6).mod(q)
    let x3 = (&w2 * &w6) % q;
    // y3 = w1.multiply(w4.shiftLeft(2).subtract(w6)).subtract(w5.shiftLeft(1).multiply(w3)).mod(q)
    let y3 = (&w1 * ((&w4 << 2) + q - &w6) + q - ((&w5 << 1) * &w3) % q) % q;
    // z3 = w2.multiply(w5).mod(q)
    let z3 = (&w2 * &w5) % q;

    Self::new(
      self.cv.clone(),
      Some(self.cv.furnish_ec_field_from_biguint(x3)),
      Some(self.cv.furnish_ec_field_from_biguint(y3)),
      Some(z3),
    )
  }

  /// 相加
  pub fn add(&self, other: &Self) -> Self {
    if self.judge_infty() {
      return other.clone();
    }
    if other.judge_infty() {
      return self.clone();
    }

    let x1 = self.x.as_ref().unwrap().furnish_x_big_uint();
    let y1 = self.y.as_ref().unwrap().furnish_x_big_uint();
    let z1 = &self.z;
    let x2 = other.x.as_ref().unwrap().furnish_x_big_uint();
    let y2 = other.y.as_ref().unwrap().furnish_x_big_uint();
    let z2 = &other.z;
    let q = &self.cv.q;

    // w1 = x1.multiply(z2).mod(q)
    let w1 = (x1 * z2) % q;
    // w2 = x2.multiply(z1).mod(q)
    let w2 = (x2 * z1) % q;
    // w3 = w1.subtract(w2)
    let w3 = (&w1 + q - &w2) % q;
    // w4 = y1.multiply(z2).mod(q)
    let w4 = (y1 * z2) % q;
    // w5 = y2.multiply(z1).mod(q)
    let w5 = (y2 * z1) % q;
    // w6 = w4.subtract(w5)
    let w6 = (&w4 + q - &w5) % q;

    if w3.is_zero() {
      if w6.is_zero() {
        return self.twice();
      }
      return self.cv.furnish_infty();
    }

    // w7 = w1.add(w2)
    let w7 = (&w1 + &w2) % q;
    // w8 = z1.multiply(z2).mod(q)
    let w8 = (z1 * z2) % q;
    // w9 = w3.square().mod(q)
    let w9 = (&w3 * &w3) % q;
    // w10 = w3.multiply(w9).mod(q)
    let w10 = (&w3 * &w9) % q;
    // w11 = w8.multiply(w6.square()).subtract(w7.multiply(w9)).mod(q)
    let w11 = (&w8 * &w6 * &w6 + q - (&w7 * &w9) % q) % q;

    // x3 = w3.multiply(w11).mod(q)
    let x3 = (&w3 * &w11) % q;
    // y3 = w6.multiply(w9.multiply(w1).subtract(w11)).subtract(w4.multiply(w10)).mod(q)
    let y3 = (&w6 * ((&w9 * &w1 + q - &w11) % q) + q - (&w4 * &w10) % q) % q;
    // z3 = w10.multiply(w8).mod(q)
    let z3 = (&w10 * &w8) % q;

    Self::new(
      self.cv.clone(),
      Some(self.cv.furnish_ec_field_from_biguint(x3)),
      Some(self.cv.furnish_ec_field_from_biguint(y3)),
      Some(z3),
    )
  }

  /// 倍点
  pub fn mul(&self, other: &BigUint) -> Self {
    if self.judge_infty() {
      return self.clone();
    }
    if other.is_zero() {
      return self.cv.furnish_infty();
    }

    let k3 = other * 3.to_biguint().unwrap();
    let mut ec_point_q = self.clone();
    let ec_point_neg = self.negate();

    // let i = k3.bitLength() - 2
    for i in (1..(k3.bits() - 1)).rev() {
      ec_point_q = ec_point_q.twice();
      let k3_bit = k3.bit(i);
      let k_bit = other.bit(i);

      if k3_bit != k_bit {
        ec_point_q = ec_point_q.add(if k3_bit { self } else { &ec_point_neg });
      }
    }

    ec_point_q
  }
}


impl PartialEq for ECPointFp {
  fn eq(&self, other: &Self) -> bool {
    if Rc::ptr_eq(&self.cv, &other.cv) {
      return self.x == other.x && self.y == other.y;
    }
    if self.judge_infty() {
      return other.judge_infty();
    }
    if other.judge_infty() {
      return self.judge_infty();
    }

    // u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z))
    // v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z))
    let q = &self.cv.q;
    let x1 = self.x.as_ref().unwrap().furnish_x_big_uint();
    let y1 = self.y.as_ref().unwrap().furnish_x_big_uint();
    let z1 = &self.z;
    let x2 = other.x.as_ref().unwrap().furnish_x_big_uint();
    let y2 = other.y.as_ref().unwrap().furnish_x_big_uint();
    let z2 = &other.z;

    if (y2 * z1) % q != (y1 * z2) % q {
      return false;
    }
    (x2 * z1) % q == (x1 * z2) % q
  }
}


impl Eq for ECPointFp {}


/// 椭圆曲线$y ^ 2 = x ^ 3 + a * x + b$
/// - `q`: `BigUint`，椭圆曲线所基于的素数字段（有限域）的大素数模数
/// - `a`: `BigUint`，椭圆曲线方程的`a`项
/// - `b`: `BigUint`，椭圆曲线方程的`b`项
#[derive(Debug)]
pub struct ECCurveFp {
  pub q: BigUint,
  pub a: ECFieldElementFp,
  pub b: ECFieldElementFp,
}


impl ECCurveFp {
  /// 构造一个椭圆曲线
  /// - `q`: `BigUint`，椭圆曲线所基于的素数字段（有限域）的大素数模数
  /// - `a`: `BigUint`，椭圆曲线方程的`a`项
  /// - `b`: `BigUint`，椭圆曲线方程的`b`项
  pub fn new(q: BigUint, a: BigUint, b: BigUint) -> Rc<Self> {
    Rc::new(Self {
      q: q.clone(),
      a: ECFieldElementFp::new(q.clone(), a),
      b: ECFieldElementFp::new(q, b),
    })
  }

  /// 生成椭圆曲线的无穷远点
  pub fn furnish_infty(self: &Rc<Self>) -> ECPointFp {
    ECPointFp::new(self.clone(), None, None, None)
  }

  /// 生成椭圆曲线域元素
  /// - `x`: `BigUint`，有限域中的一个元素（模`q`后的整数）
  pub fn furnish_ec_field_from_biguint(&self, x: BigUint) -> ECFieldElementFp {
    ECFieldElementFp::new(self.q.clone(), x)
  }

  /// 解析十六进制串为椭圆曲线点
  /// - `hex_talks`: `str`，十六进制串，且长度为奇数
  pub fn decode_point_hex(self: &Rc<Self>, hex_talks: &str) -> Option<ECPointFp> {
    let hex_byte1 = u8::from_str_radix(&hex_talks[..2], 16).ok()?;

    match hex_byte1 {
      | 0 => Some(self.furnish_infty()),
      | 2 | 3 => {
        let x = BigUint::parse_bytes(&hex_talks[2..].as_bytes(), 16)?;
        let ec_field_ele_x = self.furnish_ec_field_from_biguint(x.clone());
        // 对$p \equiv 3 \mod 4$，即存在正整数$u$，使得$p = 4u + 3$，计算
        // $y = (\sqrt{x ^ 3 + ax + b} \mod p) ^ {u + 1} \mod p$。
        let y = ec_field_ele_x
          .mul(&ec_field_ele_x.sqr())
          .add(&ec_field_ele_x.mul(&self.a))
          .add(&self.b)
          .furnish_x_big_uint()
          // .modPow(this.q.divide(new BigInteger('4')).add(BigInteger.ONE), this.q)
          .modpow(&((&self.q >> 2u32) + BigUint::one()), &self.q);
        let mut ec_field_ele_y = self.furnish_ec_field_from_biguint(y);

        // y.toBigInteger().mod(TWO)
        let y_big_uint_mod2 = ec_field_ele_y.furnish_x_big_uint() & BigUint::one();
        // 二进制最后1位不等于第1个字节 - 2则取反
        if y_big_uint_mod2 != BigUint::from(hex_byte1 - 2) {
          ec_field_ele_y = ec_field_ele_y.negate();
        }

        Some(ECPointFp::new(Rc::clone(self), Some(ec_field_ele_x), Some(ec_field_ele_y), None))
      }
      | 4 | 6 | 7 => {
        let hex_talkl = (hex_talks.len() - 2) / 2;
        let x_hex = &hex_talks[2..2 + hex_talkl];
        let y_hex = &hex_talks[2 + hex_talkl..];

        let x = BigUint::parse_bytes(x_hex.as_bytes(), 16)?;
        let y = BigUint::parse_bytes(y_hex.as_bytes(), 16)?;
        Some(ECPointFp::new(
          Rc::clone(self),
          Some(self.furnish_ec_field_from_biguint(x)),
          Some(self.furnish_ec_field_from_biguint(y)),
          None,
        ))
      }
      | _ => None,
    }
  }
}


impl PartialEq for ECCurveFp {
  fn eq(&self, other: &Self) -> bool {
    self.q == other.q && self.a == other.a && self.b == other.b
  }
}


impl Eq for ECCurveFp {}
