#![allow(deprecated)]


use std::rc::Rc;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{Num, One, Zero};
use rand::rngs::OsRng;
use crate::sm2::ec::{ECCurveFp, ECPointFp};
use crate::sm2::util::*;
use crate::sm3::achieve::*;


#[derive(Debug, PartialEq, Eq)]
pub enum Sm2Error {
  // 编码错误
  CodingError,
  // 无效的公钥
  InvalidPublicKey,
  // 无效的私钥
  InvalidPrivateKey,
  // 无效的数据
  InvalidData,
  // 加密异常
  EncryptionError,
  // 解密异常
  DecryptionError,
  // 椭圆曲线错误
  EllipticCurveError,
  Other(String),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sm2ModeKind {
  C1C3C2,
  C1C2C3,
}


pub struct Sm2KeyPair {
  pub private_key: String,
  pub public_key: String,
}


struct Sm2RandomPoint {
  #[allow(dead_code)]
  pub key_pair: Sm2KeyPair,
  pub k: BigUint,
  pub x1: BigUint,
}


/// Sm2椭圆曲线参数
/// - ec_curve: 椭圆曲线
/// - ec_gpoint: 椭圆曲线基点
/// - ec_n: 椭圆曲线基点阶
pub struct Sm2 {
  pub ec_curve: Rc<ECCurveFp>,
  pub ec_gpoint: ECPointFp,
  pub ec_n: BigUint,
}


impl Sm2 {
  pub fn new() -> Self {
    let cv_q = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    let cv_a = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap();
    let cv_b = BigUint::from_str_radix(
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap();
    // 椭圆曲线
    let ec_curve = ECCurveFp::new(cv_q, cv_a, cv_b);

    // 基点
    let ec_g_x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    let ec_g_y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
    let ec_gpoint = ec_curve.decode_point_hex(&format!("04{}{}", ec_g_x, ec_g_y)).unwrap();

    // 基点阶
    let ec_n = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap();

    Self {
      ec_curve,
      ec_gpoint,
      ec_n,
    }
  }

  #[inline]
  fn crypto_message_digest_xor(messages: &mut Vec<u8>, x2: Vec<u8>, y2: Vec<u8>) {
    let z = [x2, y2].concat();
    let mut cnt: u32 = 1;
    let mut gogga_cnt = 0;
    let mut t = sm3_digest(&[z.to_vec(), cnt.to_be_bytes().to_vec()].concat());
    cnt += 1;

    for messagei in messages.iter_mut() {
      if gogga_cnt == t.len() {
        t = sm3_digest(&[z.to_vec(), cnt.to_be_bytes().to_vec()].concat());
        cnt += 1;
        gogga_cnt = 0;
      }
      *messagei ^= t[gogga_cnt] & 0xff;
      gogga_cnt += 1;
    }
  }

  /// 生成十六进制字符串格式的私钥和公钥
  /// ## Parameters
  /// - seed: 可选的种子，用于生成密钥对，格式为`(种子字符串, 进制)`
  pub fn generate_key_pair_hex(&self, seed: Option<(String, u32)>) -> Result<Sm2KeyPair, Sm2Error> {
    let ec_n_m1 = &self.ec_n - 1u8;
    let salty_seed = match seed {
      Some((dial_talk, dial_base)) => {
        let dial = BigUint::from_str_radix(&dial_talk, dial_base)
          .map_err(|_| Sm2Error::InvalidPrivateKey)?;
        dial % &ec_n_m1 + BigUint::one()
      }
      None => { OsRng.gen_biguint_below(&ec_n_m1) + BigUint::one() }
    };
    // 私钥
    let private_key = hex_left_zero_pad(&salty_seed.to_str_radix(16), 64);

    let mut ec_point_salt = self.ec_gpoint.mul(&salty_seed);
    let ec_point_salt_x = hex_left_zero_pad(
      &ec_point_salt.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64);
    let ec_point_salt_y = hex_left_zero_pad(
      &ec_point_salt.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64);
    // 公钥
    let public_key = format!("04{}{}", ec_point_salt_x, ec_point_salt_y);

    Ok(Sm2KeyPair {
      private_key,
      public_key,
    })
  }

  /// 压缩公钥
  /// ## Parameters
  /// - public_key: 130字符的十六进制格式的完整公钥
  /// ## Returns
  /// 66字符的压缩后的公钥
  pub fn compress_public_key_hex(public_key: &str) -> Result<String, Sm2Error> {
    if public_key.len() != 130 {
      return Err(Sm2Error::InvalidPublicKey);
    }

    let pub_k_pl = (public_key.len() - 2) / 2;
    let pub_k_px = &public_key[2..2 + pub_k_pl];
    let pub_k_py = BigUint::from_str_radix(&public_key[2 + pub_k_pl..], 16)
      .map_err(|_| Sm2Error::InvalidPrivateKey)?;

    let compress_prefix = if &pub_k_py % 2u32 == BigUint::zero() { "02" } else { "03" };

    Ok(format!("{}{}", compress_prefix, pub_k_px))
  }

  /// 验证公钥是否为椭圆曲线上的点
  /// ## Parameters
  /// - public_key: 公钥
  pub fn verify_public_key(&self, public_key: &str) -> Result<bool, Sm2Error> {
    let ec_curve = &self.ec_curve;
    let mut pub_k_ec_point = ec_curve.decode_point_hex(public_key).unwrap();
    let x = pub_k_ec_point.furnish_x().ok_or(Sm2Error::EllipticCurveError)?;
    let y = pub_k_ec_point.furnish_y().ok_or(Sm2Error::EllipticCurveError)?;

    Ok(y.sqr() == x.sqr().mul(&x).add(&x.mul(&ec_curve.a)).add(&ec_curve.b))
  }


  /// 验证公钥是否等价
  pub fn compare_public_key_hex(&self, pub_k1: &str, pub_k2: &str) -> Result<bool, Sm2Error> {
    let ec_curve = &self.ec_curve;
    let pub_k_point_1 = ec_curve.decode_point_hex(pub_k1).ok_or(Sm2Error::InvalidPublicKey)?;
    let pub_k_point_2 = ec_curve.decode_point_hex(pub_k2).ok_or(Sm2Error::InvalidPublicKey)?;

    Ok(pub_k_point_1 == pub_k_point_2)
  }


  /// sm3杂凑算法
  fn sm3_hash_4sm2(
    &mut self, hash_hex: &str, public_key: &str, user_id: Option<String>,
  ) -> Result<String, Sm2Error> {
    let uid = utf8_to_hex(&user_id.unwrap_or("1234567812345678".to_string()));

    let ec_gpoint = &mut self.ec_gpoint;
    let a = hex_left_zero_pad(&ec_gpoint.curve.a.furnish_item_big_uint().to_str_radix(16), 64);
    let b = hex_left_zero_pad(&ec_gpoint.curve.b.furnish_item_big_uint().to_str_radix(16), 64);
    let gpoint_x = hex_left_zero_pad(
      &ec_gpoint.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16),
      64,
    );
    let gpoint_y = hex_left_zero_pad(
      &ec_gpoint.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16),
      64,
    );

    let (pub_k_x, pub_k_y) = if public_key.len() == 128 {
      (public_key[..64].to_string(), public_key[64..].to_string())
    } else {
      let mut pub_k_ec_point = ec_gpoint.curve.decode_point_hex(public_key)
        .ok_or(Sm2Error::InvalidPublicKey)?;
      let pub_k_ec_point_x = hex_left_zero_pad(
        &pub_k_ec_point.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
          .furnish_item_big_uint().to_str_radix(16), 64);
      let pub_k_ec_point_y = hex_left_zero_pad(
        &pub_k_ec_point.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
          .furnish_item_big_uint().to_str_radix(16), 64);
      (pub_k_ec_point_x, pub_k_ec_point_y)
    };

    let mut z_after_entl = hex_anly_arrs(
      &[uid.as_str(), &a, &b, &gpoint_x, &gpoint_y, &pub_k_x, &pub_k_y].concat()
    );
    let entl = (uid.len() * 4) as u16;
    // data.unshift(entl & 0x00ff)
    z_after_entl.insert(0, (entl & 0xff) as u8);
    // data.unshift(entl >> 8 & 0x00ff)
    z_after_entl.insert(0, (entl >> 8) as u8);

    // z = sm3(entl || id || a || b || gx || gy || px || py)
    let z = sm3_digest(&z_after_entl);
    Ok(arrs_to_hex(&sm3_digest(&[z, hex_anly_arrs(hash_hex)].concat())))
  }


  /// 私钥导出公钥
  /// ## Parameters
  /// - private_key: 私钥
  pub fn furnish_public_key_from_private_key(&mut self, private_key: &str) -> Result<String, Sm2Error> {
    let ec_gpoint = &mut self.ec_gpoint;
    let mut prv_k_gpoint = ec_gpoint.mul(
      &BigUint::from_str_radix(private_key, 16).map_err(|_| Sm2Error::InvalidPrivateKey)?
    );
    let x = hex_left_zero_pad(&prv_k_gpoint.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
      .furnish_item_big_uint().to_str_radix(16), 64);
    let y = hex_left_zero_pad(&prv_k_gpoint.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
      .furnish_item_big_uint().to_str_radix(16), 64);
    Ok(format!("04{}{}", x, y))
  }


  /// 生成随机点
  fn get_point(&self) -> Result<Sm2RandomPoint, Sm2Error> {
    let key_pair = self.generate_key_pair_hex(None)?;
    let mut pub_k_ec_point = self.ec_curve.decode_point_hex(&key_pair.public_key)
      .ok_or(Sm2Error::InvalidPublicKey)?;
    let k = BigUint::from_str_radix(&key_pair.private_key, 16)
      .map_err(|_| Sm2Error::InvalidPrivateKey)?;
    let x1 = pub_k_ec_point.furnish_x().ok_or(Sm2Error::EllipticCurveError)?.furnish_item_big_uint();
    Ok(Sm2RandomPoint {
      key_pair,
      k,
      x1,
    })
  }
}


pub trait Sm2CryptoTrait {
  fn encrypt<S>(
    &self, plain_text: S, public_key: S, sm2_mode_kind: Sm2ModeKind,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>;
  fn decrypt<S>(
    &self, cipher_text: S, private_key: S, sm2_mode_kind: Sm2ModeKind,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>;
}


impl Sm2CryptoTrait for Sm2 {
  /// SM2加密
  /// ## Parameters
  /// - plain_text: 明文，支持字符串类型
  /// - public_key: 公钥，支持字符串类型
  /// - sm2_mode_kind: 加密模式
  /// ## Returns
  /// SM2加密密文结果，失败则返回Sm2Error
  fn encrypt<S>(
    &self, plain_text: S, public_key: S, sm2_mode_kind: Sm2ModeKind,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>,
  {
    let mut plain_text_arrs = hex_anly_arrs(&utf8_to_hex(plain_text.as_ref()));
    let pub_k_ec_point = self.ec_curve.decode_point_hex(public_key.as_ref())
      .ok_or(Sm2Error::InvalidPublicKey)?;

    let key_pairs = self.generate_key_pair_hex(None)?;
    let prv_k_rad = BigUint::from_str_radix(&key_pairs.private_key, 16)
      .map_err(|_| Sm2Error::InvalidPrivateKey)?;

    let mut c1 = key_pairs.public_key;
    if c1.len() > 128 {
      c1 = c1[c1.len() - 128..].to_string();
    }

    let mut rad_point = pub_k_ec_point.mul(&prv_k_rad);
    let x2 = hex_anly_arrs(&hex_left_zero_pad(
      &rad_point.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64)
    );
    let y2 = hex_anly_arrs(&hex_left_zero_pad(
      &rad_point.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64)
    );
    let c3 = arrs_to_hex(&sm3_digest(&[&x2[..], &plain_text_arrs[..], &y2[..]].concat()));

    Self::crypto_message_digest_xor(&mut plain_text_arrs, x2.clone(), y2.clone());
    let c2 = arrs_to_hex(&plain_text_arrs);

    if sm2_mode_kind == Sm2ModeKind::C1C2C3 {
      Ok(format!("{}{}{}", c1, c2, c3))
    } else {
      Ok(format!("{}{}{}", c1, c3, c2))
    }
  }

  /// SM2解密
  /// ## Parameters
  /// - cipher_text: 密文，支持字符串类型
  /// - private_key: 私钥，支持字符串类型
  /// - sm2_mode_kind: 解密模式
  /// ## Returns
  /// SM2解密明文结果，失败则返回Sm2Error
  fn decrypt<S>(
    &self, cipher_text: S, private_key: S, sm2_mode_kind: Sm2ModeKind,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>,
  {
    let cipher_text = cipher_text.as_ref();
    let private_key = BigUint::from_str_radix(private_key.as_ref(), 16).unwrap();

    let (c2, c3) = if sm2_mode_kind == Sm2ModeKind::C1C2C3 {
      (&cipher_text[128..cipher_text.len() - 64], &cipher_text[cipher_text.len() - 64..])
    } else {
      (&cipher_text[192..], &cipher_text[128..192])
    };

    let ec_cv = &self.ec_curve;
    let c1 = ec_cv.decode_point_hex(&format!("04{}", &cipher_text[0..128]))
      .ok_or(Sm2Error::InvalidPublicKey)?;
    let mut rad_point = c1.mul(&private_key);
    let x2 = hex_anly_arrs(&hex_left_zero_pad(
      &rad_point.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64)
    );
    let y2 = hex_anly_arrs(&hex_left_zero_pad(
      &rad_point.furnish_y().ok_or(Sm2Error::EllipticCurveError)?
        .furnish_item_big_uint().to_str_radix(16), 64)
    );

    let mut c2_arrs = hex_anly_arrs(c2);
    Self::crypto_message_digest_xor(&mut c2_arrs, x2.clone(), y2.clone());

    let check_c3 = arrs_to_hex(&sm3_digest(&[&x2[..], &c2_arrs[..], &y2[..]].concat()));
    if check_c3.to_lowercase() == c3.to_lowercase() {
      Ok(arrs_to_utf8_latin1(&c2_arrs).ok_or(Sm2Error::CodingError)?)
    } else {
      Err(Sm2Error::DecryptionError)
    }
  }
}


pub trait Sm2SignTrait {
  fn sign<S>(
    &mut self, plain_text: S, private_key: S, need_der: bool, need_hash: bool,
    public_key: Option<String>, user_id: Option<String>,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>;
  fn verify<S>(
    &mut self, plain_text: S, sign_text: S, public_key: S, need_der: bool, need_hash: bool,
    user_id: Option<String>,
  ) -> Result<bool, Sm2Error> where
    S: AsRef<str>;
}


impl Sm2SignTrait for Sm2 {
  /// SM2签名
  /// ## Parameters
  /// - plain_text: 明文，支持字符串类型
  /// - private_key: 私钥，支持字符串类型
  /// - need_der: 是否返回DER格式的签名
  /// - need_hash: 是否对明文进行杂凑
  /// - public_key: 额外的公钥，在需要对明文进行杂凑时使用
  /// - user_id: 额外的用户ID
  /// ## Returns
  /// SM2签名结果，程序错误则返回Sm2Error
  fn sign<S>(
    &mut self, plain_text: S, private_key: S, need_der: bool, need_hash: bool,
    public_key: Option<String>, user_id: Option<String>,
  ) -> Result<String, Sm2Error> where
    S: AsRef<str>,
  {
    let mut plain_text = utf8_to_hex(plain_text.as_ref());

    if need_hash {
      let public_key = public_key.unwrap_or(
        self.furnish_public_key_from_private_key(private_key.as_ref())?);
      plain_text = self.sm3_hash_4sm2(&plain_text, &public_key, user_id)?;
    }

    let d_a_u = BigUint::from_str_radix(private_key.as_ref(), 16)
      .map_err(|_| Sm2Error::InvalidPrivateKey)?;
    let e_u = BigUint::from_str_radix(&plain_text, 16)
      .map_err(|_| Sm2Error::InvalidData)?;
    let n_u = self.ec_n.clone();

    let d_a = BigInt::from_biguint(Sign::Plus, d_a_u);
    let e = BigInt::from_biguint(Sign::Plus, e_u);
    let n = BigInt::from_biguint(Sign::Plus, n_u);

    let (r_u, s_u) = loop {
      let sm2_random_point = self.get_point()?;
      let k = BigInt::from_biguint(Sign::Plus, sm2_random_point.k.clone());
      let x1 = BigInt::from_biguint(Sign::Plus, sm2_random_point.x1);

      let rdm = (&e + &x1) % &n;
      if rdm.is_zero() || (&rdm + &k) == n {
        continue;
      }

      // s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n)
      let s = big_int_mod_floor(&((&k - &rdm * &d_a)
        * (&d_a + BigInt::one()).modpow(&(n.clone() - 2u32), &n)), &n);

      if !s.is_zero() {
        let r_u = rdm.to_biguint().unwrap();
        let s_u = s.to_biguint().unwrap();
        break (r_u, s_u);
      }
    };

    Ok(if need_der {
      encode_der(
        &BigInt::from_biguint(Sign::Plus, r_u),
        &BigInt::from_biguint(Sign::Plus, s_u),
      )
    } else {
      format!(
        "{}{}",
        hex_left_zero_pad(&r_u.to_str_radix(16), 64),
        hex_left_zero_pad(&s_u.to_str_radix(16), 64)
      )
    })
  }

  /// SM2验签
  /// ## Parameters
  /// - plain_text: 明文，支持字符串类型
  /// - sign_text: 签名，支持字符串类型
  /// - public_key: 公钥，支持字符串类型
  /// - need_der: 是否使用DER格式的签名
  /// - need_hash: 是否对明文进行杂凑
  /// - user_id: 额外的用户ID
  /// ## Returns
  /// SM2验签结果，程序错误则返回Sm2Error
  fn verify<S>(
    &mut self, plain_text: S, sign_text: S, public_key: S, need_der: bool, need_hash: bool,
    user_id: Option<String>,
  ) -> Result<bool, Sm2Error> where
    S: AsRef<str>,
  {
    let public_key = public_key.as_ref();
    let sign_text = sign_text.as_ref();
    let mut plain_text = utf8_to_hex(plain_text.as_ref());

    if need_hash {
      plain_text = self.sm3_hash_4sm2(&plain_text, public_key, user_id)?;
    }

    let (r, s) = if need_der {
      let (r_int, s_int) = decode_der(sign_text);

      // 负数判断，不合法直接返回 false
      let r = match r_int.to_biguint() {
        Some(val) => val,
        None => return Ok(false),
      };
      let s = match s_int.to_biguint() {
        Some(val) => val,
        None => return Ok(false),
      };
      (r, s)
    } else {
      (
        BigUint::from_str_radix(&sign_text[..64], 16).map_err(|_| Sm2Error::InvalidData)?,
        BigUint::from_str_radix(&sign_text[64..], 16).map_err(|_| Sm2Error::InvalidData)?,
      )
    };

    let p_a = self.ec_curve.decode_point_hex(public_key);
    let e = BigUint::from_str_radix(&plain_text, 16).map_err(|_| Sm2Error::InvalidData)?;
    let t = (&r + &s) % &self.ec_n;

    if t.is_zero() {
      return Ok(false);
    }

    let mut x1y1 = self.ec_gpoint.mul(&s).add(&p_a.ok_or(Sm2Error::EllipticCurveError)?.mul(&t));
    let r_check = (&e + x1y1.furnish_x().ok_or(Sm2Error::EllipticCurveError)?
      .furnish_item_big_uint()) % &self.ec_n;

    Ok(r == r_check)
  }
}


/// 计算大整数的模运算（向下取整），确保结果始终为非负数。
/// - dial: 被除数
/// - n: 除数（必须为正数）
fn big_int_mod_floor(dial: &BigInt, n: &BigInt) -> BigInt {
  let reap = dial % n;
  if reap.sign() == Sign::Minus {
    (reap + n) % n
  } else {
    reap
  }
}
