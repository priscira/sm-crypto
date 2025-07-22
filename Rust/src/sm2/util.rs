use std::rc::Rc;

use num_bigint::{BigUint, RandBigInt};
use num_traits::{Num, One, Zero};
use rand::rngs::OsRng;

use crate::sm2::ec::{ECCurveFp, ECPointFp};


/// 椭圆曲线参数
/// - `ec_cv`: `Rc<ECCurveFp>`，椭圆曲线
/// - `ec_g`: `ECPointFp`，椭圆曲线基点
/// - `n`: `BigUint`，椭圆曲线基点阶
pub struct EcParam {
  pub ec_cv: Rc<ECCurveFp>,
  pub ec_g: ECPointFp,
  pub n: BigUint,
}


impl EcParam {
  pub fn new() -> Self {
    let p = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    let a = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap();
    let b = BigUint::from_str_radix(
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap();

    // 椭圆曲线
    let ec_cv = ECCurveFp::new(p, a, b);

    // 基点
    let gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    let gy_hex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
    let ec_g = ec_cv.decode_point_hex(&format!("04{}{}", gx_hex, gy_hex)).unwrap();

    // 基点阶
    let n = BigUint::from_str_radix(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap();

    Self {
      ec_cv,
      ec_g,
      n,
    }
  }
}


/// 十六进制字符串左侧零填充
/// - `hex_talks`: `&str`，十六进制字符串
/// - `wid`: `usize`，总宽度
pub fn hex_left_zero_pad(hex_talks: &str, wid: usize) -> String {
  if hex_talks.len() >= wid {
    hex_talks.to_string()
  } else {
    format!("{:0>width$}", hex_talks, width = wid)
  }
}


/// 生成公私密钥对
/// - `key_pair_seed`: `Option<(String, u32)>`，密钥对种子，如果为`None`，则随机生成
/// - `ext_ec_param`: `Option<&EcParam>`，外部椭圆曲线参数，如果为`None`，则使用默认参数
pub fn generate_key_pair_hex(
  key_pair_seed: Option<(String, u32)>, ext_ec_param: Option<&EcParam>,
) -> (String, String) {
  let pre_ec_param_none;
  let ec_param: &EcParam = if let Some(ec_param) = ext_ec_param {
    ec_param
  } else {
    pre_ec_param_none = EcParam::new();
    &pre_ec_param_none
  };

  let ec_param_n_m1 = &ec_param.n - 1u8;
  let rad_big = match key_pair_seed {
    Some((dial_talk, dial_base)) => {
      let dial = BigUint::from_str_radix(&dial_talk, dial_base).unwrap();
      dial % &ec_param_n_m1 + BigUint::one()
    }
    None => {
      let mut rng = OsRng;
      rng.gen_biguint_below(&ec_param_n_m1) + BigUint::one()
    }
  };

  // 私钥
  let private_key = hex_left_zero_pad(&rad_big.to_str_radix(16), 64);

  let mut p = ec_param.ec_g.mul(&rad_big);
  let px = hex_left_zero_pad(&p.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  let py = hex_left_zero_pad(&p.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  // 公钥
  let public_key = format!("04{}{}", px, py);

  (private_key, public_key)
}


/// 压缩公钥
pub fn compress_public_key_hex(pub_k_talks: &str) -> String {
  if pub_k_talks.len() != 130 {
    panic!("Invalid public key to compress");
  }

  let pub_k_pl = (pub_k_talks.len() - 2) / 2;
  let pub_k_px = &pub_k_talks[2..2 + pub_k_pl];
  let pub_k_py = BigUint::from_str_radix(&pub_k_talks[2 + pub_k_pl..], 16).unwrap();

  let prefix = if &pub_k_py % 2u32 == BigUint::zero() { "02" } else { "03" };

  format!("{}{}", prefix, pub_k_px)
}


/// utf8字符串转十六进制字符串
/// - `utf8_talks`: `&str`，utf8字符串
pub fn utf8_to_hex(utf8_talks: &str) -> String {
  hex::encode(utf8_talks.as_bytes())
}


/// 字节数组转utf8字符串
/// - `arrs`: `&[u8]`，字节数组
pub fn arrs_to_utf8(arrs: &[u8]) -> Result<String, String> {
  let mut word_arrs = vec![0u32; (arrs.len() + 3) / 4];
  let mut j = 0;
  for i in (0..arrs.len() * 2).step_by(2) {
    word_arrs[i >> 3] |= (arrs[j] as u32) << (24 - (i % 8) * 4);
    j += 1;
  }

  let mut latin1_chs = Vec::new();
  for i in 0..arrs.len() {
    latin1_chs.push(((word_arrs[i >> 2] >> (24 - (i % 4) * 8)) & 0xff) as u8);
  }

  match String::from_utf8(latin1_chs) {
    Ok(latin1_talk) => Ok(latin1_talk),
    Err(_) => Err("Malformed UTF-8 data".to_string()),
  }
}


/// 字节数组转十六进制字符串
/// - `byt_arrs`: `&[u8]`，字节数组
pub fn arrs_to_hex(byt_arrs: &[u8]) -> String {
  hex::encode(byt_arrs)
}


/// 解读十六进制字符串为数组
/// - `hex_talks`: `&str`，十六进制字符串
/// 返回十六进制字符串对应的数组，例如：`hex_anly_arrs("4f20") == [79, 32]`
pub fn hex_anly_arrs(hex_talks: &str) -> Vec<u8> {
  if hex_talks.len() % 2 != 0 {
    hex_left_zero_pad(hex_talks, hex_talks.len() + 1)
  } else {
    hex_talks.to_string()
  }.as_bytes().chunks(2)
    .map(|hex_talki| u8::from_str_radix(std::str::from_utf8(hex_talki).unwrap(), 16).unwrap())
    .collect()
}


/// 验证公钥是否为椭圆曲线上的点
pub fn verify_public_key(pub_k: &str, ext_ec_param: Option<&EcParam>) -> bool {
  let ec_cv = match ext_ec_param {
    Some(ec_param) => &ec_param.ec_cv,
    None => &EcParam::new().ec_cv,
  };
  let mut point = ec_cv.decode_point_hex(pub_k).unwrap();
  let x = point.furnish_x().unwrap();
  let y = point.furnish_y().unwrap();

  y.sqr() == x.sqr().mul(&x).add(&x.mul(&ec_cv.a)).add(&ec_cv.b)
}


/// 验证公钥是否等价
pub fn compare_public_key_hex(pub_k1: &str, pub_k2: &str, ext_ec_param: Option<&EcParam>) -> bool {
  let ec_cv = match ext_ec_param {
    Some(ec_param) => &ec_param.ec_cv,
    None => &EcParam::new().ec_cv,
  };
  let p1 = ec_cv.decode_point_hex(pub_k1).unwrap();
  let p2 = ec_cv.decode_point_hex(pub_k2).unwrap();

  p1 == p2
}
