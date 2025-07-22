use std::rc::Rc;
use crate::sm2::asn1::{decode_der, encode_der};
use crate::sm2::ec::{ECCurveFp, ECFieldElementFp, ECPointFp};
use crate::sm2::sm3::{DigestTrait, Sm3};
use crate::sm2::util::*;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{Num, One, Zero};


pub struct Sm2;


fn next_t(sm3_obj: &Sm3, z: &[u8], ct: &mut u8, t: &mut Vec<u8>, offset: &mut usize) {
  *t = sm3_obj.digest(&[z.to_vec(), ct.to_be_bytes().to_vec()].concat());
  *ct += 1;
  *offset = 0;
}


pub fn sm2_encrypt(plain_text: String, public_key: String, cipher_mode: u8, ec_param: Option<&mut EcParam>) -> Option<String> {
  let mut plain_text_arrs = hex_anly_arrs(&utf8_to_hex(&plain_text));
  // let ec_param = EcParam::new();
  let ec_param = ec_param.unwrap();
  let ec_cv = &ec_param.ec_cv;
  let pub_k_ecp = ec_cv.decode_point_hex(&public_key)?;

  let key_pairs = generate_key_pair_hex(None, None);
  let k = BigUint::from_str_radix(&key_pairs.0, 16).unwrap();

  let mut c1 = key_pairs.1;
  if c1.len() > 128 {
    c1 = c1[c1.len() - 128..].to_string();
  }

  let sm3_obj = Sm3::new();

  let mut p = pub_k_ecp.mul(&k);
  let x2 = hex_anly_arrs(&hex_left_zero_pad(&p.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64));
  let y2 = hex_anly_arrs(&hex_left_zero_pad(&p.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64));
  let c3 = arrs_to_hex(&*sm3_obj.digest(&[&x2[..], &plain_text_arrs[..], &y2[..]].concat()));

  let mut ct: u8 = 1;
  let mut offset = 0;
  let mut t = vec![];
  let z = [x2.clone(), y2.clone()].concat();

  next_t(&sm3_obj, &z, &mut ct, &mut t, &mut offset);

  for byte in plain_text_arrs.iter_mut() {
    if offset == t.len() {
      next_t(&sm3_obj, &z, &mut ct, &mut t, &mut offset);
    }
    *byte ^= t[offset] & 0xff;
    offset += 1;
  }

  let c2 = arrs_to_hex(&plain_text_arrs);

  if cipher_mode == 0 {
    Some(format!("{}{}{}", c1, c2, c3))
  } else {
    Some(format!("{}{}{}", c1, c3, c2))
  }
}


pub fn sm2_decrypt(cipher_text: String, private_key: String, cipher_mode: u8, ec_param: Option<&mut EcParam>) -> Option<String> {
  let private_key = BigUint::from_str_radix(&private_key, 16).unwrap();

  let (c2, c3) = if cipher_mode == 0 {
    (&cipher_text[128..cipher_text.len() - 64], &cipher_text[cipher_text.len() - 64..])
  } else {
    (&cipher_text[192..], &cipher_text[128..192])
  };

  let msg = hex_anly_arrs(c2);
  let ec_param = ec_param.unwrap();
  let ec_cv = &ec_param.ec_cv;
  // let ec_param = EcParam::new();
  // let ec_cv = ec_param.ec_cv;
  let c1 = ec_cv.decode_point_hex(&format!("04{}", &cipher_text[0..128]))?;
  let mut p = c1.mul(&private_key);
  let x2 = hex_anly_arrs(&hex_left_zero_pad(&p.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64));
  let y2 = hex_anly_arrs(&hex_left_zero_pad(&p.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64));

  let mut ct = 1;
  let mut offset = 0;
  let mut t = vec![];
  let mut msg_mut = msg.clone();
  let z = [x2.clone(), y2.clone()].concat();

  let sm3_obj = Sm3::new();
  next_t(&sm3_obj, &z, &mut ct, &mut t, &mut offset);

  for byte in msg_mut.iter_mut() {
    if offset == t.len() {
      next_t(&sm3_obj, &z, &mut ct, &mut t, &mut offset);
    }
    *byte ^= t[offset];
    offset += 1;
  }

  let check_c3 = arrs_to_hex(&*sm3_obj.digest(&[&x2[..], &msg_mut[..], &y2[..]].concat()));

  if check_c3.to_lowercase() == c3.to_lowercase() {
    Some(arrs_to_utf8(&msg_mut).unwrap())
  } else {
    None
  }
}


pub fn sm2_sign(
  msg: String,
  private_key: String,
  der: bool,
  hash: bool,
  public_key_opt: Option<String>,
  user_id: Option<String>,
) -> String {
  let mut hash_hex = utf8_to_hex(&msg);

  let mut ec_param = EcParam::new();
  if hash {
    let public_key = public_key_opt.unwrap_or(get_public_key_from_private_key(&private_key, Some(&mut ec_param)));
    hash_hex = get_hash(&hash_hex, &public_key, user_id, Some(&mut ec_param));
  }

  let d_a_u = BigUint::from_str_radix(&private_key, 16).unwrap();
  let e_u = BigUint::from_str_radix(&hash_hex, 16).unwrap();
  let n_u = ec_param.n.clone();

  let d_a = BigInt::from_biguint(Sign::Plus, d_a_u.clone());
  let e = BigInt::from_biguint(Sign::Plus, e_u.clone());
  let n = BigInt::from_biguint(Sign::Plus, n_u.clone());

  let (r_u, s_u) = loop {
    let (_, _, k_u, x1_u) = get_point(&ec_param.ec_cv);
    let k = BigInt::from_biguint(Sign::Plus, k_u.clone());
    let x1 = BigInt::from_biguint(Sign::Plus, x1_u);

    let r = (&e + &x1) % &n;
    if r.is_zero() || (&r + &k) == n {
      continue;
    }

    // s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n)
    let s =mod_floor(&((&k - &r * &d_a)
      * (&d_a + BigInt::one()).modpow(&(n.clone() - 2u32), &n)), &n);

    if !s.is_zero() {
      let r_u = r.to_biguint().unwrap();
      let s_u = s.to_biguint().unwrap();
      break (r_u, s_u);
    }
  };

  if der {
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
  }
}

fn mod_floor(a: &BigInt, n: &BigInt) -> BigInt {
  let r = a % n;
  if r.sign() == Sign::Minus {
    (r + n) % n
  } else {
    r
  }
}


/// 验签
pub fn sm2_verify(
  msg: String,
  sign_hex: String,
  public_key: String,
  der: bool,
  hash: bool,
  user_id: Option<String>,
) -> bool {
  let mut hash_hex = utf8_to_hex(&msg);

  let mut ec_param = EcParam::new();
  if hash {
    hash_hex = get_hash(&hash_hex, &public_key, user_id, Some(&mut ec_param));
  }

  let ec_cv = &ec_param.ec_cv;
  let ec_n = &ec_param.n;
  let ec_g = &ec_param.ec_g;
  let (r, s) = if der {
    let (r_int, s_int) = decode_der(&sign_hex);

    // 负数判断，不合法直接返回 false
    let r = match r_int.to_biguint() {
      Some(val) => val,
      None => return false,
    };
    let s = match s_int.to_biguint() {
      Some(val) => val,
      None => return false,
    };
    (r, s)
  } else {
    (
      BigUint::from_str_radix(&sign_hex[..64], 16).unwrap(),
      BigUint::from_str_radix(&sign_hex[64..], 16).unwrap(),
    )
  };

  let p_a = ec_cv.decode_point_hex(&public_key);
  let e = BigUint::from_str_radix(&hash_hex, 16).unwrap();
  let t = (&r + &s) % ec_n;

  if t.is_zero() {
    return false;
  }

  let mut x1y1 = ec_g.mul(&s).add(&p_a.unwrap().mul(&t));
  let r_check = (&e + x1y1.furnish_x().unwrap().furnish_x_big_uint()) % ec_n;

  r == r_check
}


/// Z = SM3(ENTL || ID || a || b || gx || gy || px || py)
pub fn get_hash(hash_hex: &str, public_key: &str, user_id: Option<String>, ec_param: Option<&mut EcParam>) -> String {
  let user_id = user_id.unwrap_or("1234567812345678".to_string());
  let uid = utf8_to_hex(&user_id);
  let ec_param = ec_param.unwrap();
  let ec_g = &mut ec_param.ec_g;
  let a = hex_left_zero_pad(&ec_g.cv.a.furnish_x_big_uint().to_str_radix(16), 64);
  let b = hex_left_zero_pad(&ec_g.cv.b.furnish_x_big_uint().to_str_radix(16), 64);
  let gx = hex_left_zero_pad(&ec_g.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  let gy = hex_left_zero_pad(&ec_g.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  let (px, py) = if public_key.len() == 128 {
    (public_key[..64].to_string(), public_key[64..].to_string())
  } else {
    let mut point = ec_g.cv.decode_point_hex(public_key).unwrap();
    let temp_x = hex_left_zero_pad(&point.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
    let temp_y = hex_left_zero_pad(&point.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
    (temp_x, temp_y)
  };

  let mut data = hex_anly_arrs(&[uid.as_str(), &a, &b, &gx, &gy, &px, &py].concat());
  let entl = (uid.len() / 2 * 8) as u16;
  data.insert(0, (entl & 0xff) as u8);
  data.insert(0, (entl >> 8) as u8);

  let sm3_obj = Sm3::new();
  let z = sm3_obj.digest(&data);
  arrs_to_hex(&sm3_obj.digest(&[z, hex_anly_arrs(hash_hex)].concat()))
}


/// 私钥导出公钥
pub fn get_public_key_from_private_key(private_key: &str, ec_param: Option<&mut EcParam>) -> String {
  let ec_param = ec_param.unwrap(); // 现在是 &mut EcParam
  let ec_g = &mut ec_param.ec_g;
  let mut p_a = ec_g.mul(&BigUint::from_str_radix(private_key, 16).unwrap());
  let x = hex_left_zero_pad(&p_a.furnish_x().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  let y = hex_left_zero_pad(&p_a.furnish_y().unwrap().furnish_x_big_uint().to_str_radix(16), 64);
  format!("04{}{}", x, y)
}


/// 生成随机点
pub fn get_point(ec_cv: &Rc<ECCurveFp>) -> (String, String, BigUint, BigUint) {
  let kyprs = generate_key_pair_hex(None, None);
  let p_a = ec_cv.decode_point_hex(&kyprs.1);
  let kypr_k = BigUint::from_str_radix(&kyprs.0, 16).unwrap();
  let kypr_x1 = p_a.unwrap().furnish_x().unwrap().furnish_x_big_uint();
  (kyprs.0, kyprs.1, kypr_k, kypr_x1)
}
