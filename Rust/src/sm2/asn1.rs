// 废弃，使用der代替
#[allow(dead_code)]

use num_bigint::BigInt;
use num_traits::{One, Zero, Signed};
use num_traits::ToPrimitive;


/// 将BigInt转换成DER编码的Value部分16进制字符串
fn bigint_to_value(dial: &BigInt) -> String {
  let mut hex_talks: String = dial.to_str_radix(16);
  if !dial.is_negative() {
    // 正数处理
    if hex_talks.len() % 2 == 1 {
      // 补齐到整字节
      hex_talks = format!("0{}", hex_talks);
    } else if !hex_talks.starts_with(|hex_talki| matches!(hex_talki, '0'..='7')) {
      // 最高有效字节的最高位非0，补两个0字节
      hex_talks = format!("00{}", hex_talks);
    }
  } else {
    // 负数处理
    hex_talks = hex_talks.trim_start_matches('-').to_string();
    let mut hex_talkl = hex_talks.len();
    if hex_talkl % 2 == 1 {
      hex_talkl += 1; // 补齐到整字节
    } else if !hex_talks.starts_with(|hex_talki| matches!(hex_talki, '0'..='7')) {
      hex_talkl += 2; // 最高有效字节的最高位非0，补两个0字节
    }

    let mask = BigInt::parse_bytes("f".repeat(hex_talkl).as_bytes(), 16).unwrap();
    // 对绝对值取反，加1
    hex_talks = (mask ^ dial + BigInt::one()).to_str_radix(16).trim_start_matches('-').to_string();
  }
  hex_talks
}


/// ASN1基类
pub struct ASN1Object {
  t: String,
  l: String,
  v: String,
  tlv: Option<String>,
}


impl ASN1Object {
  #[allow(dead_code)]
  pub fn new() -> Self {
    Self {
      t: "00".to_string(),
      l: "00".to_string(),
      v: "".to_string(),
      tlv: None,
    }
  }

  /// 计算长度部分l的编码
  fn get_length(&self) -> String {
    let vl = self.v.len() / 2;
    let mut hex_vl = format!("{:x}", vl);
    // 补齐到整字节
    if hex_vl.len() % 2 == 1 {
      hex_vl = format!("0{}", hex_vl);
    }

    if vl < 128 {
      // 短格式，单字节长度，以0开头
      hex_vl
    } else {
      // 长格式，最高位为1，其余7位表示长度字节数
      // 1(1位) + 真正的长度占用字节数(7位) + 真正的长度
      let head = 128 + hex_vl.len() / 2;
      format!("{:x}{}", head, hex_vl)
    }
  }

  /// 子类重写获取value的方法
  fn get_value(&self) -> String {
    "".to_string()
  }
}


/// DER整数类型
pub struct DERInteger {
  asn1_obj: ASN1Object,
}


impl DERInteger {
  pub fn new(dial: &BigInt) -> Self {
    let v = if !dial.is_zero() {
      bigint_to_value(dial)
    } else {
      "".to_string()
    };

    Self {
      asn1_obj: ASN1Object {
        t: "02".to_string(),
        l: "00".to_string(),
        v: v.clone(),
        tlv: None,
      }
    }
  }

  pub fn get_value(&self) -> String {
    self.asn1_obj.v.clone()
  }
}


/// DER序列类型
pub struct DERSequence {
  asn1_obj: ASN1Object,
  asn1_arrs: Vec<Box<dyn EncodeHexTrait>>,
}


impl DERSequence {
  pub fn new(asn1_array: Vec<Box<dyn EncodeHexTrait>>) -> Self {
    Self {
      asn1_obj: ASN1Object {
        t: "30".to_string(),
        l: "00".to_string(),
        v: "".to_string(),
        tlv: None,
      },
      asn1_arrs: asn1_array,
    }
  }

  pub fn get_value(&mut self) -> String {
    self.asn1_obj.v = self.asn1_arrs
      .iter_mut()
      .map(|asn1_arri| asn1_arri.get_encoded_hex().to_string())
      .collect::<Vec<String>>()
      .join("");
    self.asn1_obj.v.clone()
  }
}


pub trait EncodeHexTrait {
  /// 获取der编码后的16进制字符串
  fn get_encoded_hex(&mut self) -> &str;
}


impl EncodeHexTrait for ASN1Object {
  fn get_encoded_hex(&mut self) -> &str {
    if self.tlv.is_none() {
      self.v = self.get_value();
      self.l = self.get_length();
      self.tlv = Some(format!("{}{}{}", self.t, self.l, self.v));
    }
    self.tlv.as_ref().unwrap()
  }
}


macro_rules! impl_get_encoded_hex_trait_for_der {
  ($ty:ty) => {
    impl EncodeHexTrait for $ty {
      fn get_encoded_hex(&mut self) -> &str {
        if self.asn1_obj.tlv.is_none() {
          self.asn1_obj.v = self.get_value();
          self.asn1_obj.l = self.asn1_obj.get_length();
          self.asn1_obj.tlv = Some(format!("{}{}{}", self.asn1_obj.t, self.asn1_obj.l, self.asn1_obj.v));
        }
        self.asn1_obj.tlv.as_ref().unwrap()
      }
    }
  }
}

impl_get_encoded_hex_trait_for_der!(DERInteger);
impl_get_encoded_hex_trait_for_der!(DERSequence);


/// 获取l占用字节数
fn gain_len_of_l(talks: &str, start: usize) -> usize {
  let byte = u8::from_str_radix(&talks[start + 2..start + 4], 16).unwrap();
  if (byte & 0x80) == 0 {
    // l以0开头，则表示短格式，只占一个字节
    1
  } else {
    // 长格式，取第一个字节后7位作为长度真正占用字节数，再加上本身1字节
    ((byte & 0x7f) + 1) as usize
  }
}


/// 获取l
fn gain_l(talks: &str, start: usize) -> i64 {
  let ll = gain_len_of_l(talks, start);
  let l_talks = &talks[start + 2..start + 2 + ll * 2];

  if l_talks.is_empty() {
    return -1;
  }

  let first_byte = u8::from_str_radix(&l_talks[0..2], 16).unwrap();

  let bigint = if (first_byte & 0x80) == 0 {
    BigInt::parse_bytes(l_talks.as_bytes(), 16).unwrap()
  } else {
    // 长格式去掉前面表示长度的2字符
    BigInt::parse_bytes(l_talks[2..].as_bytes(), 16).unwrap()
  };

  bigint.to_i64().unwrap_or(-1)
}


/// 获取v的起始位置
fn gain_start_pos_of_v(talks: &str, start: usize) -> usize {
  let ll = gain_len_of_l(talks, start);
  start + (ll + 1) * 2
}


/// SM2签名 der编码
/// ## Parameters
/// - r: sm2签名的`r`
/// - s: sm2签名的`s`
pub fn encode_der(r: &BigInt, s: &BigInt) -> String {
  let der_r = DERInteger::new(r);
  let der_s = DERInteger::new(s);

  let mut der_seq = DERSequence::new(vec![
    Box::new(der_r),
    Box::new(der_s),
  ]);

  der_seq.get_encoded_hex().to_string()
}


/// SM2签名 der解码
/// ## Parameters
/// - sg_talks: sm2签名的DER编码字符串
/// ## Returns
/// sm2签名的`r`和`s`
pub fn decode_der(sg_talks: &str) -> (BigInt, BigInt) {
  // 结构：input = | tSeq | lSeq | vSeq |
  // vSeq = | tR | lR | vR | tS | lS | vS |
  let v_start = gain_start_pos_of_v(sg_talks, 0);

  let v_index_r = gain_start_pos_of_v(sg_talks, v_start);
  let l_r = gain_l(sg_talks, v_start) as usize;
  let v_r = &sg_talks[v_index_r..v_index_r + l_r * 2];

  let next_start = v_index_r + v_r.len();
  let v_index_s = gain_start_pos_of_v(sg_talks, next_start);
  let l_s = gain_l(sg_talks, next_start) as usize;
  let v_s = &sg_talks[v_index_s..v_index_s + l_s * 2];

  let r = BigInt::parse_bytes(v_r.as_bytes(), 16).unwrap();
  let s = BigInt::parse_bytes(v_s.as_bytes(), 16).unwrap();

  (r, s)
}
