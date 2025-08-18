use der::{Encode, Decode, Sequence};
use der::asn1::UintRef;
use num_bigint::BigInt;


/// SM2签名的der元素r和s
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
struct Sm2SignDerRS<'a> {
  r: UintRef<'a>,
  s: UintRef<'a>,
}


/// SM2签名 der编码
/// ## Parameters
/// - r: sm2的`r`，必须是正数
/// - s: sm2签名的`s`，必须是正数
pub fn encode_der(r: &BigInt, s: &BigInt) -> String {
  let r_byt = r.to_bytes_be().1;
  let s_byt = s.to_bytes_be().1;

  let sm2_sig_der = Sm2SignDerRS {
    r: UintRef::new(&r_byt).unwrap(),
    s: UintRef::new(&s_byt).unwrap(),
  };

  hex::encode(sm2_sig_der.to_der().unwrap())
}


/// SM2签名 der解码
/// ## Parameters
/// - sg_talks: sm2签名的DER编码字符串
/// ## Returns
/// sm2签名的`r`和`s`
pub fn decode_der(sg_talks: &str) -> (BigInt, BigInt) {
  let sg_byts = hex::decode(sg_talks).unwrap();
  let sig = Sm2SignDerRS::from_der(sg_byts.as_slice()).unwrap();
  let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, sig.r.as_bytes());
  let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, sig.s.as_bytes());
  (r, s)
}


/// 十六进制字符串左侧零填充
/// ## Parameters
/// - hex_talks: 十六进制字符串
/// - wid: 总宽度
pub fn hex_left_zero_pad(hex_talks: &str, wid: usize) -> String {
  if hex_talks.len() >= wid {
    hex_talks.to_string()
  } else {
    format!("{:0>width$}", hex_talks, width = wid)
  }
}


/// utf8字符串转十六进制字符串
/// ## Parameters
/// - utf8_talks: utf8字符串
pub fn utf8_to_hex(utf8_talks: &str) -> String {
  hex::encode(utf8_talks.as_bytes())
}


/// 字节数组转utf8字符串
/// ## Parameters
/// - arrs: 字节数组
pub fn arrs_to_utf8_latin1(arrs: &[u8]) -> Option<String> {
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
    Ok(latin1_talk) => Some(latin1_talk),
    Err(_) => None,
  }
}


/// 字节数组转十六进制字符串
/// ## Parameters
/// - byt_arrs: 字节数组
pub fn arrs_to_hex(byt_arrs: &[u8]) -> String {
  hex::encode(byt_arrs)
}


/// 解读十六进制字符串为数组
/// ## Parameters
/// - hex_talks: 十六进制字符串
/// ## Returns
/// 十六进制字符串对应的数组，例如：`hex_anly_arrs("4f20") == [79, 32]`
pub fn hex_anly_arrs(hex_talks: &str) -> Vec<u8> {
  if hex_talks.len() % 2 != 0 {
    hex_left_zero_pad(hex_talks, hex_talks.len() + 1)
  } else {
    hex_talks.to_string()
  }.as_bytes().chunks(2)
    .map(|hex_talki| u8::from_str_radix(std::str::from_utf8(hex_talki).unwrap(), 16).unwrap())
    .collect()
}
