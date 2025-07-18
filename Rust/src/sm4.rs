use crate::sm::CryptoKind;
use crate::sm::ModeKind;
use crate::sm::PaddingKind;
use crate::sm::SmCryptoError;

const ROUND: usize = 32;
const BLOCK: usize = 16;

const SBOX: [u8; 256] = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b,
  0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42,
  0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c,
  0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc,
  0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71,
  0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58,
  0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27,
  0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
  0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad,
  0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29,
  0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a,
  0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
  0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8,
  0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e,
  0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
  0x48,
];
const CK: [u32; 32] = [
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

fn hex_to_array(hex_talks: &str) -> Result<Vec<u8>, SmCryptoError> {
  match hex::decode(hex_talks) {
    | Ok(byt_arrs) => Ok(byt_arrs),
    | Err(_) => Err(SmCryptoError::EnDecodingError),
  }
}

fn array_to_hex(byt_arrs: &[u8]) -> String {
  hex::encode(byt_arrs)
}

fn utf8_to_array(utf8_talks: &str) -> Vec<u8> {
  utf8_talks.as_bytes().to_vec()
}

fn array_to_utf8(byt_arrs: &[u8]) -> Result<String, SmCryptoError> {
  match std::str::from_utf8(byt_arrs) {
    | Ok(s) => Ok(s.to_string()),
    | Err(_) => Err(SmCryptoError::EnDecodingError),
  }
}

/// 非线性变换，逐字节查s盒
/// ## Parameters
/// - dial: 4字节待变换数据
/// ## Returns
/// s盒变换结果
fn byte_sub(dial: u32) -> u32 {
  let dial_bytes = dial.to_be_bytes();
  u32::from_be_bytes([
    SBOX[dial_bytes[0] as usize], SBOX[dial_bytes[1] as usize], SBOX[dial_bytes[2] as usize],
    SBOX[dial_bytes[3] as usize],
  ])
}

/// 线性变换l，用于给轮函数加密/解密
fn l1(num: u32) -> u32 {
  num ^ num.rotate_left(2) ^ num.rotate_left(10) ^ num.rotate_left(18) ^ num.rotate_left(24)
}

/// 线性变换l'，扩展密钥
fn l2(num: u32) -> u32 {
  num ^ num.rotate_left(13) ^ num.rotate_left(23)
}

/// 每32bits作为一个字
fn to_words(blks: &[u8]) -> Result<[u32; 4], SmCryptoError> {
  if blks.len() != BLOCK {
    return Err(SmCryptoError::InvalidData);
  }
  Ok([
    u32::from_be_bytes([blks[0], blks[1], blks[2], blks[3]]),
    u32::from_be_bytes([blks[4], blks[5], blks[6], blks[7]]),
    u32::from_be_bytes([blks[8], blks[9], blks[10], blks[11]]),
    u32::from_be_bytes([blks[12], blks[13], blks[14], blks[15]]),
  ])
}

/// 对16字节明/密文块执行一次SMS4轮变换
/// ## Parameters
/// - blk: 16字节明文或密文块
/// - rk: list[int]
/// ## Returns
/// SMS4轮变换结果
fn sms4_crypt(blk: &[u8], rk: &[u32]) -> Result<[u8; BLOCK], SmCryptoError> {
  let words: [u32; 4] = to_words(blk)?;
  let mut words: Vec<u32> = vec![words[0], words[1], words[2], words[3]];

  for i in 0..ROUND {
    let gogga: u32 = l1(byte_sub(words[i + 1] ^ words[i + 2] ^ words[i + 3] ^ rk[i]));
    let word_to_4 = words[i] ^ gogga;
    words.push(word_to_4);
  }

  let mut reaps: [u8; BLOCK] = [0u8; BLOCK];
  for (wordi, wordj) in words[32..36].iter().rev().enumerate() {
    let word_bytes: [u8; 4] = wordj.to_be_bytes();
    let wordk: usize = wordi * 4;
    reaps[wordk..wordk + 4].copy_from_slice(&word_bytes);
  }

  Ok(reaps)
}

/// 密钥扩展，将128比特的密钥变成32个32比特的轮密钥
/// ## Parameters
/// - master_key: 128比特主密钥
/// - crypt_kind: 加密还是解密
/// ## Returns
/// 32个32比特的轮密钥
fn sms4_key_ext(mk: &[u8], crypt_kind: &CryptoKind) -> Result<Vec<u32>, SmCryptoError> {
  let words: [u32; 4] = to_words(mk)?;
  let mut words: Vec<u32> =
    vec![words[0] ^ 0xa3b1bac6, words[1] ^ 0x56aa3350, words[2] ^ 0x677d9197, words[3] ^ 0xb27022dc];
  let mut rks: Vec<u32> = Vec::with_capacity(32);

  for i in 0..ROUND {
    let rki: u32 = words[i] ^ l2(byte_sub(words[i + 1] ^ words[i + 2] ^ words[i + 3] ^ CK[i]));
    rks.push(rki);
    words.push(rki);
  }

  if let CryptoKind::Decrypt = crypt_kind {
    rks.reverse();
  }

  Ok(rks)
}

#[derive(Debug)]
pub struct Sm4 {
  pub sm4_key: Vec<u8>,
  padding: PaddingKind,
  mode: ModeKind,
  iv: Option<Vec<u8>>,
}

impl Sm4 {
  pub fn new<T: ConvertByteArr>(
    sm4_key: T, padding: PaddingKind, mode: ModeKind, iv: Option<T>,
  ) -> Result<Self, SmCryptoError> {
    let sm4_key = sm4_key.convert_to_byte_arrs(EnDecodingKind::Hex)?;
    if sm4_key.len() != BLOCK {
      return Err(SmCryptoError::InvalidKey);
    }
    // if let ModeKind::Cbc = mode {
    //   if iv.is_none() || iv.as_ref().unwrap().len() != BLOCK {
    //     return Err(SmCryptoError::InvalidData);
    //   }
    // }
    let iv = match mode {
      | ModeKind::Cbc => {
        let iv_ctn = iv.ok_or(SmCryptoError::InvalidData)?;
        let iv_arrs = iv_ctn.convert_to_byte_arrs(EnDecodingKind::Hex)?;
        if iv_arrs.len() != BLOCK {
          return Err(SmCryptoError::InvalidData);
        }
        Some(iv_arrs)
      },
      | _ => None,
    };

    Ok(Self {
      sm4_key,
      padding,
      mode,
      iv,
    })
  }

  fn sm4(&self, mut arrs: Vec<u8>, cp_kind: CryptoKind) -> Result<Vec<u8>, SmCryptoError> {
    let rk = sms4_key_ext(&self.sm4_key, &cp_kind)?;
    let mut gogga_iv = self.iv.clone().unwrap_or_default();
    let mut reap: Vec<u8> = Vec::new();

    if self.padding != PaddingKind::NonePad && cp_kind != CryptoKind::Decrypt {
      let padl = BLOCK - (arrs.len() % BLOCK);
      arrs.extend(std::iter::repeat(padl as u8).take(padl));
    }

    for arri in arrs.chunks_exact(BLOCK) {
      let mut blk = arri.to_vec();
      if self.mode == ModeKind::Cbc && cp_kind != CryptoKind::Decrypt {
        for i in 0..BLOCK {
          blk[i] ^= gogga_iv[i];
        }
      }
      let mut sms4_blk = sms4_crypt(&blk, &rk)?;
      if self.mode == ModeKind::Cbc {
        if cp_kind == CryptoKind::Decrypt {
          for i in 0..BLOCK {
            sms4_blk[i] ^= gogga_iv[i];
          }
          gogga_iv = blk;
        } else {
          gogga_iv = sms4_blk.to_vec();
        }
      }
      reap.extend(sms4_blk);
    }

    // 解密时去除 padding
    if matches!(self.padding, PaddingKind::Pkcs5 | PaddingKind::Pkcs7) && cp_kind == CryptoKind::Decrypt {
      let padl = *reap.last().ok_or(SmCryptoError::PaddingError)? as usize;
      if padl == 0 || padl > BLOCK {
        return Err(SmCryptoError::PaddingError);
      }
      reap.truncate(reap.len() - padl);
    }

    Ok(reap)
  }
}

pub trait ConvertByteArr {
  type OutputType;

  fn convert_to_byte_arrs(&self, edc_kind: EnDecodingKind) -> Result<Vec<u8>, SmCryptoError>;
  fn convert_fo_byte_arrs(
    byt_arrs: Vec<u8>, edc_kind: EnDecodingKind,
  ) -> Result<Self::OutputType, SmCryptoError>;
}

pub enum EnDecodingKind {
  Utf8,
  Hex,
}

macro_rules! impl_convert_bytearr_about_str {
  ($($t:ty),*) => {
    $(
      impl ConvertByteArr for $t {
        type OutputType = String;

        fn convert_to_byte_arrs(&self, edc_kind: EnDecodingKind) -> Result<Vec<u8>, SmCryptoError> {
          match edc_kind {
            | EnDecodingKind::Utf8 => Ok(utf8_to_array(self)),
            | EnDecodingKind::Hex => hex_to_array(self)
          }
        }

        fn convert_fo_byte_arrs(
          byt_arrs: Vec<u8>, edc_kind: EnDecodingKind,
        ) -> Result<Self::OutputType, SmCryptoError>{
          match edc_kind {
            | EnDecodingKind::Utf8 => array_to_utf8(&byt_arrs),
            | EnDecodingKind::Hex => Ok(array_to_hex(&byt_arrs))
          }
        }
      }
    )*
  };
}

macro_rules! impl_convert_bytearr_about_list {
  ($($t:ty),*) => {
    $(
      impl ConvertByteArr for $t {
        type OutputType = Vec<u8>;

        fn convert_to_byte_arrs(&self, _edc_kind: EnDecodingKind) -> Result<Vec<u8>, SmCryptoError> {
          Ok(self.to_vec())
        }

        fn convert_fo_byte_arrs(
          byt_arrs: Vec<u8>, _edc_kind: EnDecodingKind
        ) -> Result<Self::OutputType, SmCryptoError> {
          Ok(byt_arrs)
        }
      }
    )*
  };
}

// 为 Vec<u8> 和 &[u8] 实现
impl_convert_bytearr_about_list!(Vec<u8>, &[u8]);
impl_convert_bytearr_about_str!(String, &str);

pub trait CryptoTrait {
  fn encrypt<T: ConvertByteArr>(&self, plain_text: T) -> Result<T::OutputType, SmCryptoError>;
  fn decrypt<T: ConvertByteArr>(&self, cipher_text: T) -> Result<T::OutputType, SmCryptoError>;
}

impl CryptoTrait for Sm4 {
  fn encrypt<T: ConvertByteArr>(&self, plain_text: T) -> Result<T::OutputType, SmCryptoError> {
    let plain_text_arrs = plain_text.convert_to_byte_arrs(EnDecodingKind::Utf8)?;
    let reap = self.sm4(plain_text_arrs, CryptoKind::Encrypt)?;
    T::convert_fo_byte_arrs(reap, EnDecodingKind::Hex)
  }

  fn decrypt<T: ConvertByteArr>(&self, cipher_text: T) -> Result<T::OutputType, SmCryptoError> {
    let cipher_text_arrs = cipher_text.convert_to_byte_arrs(EnDecodingKind::Hex)?;
    let reap = self.sm4(cipher_text_arrs, CryptoKind::Decrypt)?;
    T::convert_fo_byte_arrs(reap, EnDecodingKind::Utf8)
  }
}
