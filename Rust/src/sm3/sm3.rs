use crate::sm3::achieve::*;
use crate::sm4::util::*;


#[derive(Debug, PartialEq, Eq)]
pub enum Sm3Error {
  // 编码错误
  CodingError,
  // 无效的密钥
  InvalidKey,
  // 不支持的SM3模式
  UnsupportedMode,
}


#[derive(Debug, PartialEq, Eq)]
pub enum Sm3ModeKind {
  HMAC
}


pub struct Sm3;


impl Sm3 {
  pub fn new() -> Self {
    Self
  }

  /// SM3杂凑
  /// ## Parameters
  /// - plain_text: 明文，支持字符串类型
  /// - sm3_key: 密钥，若杂凑模式为HMAC则必须提供
  /// - sm3_mode_kind: 模式，目前仅支持HMAC
  /// ## Returns
  /// - SM3杂凑值，失败则返回Sm3Error
  pub fn hash<S>(
    &self, plain_text: S, sm3_key: Option<S>, sm3_mode_kind: Option<Sm3ModeKind>,
  ) -> Result<String, Sm3Error>
    where
      S: AsRef<str>,
  {
    let mut plain_text_arrs = utf8_to_arrs(plain_text.as_ref());

    if let Some(sm3_mode_kind) = sm3_mode_kind {
      if sm3_mode_kind != Sm3ModeKind::HMAC {
        return Err(Sm3Error::UnsupportedMode);
      }

      let sm3_key_arrs = hex_to_arrs(sm3_key.ok_or(Sm3Error::InvalidKey)?.as_ref())
        .ok_or(Sm3Error::CodingError)?;
      plain_text_arrs = sm3_hmac(&sm3_key_arrs, &plain_text_arrs);
    }

    Ok(arrs_to_hex(&sm3_digest(&plain_text_arrs)))
  }
}
