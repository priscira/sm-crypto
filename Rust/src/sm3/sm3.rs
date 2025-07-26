use crate::sm3::achieve::*;
use crate::sm4::util::*;


#[derive(Debug, PartialEq, Eq)]
pub enum Sm3Error {
  CodingError,
  InvalidKey,
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
