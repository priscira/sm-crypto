#[derive(Debug, PartialEq, Eq)]
pub enum SmCryptoError {
  EnDecodingError,
  InvalidKey,
  InvalidData,
  PaddingError,
  EncryptionError,
  DecryptionError,
  Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoKind {
  Encrypt,
  Decrypt
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeKind {
  Ecb, Cbc
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingKind {
  Pkcs5, Pkcs7, NonePad
}
