pub use crate::sm2::util::arrs_to_hex;

pub fn hex_to_arrs(hex_talks: &str) -> Option<Vec<u8>> {
  match hex::decode(hex_talks) {
    | Ok(byt_arrs) => Some(byt_arrs),
    | Err(_) => None,
  }
}


pub fn utf8_to_arrs(utf8_talks: &str) -> Vec<u8> {
  utf8_talks.as_bytes().to_vec()
}


pub fn arrs_to_utf8(byt_arrs: &[u8]) -> Option<String> {
  match std::str::from_utf8(byt_arrs) {
    | Ok(s) => Some(s.to_string()),
    | Err(_) => None,
  }
}
