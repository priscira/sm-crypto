// cargo test --test sm3 -- --show-output

use sm_crypto::sm3::sm3::*;


#[test]
fn test_sm3_hash_without_hmac() {
  let sm3_obj = Sm3::new();
  let sm3_hash_reap = sm3_obj.hash("hello world", None, None);
  println!("sm3_hash_reap: {}", sm3_hash_reap.unwrap());
}


#[test]
fn test_sm3_hash_with_hmac() {
  let sm3_obj = Sm3::new();
  let sm3_hash_reap = sm3_obj.hash(
    "hello world", Some("abe12300985eef"), Some(Sm3ModeKind::HMAC));
  println!("sm3_hash_reap: {}", sm3_hash_reap.unwrap());

  let sm3_hash_reap = sm3_obj.hash(
    "hello world",
    Some("daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e\
          0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9"),
    Some(Sm3ModeKind::HMAC),
  );
  println!("sm3_hash_reap: {}", sm3_hash_reap.unwrap());
}
