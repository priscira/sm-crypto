// cargo test --test sm2 -- --show-output

use sm_crypto::sm2::sm2::{sm2_decrypt, sm2_encrypt, sm2_sign, sm2_verify};
use sm_crypto::sm2::util::*;


#[test]
fn test_generate_key_pair_hex() {
  let kyprs = generate_key_pair_hex(None, None);
  println!("private_key = {:?}, len = {:?}", kyprs.0, kyprs.0.len());
  println!("public_key = {:?}, len = {:?}", kyprs.1, kyprs.1.len());

  let comp_pub_k = compress_public_key_hex(&kyprs.1);
  println!("compressed_public_key = {:?}, len = {:?}", comp_pub_k, comp_pub_k.len());

  println!("===================================");

  let kyprs = generate_key_pair_hex(Some(("123123123123123".to_string(), 16)), None);
  println!("private_key = {:?}, len = {:?}", kyprs.0, kyprs.0.len());
  println!("public_key = {:?}, len = {:?}", kyprs.1, kyprs.1.len());

  let comp_pub_k = compress_public_key_hex(&kyprs.1);
  println!("compressed_public_key = {:?}, len = {:?}", comp_pub_k, comp_pub_k.len());

  println!("===================================");

  let ec_param = EcParam::new();
  let (private_key, public_key) = generate_key_pair_hex(None, Some(&ec_param));
  println!("private_key = {:?}, len = {:?}", private_key, private_key.len());
  println!("public_key = {:?}, len = {:?}", public_key, public_key.len());

  let ver_pub_k = verify_public_key(&public_key, Some(&ec_param));
  println!("verify_public_key = {:?}", ver_pub_k);

  let comp_pub_k = compress_public_key_hex(&public_key);
  println!("compressed_public_key = {:?}, len = {:?}", comp_pub_k, comp_pub_k.len());

  let ver_pub_k = verify_public_key(&comp_pub_k, Some(&ec_param));
  println!("verify_public_key = {:?}", ver_pub_k);
}


#[test]
fn test_sm2_c1c2c3_crypto() {
  let mut ec_param = EcParam::new();
  let cn_talks = "臂上妆犹在，襟间泪尚盈。".to_string();
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.".to_string();
  let (private_key, public_key) = generate_key_pair_hex(None, Some(&ec_param));
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let cn_enc_talks = sm2_encrypt(cn_talks, public_key.clone(), 0, Some(&mut ec_param));
  println!("c1c2c3_cn_enc = {:?}", cn_enc_talks);

  let cn_dec_talks = sm2_decrypt(cn_enc_talks.unwrap(), private_key.clone(), 0, Some(&mut ec_param));
  println!("c1c2c3_cn_dec = {:?}", cn_dec_talks);

  let en_enc_talks = sm2_encrypt(en_talks, public_key.clone(), 0, Some(&mut ec_param));
  println!("c1c2c3_en_enc = {:?}", en_enc_talks);

  let en_dec_talks = sm2_decrypt(en_enc_talks.unwrap(), private_key.clone(), 0, Some(&mut ec_param));
  println!("c1c2c3_en_dec = {:?}", en_dec_talks);
}


#[test]
fn test_sm2_c1c3c2_crypto() {
  let mut ec_param = EcParam::new();
  let cn_talks = "臂上妆犹在，襟间泪尚盈。".to_string();
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.".to_string();
  let (private_key, public_key) = generate_key_pair_hex(None, Some(&ec_param));
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let cn_enc_talks = sm2_encrypt(cn_talks, public_key.clone(), 1, Some(&mut ec_param));
  println!("c1c2c3_cn_enc = {:?}", cn_enc_talks);

  let cn_dec_talks = sm2_decrypt(cn_enc_talks.unwrap(), private_key.clone(), 1, Some(&mut ec_param));
  println!("c1c2c3_cn_dec = {:?}", cn_dec_talks);

  let en_enc_talks = sm2_encrypt(en_talks, public_key.clone(), 1, Some(&mut ec_param));
  println!("c1c2c3_en_enc = {:?}", en_enc_talks);

  let en_dec_talks = sm2_decrypt(en_enc_talks.unwrap(), private_key.clone(), 1, Some(&mut ec_param));
  println!("c1c2c3_en_dec = {:?}", en_dec_talks);
}

#[test]
fn test_sm2_sign_verify() {
  let mut ec_param = EcParam::new();
  let (private_key, public_key) = generate_key_pair_hex(None, Some(&ec_param));
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let sign = sm2_sign("test message".to_string(), private_key.clone(), false, false, Some(public_key.clone()), None);
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), false, false, None);
  println!("verify = {:?}", verify);


  let sign = sm2_sign("test message".to_string(), private_key.clone(), true, false, Some(public_key.clone()), None);
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), true, false, None);
  println!("verify = {:?}", verify);

  let sign = sm2_sign("test message".to_string(), private_key.clone(), false, true, Some(public_key.clone()), None);
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), false, true, None);
  println!("verify = {:?}", verify);

  let sign = sm2_sign("test message".to_string(), private_key.clone(), true, true, Some(public_key.clone()), None);
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), true, true, None);
  println!("verify = {:?}", verify);
}

#[test]
fn test_sm2_sign_verify_with_special_user() {
  let mut ec_param = EcParam::new();
  let (private_key, public_key) = generate_key_pair_hex(None, Some(&ec_param));
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let user_id = Some("pthumerian".to_string());

  let sign = sm2_sign("test message".to_string(), private_key.clone(), false, false, Some(public_key.clone()), user_id.clone());
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), false, false, user_id.clone());
  println!("verify = {:?}", verify);


  let sign = sm2_sign("test message".to_string(), private_key.clone(), true, false, Some(public_key.clone()), user_id.clone());
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), true, false, user_id.clone());
  println!("verify = {:?}", verify);

  let sign = sm2_sign("test message".to_string(), private_key.clone(), false, true, Some(public_key.clone()), user_id.clone());
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), false, true, user_id.clone());
  println!("verify = {:?}", verify);

  let sign = sm2_sign("test message".to_string(), private_key.clone(), true, true, Some(public_key.clone()), user_id.clone());
  println!("sign = {:?}", sign);

  let verify = sm2_verify("test message".to_string(), sign.clone(), public_key.clone(), true, true, user_id.clone());
  println!("verify = {:?}", verify);
}