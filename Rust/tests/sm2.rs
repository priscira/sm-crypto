// cargo test --test sm2 -- --show-output

use sm_crypto::sm2::sm2::*;


#[test]
fn test_generate_key_pair_hex() {
  let sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(None).unwrap();
  let public_key = key_pair.public_key;
  let private_key = key_pair.private_key;
  assert_eq!(public_key.len(), 130);
  assert_eq!(private_key.len(), 64);
  println!("private_key = {:?}", public_key);
  println!("public_key = {:?}", private_key);
  let comp_public_key = Sm2::compress_public_key_hex(&public_key).unwrap();
  assert_eq!(comp_public_key.len(), 66);
  println!("compressed_public_key = {:?}", comp_public_key);
  let verfy_public_key = sm2_obj.verify_public_key(&public_key).unwrap();
  println!("verify_public_key = {:?}", verfy_public_key);
  println!("===================================");

  let sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(Some(("123123123123123".to_string(), 16))).unwrap();
  let public_key = key_pair.public_key;
  let private_key = key_pair.private_key;
  assert_eq!(public_key.len(), 130);
  assert_eq!(private_key.len(), 64);
  println!("private_key = {:?}", public_key);
  println!("public_key = {:?}", private_key);
  let compress_public_key = Sm2::compress_public_key_hex(&public_key).unwrap();
  assert_eq!(comp_public_key.len(), 66);
  println!("compressed_public_key = {:?}", compress_public_key);
  let verfy_public_key = sm2_obj.verify_public_key(&public_key).unwrap();
  println!("verify_public_key = {:?}", verfy_public_key);
}


#[test]
fn test_sm2_c1c2c3_crypto() {
  let sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(None).unwrap();
  let private_key = key_pair.private_key;
  let public_key = key_pair.public_key;
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let cn_talks = "臂上妆犹在，襟间泪尚盈。";
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.".to_string();

  let cn_enc_talks = sm2_obj.encrypt(cn_talks, &public_key, Sm2ModeKind::C1C2C3).unwrap();
  println!("c1c2c3_cn_enc = {:?}", cn_enc_talks);
  let cn_dec_talks = sm2_obj.decrypt(&cn_enc_talks, &private_key, Sm2ModeKind::C1C2C3).unwrap();
  assert_eq!(cn_talks, cn_dec_talks);

  let en_enc_talks = sm2_obj.encrypt(en_talks.clone(), public_key.clone(), Sm2ModeKind::C1C2C3).unwrap();
  println!("c1c2c3_en_enc = {:?}", en_enc_talks);
  let en_dec_talks = sm2_obj.decrypt(en_enc_talks, private_key.clone(), Sm2ModeKind::C1C2C3).unwrap();
  assert_eq!(en_talks, en_dec_talks);
}


#[test]
fn test_sm2_c1c3c2_crypto() {
  let sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(None).unwrap();
  let private_key = key_pair.private_key;
  let public_key = key_pair.public_key;
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let cn_talks = "臂上妆犹在，襟间泪尚盈。".to_string();
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.";

  let cn_enc_talks = sm2_obj.encrypt(cn_talks.clone(), public_key.clone(), Sm2ModeKind::C1C3C2).unwrap();
  println!("c1c3c2_cn_enc = {:?}", cn_enc_talks);
  let cn_dec_talks = sm2_obj.decrypt(cn_enc_talks, private_key.clone(), Sm2ModeKind::C1C3C2).unwrap();
  assert_eq!(cn_talks, cn_dec_talks);

  let en_enc_talks = sm2_obj.encrypt(en_talks, &public_key, Sm2ModeKind::C1C3C2).unwrap();
  println!("c1c3c2_en_enc = {:?}", en_enc_talks);
  let en_dec_talks = sm2_obj.decrypt(&en_enc_talks, &private_key, Sm2ModeKind::C1C3C2).unwrap();
  assert_eq!(en_talks, en_dec_talks);
}


#[test]
fn test_sm2_sign_verify() {
  let mut sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(None).unwrap();
  let private_key = key_pair.private_key;
  let public_key = key_pair.public_key;
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), false, false,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), false, false, None).unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world", &private_key, false, true,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world", &sign, &public_key, false, true, None).unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), true, false,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), true, false, None).unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), true, true,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), true, true, None).unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);
}


#[test]
fn test_sm2_sign_verify_with_special_user() {
  let mut sm2_obj = Sm2::new();
  let key_pair = sm2_obj.generate_key_pair_hex(None).unwrap();
  let private_key = key_pair.private_key;
  let public_key = key_pair.public_key;
  println!("private_key = {:?}", private_key);
  println!("public_key = {:?}", public_key);

  let user_id = Some("priscira".to_string());

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), false, false,
    Some(public_key.clone()), user_id.clone()).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), false, false, user_id.clone())
    .unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), false, true,
    Some(public_key.clone()), user_id.clone()).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), false, true, user_id.clone())
    .unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world", &private_key, true, false,
    Some(public_key.clone()), user_id.clone()).unwrap();
  let verify = sm2_obj.verify(
    "hello world", &sign, &public_key, true, false, user_id.clone())
    .unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world", &private_key, true, true,
    Some(public_key.clone()), user_id.clone()).unwrap();
  let verify = sm2_obj.verify(
    "hello world", &sign, &public_key, true, true, user_id.clone())
    .unwrap();
  println!("sign = {:?}", sign);
  assert!(verify);
}
