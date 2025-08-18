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

  let private_key = "7e5a640cd13da614dc7afefa1ecc6c69909dd3c2e9b40664f72d41e81e5265d1";
  assert_eq!(cn_talks, sm2_obj.decrypt(
    "7e09373dd39bcf7dc7799cf10e15bea7dac5cb6b62739c2e67ae4b9911efc5b0d50d9306ff1e049f5f2041e8\
    f128aec35306d613c11716b13888f852932e370fa75836eb7e753066a578b17bdc281ea203b62a90594bba68\
    0a1e8ea9a21e9e401366f7843be2907011b140366b11169a70e7faab497fe9905f27afd49fa672cf13e68532",
    private_key,
    Sm2ModeKind::C1C2C3
  ).unwrap());
  assert_eq!(en_talks, sm2_obj.decrypt(
    "f7ce0c623b7f646a57557cba2e85c77fd9eee9b787fdb05b4a30ac6f371d6471cd4f48ca3397c7ec8316\
    cea71b0a40c80478cdc842f97eda8a5bf7198349e66edff5671a240d7a795447ad73f3d6420483ce5fd0\
    7ee47edc12eb8336df55bed4f061529d078ad424d7c3c861aa6376b1a2f897d55b5eb4c8dfd63b778715\
    7f5487e86d8e68ef2eae85f12aed4c97a3fc3d0b3eedd61cfff8d4fd81483cfd705be43df0139cde59d6",
    private_key,
    Sm2ModeKind::C1C2C3
  ).unwrap());
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

  let private_key = "67f81e0079cd0c4823b6d1479efe208d6901f0b427916f560217a40d84d76d9e";
  assert_eq!(cn_talks, sm2_obj.decrypt(
    "4a13750d82668e81d5c7a1675d848d0d23ab622e3d40db42c1e5d8e29b07abdbeb26957115869403b6845084\
    49ba2cd7fa531923f8f99ff3b7de11b0afc0f9bf02f8d5c02400ab26996b9387b1a72c0dc41e7722c73cf596\
    e00f800f008c50701d148e4fda31fb1a6001d27befa6b84d7634bf673ae0ae601ab058b16f71ce9961840155",
    private_key,
    Sm2ModeKind::C1C3C2
  ).unwrap());
  assert_eq!(en_talks, sm2_obj.decrypt(
    "ac6e2b0577b987e868c4265e1f3a7fdb30a67e042c8a72cb8f53a702e0d27c77cb12213b9edda39ac931\
    57e7d7e34d7ba59af9d3bb3f518f1cf9ed2eb7b9ad8eed4005758274ca63a4a4aba73332b18f353f5934\
    29e8c029bab1043ca4a621b1621e34b75cf0cb830590c4fcc1392554d1b8c342803324add863770ee8e6\
    0dbdbdcb6167a8aad79b94ee087a507334c60b5728267c74686e15db81e43572866848d7ff0c4c41f94c",
    private_key,
    Sm2ModeKind::C1C3C2
  ).unwrap());
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
  println!("sign(hash) = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), true, false,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), true, false, None).unwrap();
  println!("sign(der) = {:?}", sign);
  assert!(verify);

  let sign = sm2_obj.sign(
    "hello world".to_string(), private_key.clone(), true, true,
    Some(public_key.clone()), None).unwrap();
  let verify = sm2_obj.verify(
    "hello world".to_string(), sign.clone(), public_key.clone(), true, true, None).unwrap();
  println!("sign(der, hash) = {:?}", sign);
  assert!(verify);

  let public_key = "0436c1e4a136c4b1a4e6c314aed13276e506fb9b3bc6e3476fd286785e3d09d7f\
  707d5d0fa00977de2255fb25a38f0a8397276bd997cba63f1a7bfdc33d61efc76";
  assert!(sm2_obj.verify(
    "hello world",
    "48cc2dceb370bd27ba4e663a2df89204826be02d9252783bfda448f1f5ad3e7b\
    f45010d79383beaf2b37850ec51877228f47867591c2323facd00264e44391ca",
    public_key,
    false, false, None
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "3eec13c584fd5bf1f76b0e2f7b32f0b68d876eeca7807910e9419641af78b592\
    419afc09f8fce4b9a44f7086677ce735162b6fb6f6f0e0d657e2a0ad0b6acf30",
    public_key,
    false, true, None
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "304402202e42656561a31a70f623ce4b3a389568a788772b7fb9a81bda921f590db490\
    f60220338fcdb11380159f6dd0ee290e612ad77c3b2c430ab222eb470f060e0fd4ab37",
    public_key,
    true, false, None
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "3045022058de1e97a55f0cb0f2cd7f5878409d8e4f8e05e6f8b11ab92f7fc19bef2bcc5\
    f022100a8069cff70e9e3cdf6e6b652668a428141fbcbd51215ee5bb926578e1380b6c2",
    public_key,
    true, true, None
  ).unwrap());
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

  let public_key = "040af7e012f78307357aecc370bbd82db878303e161789397e74ec1f23335db52\
  7326954c2dc8fecd169743f2efeb48930060108285e093bb1bd2b38dd456e17bf";
  assert!(sm2_obj.verify(
    "hello world",
    "2a9d22d9dcaf43732ac702e4458622982a60d5f0a8044bb8d91b72dc7d623b57\
    ac3aa5780583c74ba489138b733a2b1c68e5b1da8327094d4d32d78f5cc574d7",
    public_key,
    false, false, user_id.clone()
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "60278c87e5856f834f0f217268ca1c61dc74a8e4143bcb9f2188f19511a4cbea\
    44fd732c8d0864b501c565c36abbb37ea0823dd497fd664280b9c4c88c819aaa",
    public_key,
    false, true, user_id.clone()
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "304502203de6dbea11abf3cd39ea9ed855c9dc3222270bf0b082e8b0674a8c770289778\
    5022100fc3d0a9627362e90532ea7da2d6b0257fe5a56e737b51e65dfa20a24657eb6fb",
    public_key,
    true, false, user_id.clone()
  ).unwrap());
  assert!(sm2_obj.verify(
    "hello world",
    "304502202fb9e0864b7bd62ed3b24a41360f1ee18eb9b587bbd8a93f3414e9c34478896\
    7022100939e4ac4eb413e2bacb27829420bfbc33cb82b4944e1bc7956c4adbe6f564972",
    public_key,
    true, true, user_id.clone()
  ).unwrap());
}
