// cargo test --test sm4 -- --show-output

use sm_crypto::sm4::sm4::*;


#[test]
fn test_sm4_ecb_string() {
  let key = "af32409cf34aeef23f4b328a96100ce1";
  let cn_talks = "臂上妆犹在，襟间泪尚盈。".to_string();
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.";
  let sm4 = Sm4::new();

  let cn_talks_ecb = sm4.encrypt(
    cn_talks.clone(), key.to_string(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap();
  let en_talks_ecb = sm4.encrypt(en_talks, key, Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap();
  assert_eq!(
    cn_talks_ecb,
    "0fb9045738bf0c9e660743c52753ca36b374a461536971890e8143aa1ae425544c0f0f0bee82d5b2518cd9f89c931709"
  );
  assert_eq!(
    en_talks_ecb,
    "2009305f19f25e5386cb425a44eee723c83bfb72292af287d8df1a9455c24d8ed92b3aa517de87d5\
     4ebe29fcd5094f1f92a37b147eac20eec83323454fc07e1742f00704d2f76109a7b306b7bb530937"
  );

  assert_eq!(
    sm4.decrypt(cn_talks_ecb, key.to_string(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap(),
    cn_talks
  );
  assert_eq!(
    sm4.decrypt(en_talks_ecb, key.to_string(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap(),
    en_talks
  );
}


#[test]
fn test_sm4_ecb_list() {
  let key: Vec<u8> = vec![175, 50, 64, 156, 243, 74, 238, 242, 63, 75, 50, 138, 150, 16, 12, 225];
  let cn_talks: Vec<u8> = vec![
    232, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156, 168, 239, 188, 140, 232, 165,
    159, 233, 151, 180, 230, 179, 170, 229, 176, 154, 231, 155, 136, 227, 128, 130,
  ];
  let en_talks: [u8; 72] = [
    87, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110, 103, 32, 73, 39, 100, 32, 108,
    105, 115, 116, 101, 110, 32, 116, 111, 32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97,
    105, 116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118, 111, 114, 105, 116, 101,
    32, 115, 111, 110, 103, 115, 46,
  ];
  let sm4 = Sm4::new();

  let cn_talks_ecb = sm4.encrypt(
    cn_talks.clone(), key.clone(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap();
  let en_talks_ecb = sm4.encrypt(
    &en_talks[..], &key, Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap();
  assert_eq!(
    cn_talks_ecb, [
      15, 185, 4, 87, 56, 191, 12, 158, 102, 7, 67, 197, 39, 83, 202, 54, 179, 116, 164, 97, 83, 105, 113,
      137, 14, 129, 67, 170, 26, 228, 37, 84, 76, 15, 15, 11, 238, 130, 213, 178, 81, 140, 217, 248, 156,
      147, 23, 9
    ]
  );
  assert_eq!(
    en_talks_ecb, [
      32, 9, 48, 95, 25, 242, 94, 83, 134, 203, 66, 90, 68, 238, 231, 35, 200, 59, 251, 114, 41, 42, 242,
      135, 216, 223, 26, 148, 85, 194, 77, 142, 217, 43, 58, 165, 23, 222, 135, 213, 78, 190, 41, 252, 213,
      9, 79, 31, 146, 163, 123, 20, 126, 172, 32, 238, 200, 51, 35, 69, 79, 192, 126, 23, 66, 240, 7, 4,
      210, 247, 97, 9, 167, 179, 6, 183, 187, 83, 9, 55
    ]
  );

  assert_eq!(
    sm4.decrypt(cn_talks_ecb, key.clone(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap(),
    cn_talks
  );
  assert_eq!(
    sm4.decrypt(en_talks_ecb, key.clone(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Ecb, None).unwrap(),
    en_talks
  );
}


#[test]
fn test_sm4_cbc_string() {
  let key = "fa4f311bd2765bb23f4b328a0001ac00";
  let cn_talks = "臂上妆犹在，襟间泪尚盈。".to_string();
  let en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs.";
  let iv = "32ef4500ad3ecb2a34dcb09aac34bfea";
  let sm4 = Sm4::new();

  let cn_talks_cbc = sm4.encrypt(
    cn_talks.clone(), key.to_string(), Sm4PaddingKind::Pkcs7, Sm4ModeKind::Cbc, Some(iv.to_string())
  ).unwrap();
  let en_talks_cbc = sm4.encrypt(
    en_talks, key, Sm4PaddingKind::Pkcs7, Sm4ModeKind::Cbc, Some(iv)).unwrap();

  assert_eq!(
    cn_talks_cbc,
    "bf484cb9ee733cea62377187ba0cd6cd522a4941ba87a73e4632fc706a6c3860a00c029d50f611a333d37a6eb73ccc6d"
  );
  assert_eq!(
    en_talks_cbc,
    "527baf83366542b2a5dab3c6a1808a42bbcf656d194114de4825e4a84e3c407ded4449627652a38\
     3036f541fb8dfa762bbc2ae0686bf6d204775c1cf342130df251a74ad7ee12ae59248fbcb69ef190d"
  );
}


#[test]
fn test_sm4_cbc_list() {
  let key: Vec<u8> = vec![250, 79, 49, 27, 210, 118, 91, 178, 63, 75, 50, 138, 0, 1, 172, 0];
  let cn_talks: [u8; 36] = [
    232, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156, 168, 239, 188, 140, 232, 165,
    159, 233, 151, 180, 230, 179, 170, 229, 176, 154, 231, 155, 136, 227, 128, 130,
  ];
  let en_talks: Vec<u8> = vec![
    87, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110, 103, 32, 73, 39, 100, 32, 108,
    105, 115, 116, 101, 110, 32, 116, 111, 32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97,
    105, 116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118, 111, 114, 105, 116, 101,
    32, 115, 111, 110, 103, 115, 46,
  ];
  let iv: Vec<u8> = vec![50, 239, 69, 0, 173, 62, 203, 42, 52, 220, 176, 154, 172, 52, 191, 234];
  let sm4 = Sm4::new();

  let cn_talks_cbc = sm4.encrypt(
    &cn_talks[..], &key, Sm4PaddingKind::Pkcs7, Sm4ModeKind::Cbc, Some(&iv)).unwrap();
  let en_talks_cbc = sm4.encrypt(
    en_talks, key, Sm4PaddingKind::Pkcs7, Sm4ModeKind::Cbc, Some(iv)).unwrap();

  assert_eq!(
    cn_talks_cbc, [
      191, 72, 76, 185, 238, 115, 60, 234, 98, 55, 113, 135, 186, 12, 214, 205, 82, 42, 73, 65, 186, 135,
      167, 62, 70, 50, 252, 112, 106, 108, 56, 96, 160, 12, 2, 157, 80, 246, 17, 163, 51, 211, 122, 110,
      183, 60, 204, 109
    ]
  );
  assert_eq!(
    en_talks_cbc, [
      82, 123, 175, 131, 54, 101, 66, 178, 165, 218, 179, 198, 161, 128, 138, 66, 187, 207, 101, 109, 25,
      65, 20, 222, 72, 37, 228, 168, 78, 60, 64, 125, 237, 68, 73, 98, 118, 82, 163, 131, 3, 111, 84, 31,
      184, 223, 167, 98, 187, 194, 174, 6, 134, 191, 109, 32, 71, 117, 193, 207, 52, 33, 48, 223, 37, 26,
      116, 173, 126, 225, 42, 229, 146, 72, 251, 203, 105, 239, 25, 13
    ]
  );
}
