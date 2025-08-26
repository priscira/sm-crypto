/// 字节数组异或
fn xor_in_bytes(byts1: &[u8], byts2: &[u8]) -> Vec<u8> {
  byts1.iter().zip(byts2.iter()).map(|(&byti1, &byti2)| byti1 ^ byti2).collect()
}


/// 压缩函数的置换函数P0(X) = X xor (X <<< 9) xor (X <<< 17)
fn p0(dial: u32) -> u32 {
  dial ^ dial.rotate_left(9) ^ dial.rotate_left(17)
}


/// 消息扩展中的置换函数P1(X) = X xor (X <<< 15) xor (X <<< 23)
fn p1(dial: u32) -> u32 {
  dial ^ dial.rotate_left(15) ^ dial.rotate_left(23)
}


/// SM3填充压缩数据为64字节整数倍[元数据，0x80，零填充，原始长度填充]
/// ## Parameters
/// - byt_arrs: 待填充的字节数组
fn sm3_pad(byt_arrs: &[u8]) -> Vec<u8> {
  // m = [...array, 0x80, ...kArr, ...lenArr]
  // ...array
  let mut reap = byt_arrs.to_vec();

  let bytl = (reap.len() as u64) * 8;
  // 0x80
  reap.push(0x80);

  // k = len % 512
  // k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  // 需要补充长度为512b的整数倍：
  //   ...array: bytl长度
  //   0x80: 1b
  //   ...kArr: k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  //   ...lenArr: 64b
  // 先补充到56byte
  let mut kl = 56usize.wrapping_sub(reap.len() % 64);
  if reap.len() % 64 > 56 {
    // 新补一块64byte
    kl += 64;
  }
  // kArr
  reap.extend(vec![0u8; kl]);
  // lenArr
  reap.extend_from_slice(&[
    (bytl >> 56) as u8,
    (bytl >> 48) as u8,
    (bytl >> 40) as u8,
    (bytl >> 32) as u8,
    (bytl >> 24) as u8,
    (bytl >> 16) as u8,
    (bytl >> 8) as u8,
    bytl as u8,
  ]);
  reap
}


/// 模拟dataview.getUint32()，整合4个字节为一个u32
/// ## Parameters
/// - byt4: 4个字节的字节数组
/// - is_be: 是否以大端字节序读取
fn data_view_get_uint_32(byt4: &[u8], is_be: bool) -> u32 {
  if is_be {
    u32::from_be_bytes([byt4[0], byt4[1], byt4[2], byt4[3]])
  } else {
    u32::from_le_bytes([byt4[0], byt4[1], byt4[2], byt4[3]])
  }
}


/// SM3压缩函数
/// ## Parameters
/// - byt_arrs: 待压缩的字节数组
pub fn sm3_digest(byt_arrs: &[u8]) -> Vec<u8> {
  let mut sm3_v: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
  ];

  let byt_arrs = sm3_pad(byt_arrs);
  for byt_arri in byt_arrs.chunks_exact(64) {
    let mut w = [0u32; 68];
    let mut m = [0u32; 64];

    // 将消息分组B划分为16个字W0, W1, \dots, W15
    for i in 0..16 {
      w[i] = data_view_get_uint_32(&byt_arri[i * 4..(i + 1) * 4], true);
    }

    // W16 -> W67：W[i] <- P1(W[i−16] xor W[i−9] xor (W[i−3] <<< 15)) xor (W[i−13] <<< 7) xor W[i−6]
    for i in 16..68 {
      w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
        ^ w[i - 13].rotate_left(7)
        ^ w[i - 6];
    }

    // W′0 ～ W′63：W′[i] = W[i] xor W[i+4]
    for i in 0..64 {
      m[i] = w[i] ^ w[i + 4];
    }

    // 字寄存器
    let mut a = sm3_v[0];
    let mut b = sm3_v[1];
    let mut c = sm3_v[2];
    let mut d = sm3_v[3];
    let mut e = sm3_v[4];
    let mut f = sm3_v[5];
    let mut g = sm3_v[6];
    let mut h = sm3_v[7];

    for i in 0..64 {
      let t: u32 = if i <= 15 { 0x79cc4519 } else { 0x7a879d8a };
      // SS1 = rotl(rotl(A, 12) + E + rotl(T, i), 7)
      let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(t.rotate_left(i as u32))
        .rotate_left(7);
      // SS2 = SS1 ^ rotl(A, 12)
      let ss2 = ss1 ^ a.rotate_left(12);
      // TT1 = (i >= 0 && i <= 15 ? ((A ^ B) ^ C) : (((A & B) | (A & C)) | (B & C))) + D + SS2 + M[i]
      let tt1 = if i <= 15 { a ^ b ^ c } else { (a & b) | (a & c) | (b & c) }
        .wrapping_add(d).wrapping_add(ss2).wrapping_add(m[i]);
      // TT2 = (i >= 0 && i <= 15 ? ((E ^ F) ^ G) : ((E & F) | ((~E) & G))) + H + SS1 + W[i]
      let tt2 = if i <= 15 { e ^ f ^ g } else { (e & f) | ((!e) & g) }
        .wrapping_add(h).wrapping_add(ss1).wrapping_add(w[i]);

      d = c;
      c = b.rotate_left(9);
      b = a;
      a = tt1;
      h = g;
      g = f.rotate_left(19);
      f = e;
      e = p0(tt2);
    }

    sm3_v[0] ^= a;
    sm3_v[1] ^= b;
    sm3_v[2] ^= c;
    sm3_v[3] ^= d;
    sm3_v[4] ^= e;
    sm3_v[5] ^= f;
    sm3_v[6] ^= g;
    sm3_v[7] ^= h;
  }

  // 转回u8
  let mut reap = Vec::with_capacity(32);
  for sm3_vi in sm3_v.iter() {
    reap.extend_from_slice(&sm3_vi.to_be_bytes());
  }
  reap
}


/// HMAC-SM3认证算法
/// ## Parameters
/// - sm3_k: HMAC密钥
/// - val: 待签名消息
pub fn sm3_hmac(sm3_k: &[u8], val: &[u8]) -> Vec<u8> {
  const BLOCK: usize = 64;

  // 密钥填充
  let mut sm3_k = sm3_k.to_vec();
  if sm3_k.len() > BLOCK {
    sm3_k = sm3_digest(&sm3_k);
  }
  if sm3_k.len() < BLOCK {
    sm3_k.extend(vec![0; BLOCK - sm3_k.len()]);
  }

  let i_pad = vec![0x36; BLOCK];
  let o_pad = vec![0x5c; BLOCK];

  let i_pad_k = xor_in_bytes(&sm3_k, &i_pad);
  let o_pad_k = xor_in_bytes(&sm3_k, &o_pad);

  let inner = sm3_digest(&[i_pad_k, val.to_vec()].concat());
  sm3_digest(&[o_pad_k, inner].concat())
}
