const BLOCK: usize = 64;


fn read_u32_be(bytes: &[u8]) -> u32 {
  ((bytes[0] as u32) << 24) | ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32)
}


fn write_u64_be(n: u64) -> [u8; 8] {
  [
    (n >> 56) as u8,
    (n >> 48) as u8,
    (n >> 40) as u8,
    (n >> 32) as u8,
    (n >> 24) as u8,
    (n >> 16) as u8,
    (n >> 8) as u8,
    n as u8,
  ]
}


fn xor_bytes(x: &[u8], y: &[u8]) -> Vec<u8> {
  x.iter().zip(y.iter()).map(|(&a, &b)| a ^ b).collect()
}


fn p0(x: u32) -> u32 {
  x ^ x.rotate_left(9) ^ x.rotate_left(17)
}


fn p1(x: u32) -> u32 {
  x ^ x.rotate_left(15) ^ x.rotate_left(23)
}


pub trait DigestTrait {
  fn digest(&self, input: &[u8]) -> Vec<u8>;
}


pub struct Sm3 {
  w: [u32; 68],
  m: [u32; 64],
}


impl Sm3 {
  pub fn new() -> Self {
    Self {
      w: [0; 68],
      m: [0; 64],
    }
  }

  fn padding(&self, input: &[u8]) -> Vec<u8> {
    let mut m = input.to_vec();
    let bit_len = (m.len() as u64) * 8;
    m.push(0x80);

    let mut pad_len = 56usize.wrapping_sub(m.len() % 64);
    if m.len() % 64 > 56 {
      pad_len += 64;
    }
    m.extend(vec![0u8; pad_len]);

    let len_buf = write_u64_be(bit_len);
    m.extend_from_slice(&len_buf);
    m
  }
}


impl DigestTrait for Sm3 {
  fn digest(&self, input: &[u8]) -> Vec<u8> {
    let mut v: [u32; 8] = [
      0x7380166f,
      0x4914b2b9,
      0x172442d7,
      0xda8a0600,
      0xa96f30bc,
      0x163138aa,
      0xe38dee4d,
      0xb0fb0e4e,
    ];

    let padded = self.padding(input);
    for chunk in padded.chunks_exact(64) {
      let mut w = [0u32; 68];
      let mut m = [0u32; 64];

      for j in 0..16 {
        w[j] = read_u32_be(&chunk[j * 4..(j + 1) * 4]);
      }
      for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
          ^ w[j - 13].rotate_left(7)
          ^ w[j - 6];
      }
      for j in 0..64 {
        m[j] = w[j] ^ w[j + 4];
      }

      let mut a = v[0];
      let mut b = v[1];
      let mut c = v[2];
      let mut d = v[3];
      let mut e = v[4];
      let mut f = v[5];
      let mut g = v[6];
      let mut h = v[7];

      for j in 0..64 {
        let t: u32 = if j <= 15 { 0x79cc4519 } else { 0x7a879d8a };
        let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(t.rotate_left(j as u32)).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = if j <= 15 {
          (a ^ b ^ c).wrapping_add(d).wrapping_add(ss2).wrapping_add(m[j])
        } else {
          ((a & b) | (a & c) | (b & c)).wrapping_add(d).wrapping_add(ss2).wrapping_add(m[j])
        };
        let tt2 = if j <= 15 {
          (e ^ f ^ g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j])
        } else {
          ((e & f) | ((!e) & g)).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j])
        };

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
      }

      v[0] ^= a;
      v[1] ^= b;
      v[2] ^= c;
      v[3] ^= d;
      v[4] ^= e;
      v[5] ^= f;
      v[6] ^= g;
      v[7] ^= h;
    }

    let mut result = Vec::with_capacity(32);
    for word in v.iter() {
      result.extend_from_slice(&word.to_be_bytes());
    }
    result
  }
}


pub fn hmac_sm3(key: &[u8], data: &[u8]) -> Vec<u8> {
  let mut key = key.to_vec();
  if key.len() > BLOCK {
    key = Sm3::new().digest(&key);
  }
  if key.len() < BLOCK {
    key.extend(vec![0; BLOCK - key.len()]);
  }

  let i_pad = vec![0x36; BLOCK];
  let o_pad = vec![0x5c; BLOCK];

  let i_key_pad = xor_bytes(&key, &i_pad);
  let o_key_pad = xor_bytes(&key, &o_pad);

  let inner = Sm3::new().digest(&[i_key_pad, data.to_vec()].concat());
  Sm3::new().digest(&[o_key_pad, inner].concat())
}
