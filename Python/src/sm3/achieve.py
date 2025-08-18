import struct


def _rotl(value, left_move_nums):
  """
  32位循环左移

  Parameters
  ----------
  value: int
    32位无符号整数
  left_move_nums: int
    循环左移的位数

  Returns
  -------
  int
    循环左移结果
  """
  left_move_nums &= 31
  return (
    (value << left_move_nums) | (value >> (32 - left_move_nums))
  ) & 0xffffffff


def _xor_in_bytes(byts1, byts2):
  """
  字节数组异或

  Parameters
  ----------
  byts1: bytearray
  byts2: bytearray

  Returns
  -------
  bytearray
  """
  return bytearray(byti1 ^ byti2 for byti1, byti2 in zip(byts1, byts2))


def _p0(dial):
  """
  压缩函数的置换函数P0(X) = X xor (X <<< 9) xor (X <<< 17)

  Parameters
  ----------
  dial: int

  Returns
  -------
  int
  """
  return (dial ^ _rotl(dial, 9)) ^ _rotl(dial, 17)


def _p1(dial):
  """
  消息扩展中的置换函数P1(X) = X xor (X <<< 15) xor (X <<< 23)

  Parameters
  ----------
  dial: int

  Returns
  -------
  int
  """
  return (dial ^ _rotl(dial, 15)) ^ _rotl(dial, 23)


def sm3_digest(byt_arrs):
  """
  SM3压缩函数

  Parameters
  ----------
  byt_arrs: bytearray
    待压缩的字节数组

  Returns
  -------
  bytearray
    SM3压缩结果
  """
  byt_arrs = bytearray(byt_arrs)
  bytl = len(byt_arrs) * 8

  # k = len % 512
  # k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  # 需要补充长度为512b的整数倍：
  #   ...array: bytl长度
  #   0x80: 1b
  #   ...kArr: k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  #   ...lenArr: 64b
  # 先补充到56byte
  k = bytl % 512
  k = 512 - (k % 512) + 448 - 1 if k >= 448 else 448 - k - 1
  k_arrs = [0] * ((k - 7) // 8)

  byt_arrs.append(0x80)
  byt_arrs.extend(k_arrs)
  byt_arrs.append(bytl >> 56 & 0xff)
  byt_arrs.append(bytl >> 48 & 0xff)
  byt_arrs.append(bytl >> 40 & 0xff)
  byt_arrs.append(bytl >> 32 & 0xff)
  byt_arrs.append(bytl >> 24 & 0xff)
  byt_arrs.append(bytl >> 16 & 0xff)
  byt_arrs.append(bytl >> 8 & 0xff)
  byt_arrs.append(bytl & 0xff)

  sm3_v = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

  w = [0] * 68
  m = [0] * 64
  n = len(byt_arrs) // 64
  for i in range(n):
    w[:] = [0] * 68
    m[:] = [0] * 64

    # 将消息分组B划分为16个字W0, W1, \dots, W15
    for j in range(16):
      w[j] = struct.unpack(">I", byt_arrs[(i * 64 + j * 4):(i * 64 + j * 4 + 4)])[0]

    # W16 -> W67：W[i] <- P1(W[i−16] xor W[i−9] xor (W[i−3] <<< 15)) xor (W[i−13] <<< 7) xor W[i−6]
    for j in range(16, 68):
      w[j] = (_p1((w[j - 16] ^ w[j - 9]) ^ _rotl(w[j - 3], 15)) ^ _rotl(w[j - 13], 7)) ^ w[j - 6]

    # W′0 ～ W′63：W′[i] = W[i] xor W[i+4]
    for j in range(64):
      m[j] = w[j] ^ w[j + 4]

    a, b, c, d, e, f, g, h = sm3_v
    for j in range(64):
      t = 0x79cc4519 if j <= 15 else 0x7a879d8a
      # SS1 = rotl(rotl(A, 12) + E + rotl(T, i), 7)
      ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xffffffff, 7)
      # SS2 = SS1 ^ rotl(A, 12)
      ss2 = ss1 ^ _rotl(a, 12)
      # TT1 = (i >= 0 && i <= 15 ? ((A ^ B) ^ C) : (((A & B) | (A & C)) | (B & C))) + D + SS2 + M[i]
      tt1 = ((a ^ b ^ c) if j <= 15 else ((a & b) | (a & c) | (b & c)))
      tt1 = (tt1 + d + ss2 + m[j]) & 0xffffffff
      # TT2 = (i >= 0 && i <= 15 ? ((E ^ F) ^ G) : ((E & F) | ((~E) & G))) + H + SS1 + W[i]
      tt2 = ((e ^ f ^ g) if j <= 15 else ((e & f) | ((~e) & g)))
      tt2 = (tt2 + h + ss1 + w[j]) & 0xffffffff

      d = c
      c = _rotl(b, 9)
      b = a
      a = tt1
      h = g
      g = _rotl(f, 19)
      f = e
      e = _p0(tt2)

    sm3_v[0] ^= a
    sm3_v[1] ^= b
    sm3_v[2] ^= c
    sm3_v[3] ^= d
    sm3_v[4] ^= e
    sm3_v[5] ^= f
    sm3_v[6] ^= g
    sm3_v[7] ^= h

  reap = []
  for sm3_vi in sm3_v:
    reap.extend(
      [
        sm3_vi >> 24 & 0xff,
        sm3_vi >> 16 & 0xff,
        sm3_vi >> 8 & 0xff,
        sm3_vi & 0xff
        ]
      )

  return bytearray(reap)


def sm3_hmac(sm3_k, val):
  """
  Parameters
  ----------
  sm3_k: bytearray
    HMAC密钥
  val: bytearray
    待签名消息

  Returns
  -------
  bytearray
    SM3-HMAC结果
  """
  blkl = 64
  if len(sm3_k) > blkl:
    sm3_k = sm3_digest(sm3_k)
  while len(sm3_k) < blkl:
    sm3_k.append(0)

  i_pad = bytearray([0x36] * blkl)
  o_pad = bytearray([0x5c] * blkl)
  i_pad_k = _xor_in_bytes(sm3_k, i_pad)
  o_pad_k = _xor_in_bytes(sm3_k, o_pad)

  hash_val = sm3_digest(i_pad_k + val)
  return sm3_digest(o_pad_k + hash_val)
