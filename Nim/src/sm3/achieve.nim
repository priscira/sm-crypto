import std/[sequtils]


proc rotl32(val: uint32, left_move_nums: int): uint32 {.inline.} =
  ## 32位循环左移
  let left_move_nums = left_move_nums and 31
  (val shl left_move_nums) or (val shr (32 - left_move_nums))


proc xorInBytes(byts1: seq[uint8], byts2: seq[uint8]): seq[uint8] = 
  ## 字节数组异或
  var reap = newSeq[uint8]()
  for (byti1, byti2) in zip(byts1, byts2):
    reap.add(byti1 xor byti2)
  return reap


proc p0(dial: uint32): uint32 = 
  ## 压缩函数的置换函数P0(X) = X xor (X <<< 9) xor (X <<< 17)
  dial xor rotl32(dial, 9) xor rotl32(dial, 17)


proc p1(dial: uint32): uint32 = 
  ## 消息扩展中的置换函数P1(X) = X xor (X <<< 15) xor (X <<< 23)
  dial xor rotl32(dial, 15) xor rotl32(dial, 23)


proc sm3Digest*(bytArrs: seq[uint8]): seq[uint8] = 
  ## SM3压缩函数
  ## 
  ## Parameters
  ## ----------
  ## bytArrs: 待压缩的字节数组
  ## 
  ## Returns
  ## -------
  ## SM3压缩结果
  var bytArrs = toSeq(bytArrs)

  var bytl = bytArrs.len() * 8
  # k = len % 512
  # k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  # 需要补充长度为512b的整数倍：
  #   ...array: bytl长度
  #   0x80: 1b
  #   ...kArr: k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1
  #   ...lenArr: 64b
  # 先补充到56byte
  var k = bytl mod 512
  k = if k >= 448: 512 - (k mod 512) + 448 - 1 else: 448 - k - 1
  let kArrs = repeat(0'u8, (k - 7) div 8)

  bytArrs.add(0x80)
  bytArrs.add(kArrs)
  for i in countdown(56, 0, 8):
    bytArrs.add(uint8(bytl shr i))

  var sm3V = [
    0x7380166f'u32, 0x4914b2b9'u32, 0x172442d7'u32, 0xda8a0600'u32,
    0xa96f30bc'u32, 0x163138aa'u32, 0xe38dee4d'u32, 0xb0fb0e4e'u32
    ]
  bytl = bytArrs.len() div 64

  var
    w: array[0..67, uint32] = arrayWith(0'u32, 68)
    m: array[0..63, uint32] = arrayWith(0'u32, 64)
  for i in countup(0, bytl - 1):
    w = arrayWith(0'u32, 68)
    m = arrayWith(0'u32, 64)
    # 将消息分组B划分为16个字W0, W1, \dots, W15
    for j in countup(0, 15):
      var k = i * 64 + j * 4
      w[j] = (uint32(bytArrs[k]) shl 24) or
        (uint32(bytArrs[k + 1]) shl 16) or
        (uint32(bytArrs[k + 2]) shl 8) or
        (uint32(bytArrs[k + 3]))
    # W16 -> W67：W[i] <- P1(W[i−16] xor W[i−9] xor (W[i−3] <<< 15)) xor (W[i−13] <<< 7) xor W[i−6]
    for j in countup(16, 67):
      w[j] = (p1(w[j - 16] xor w[j - 9] xor rotl32(w[j - 3], 15)) xor rotl32(w[j - 13], 7)) xor w[j - 6]
    # W′0 ～ W′63：W′[i] = W[i] xor W[i+4]
    for j in countup(0, 63):
      m[j] = w[j] xor w[j + 4]

    var
      a = sm3V[0]
      b = sm3V[1]
      c = sm3V[2]
      d = sm3V[3]
      e = sm3V[4]
      f = sm3V[5]
      g = sm3V[6]
      h = sm3V[7]
    for j in countup(0, 63):
      var t = if j <= 15: 0x79cc4519'u32 else: 0x7a879d8a'u32
      # SS1 = rotl(rotl(A, 12) + E + rotl(T, i), 7)
      var ss1 = rotl32(rotl32(a, 12) + e + rotl32(t, j), 7)
      # SS2 = SS1 ^ rotl(A, 12)
      var ss2 = ss1 xor rotl32(a, 12)
      # TT1 = (i >= 0 && i <= 15 ? ((A ^ B) ^ C) : (((A & B) | (A & C)) | (B & C))) + D + SS2 + M[i]
      var tt1 = if j <= 15: a xor b xor c else: (a and b) or (a and c) or (b and c)
      tt1 = tt1 + d + ss2 + m[j]
      # TT2 = (i >= 0 && i <= 15 ? ((E ^ F) ^ G) : ((E & F) | ((~E) & G))) + H + SS1 + W[i]
      var tt2 = if j <= 15: e xor f xor g else: (e and f) or ((not e) and g)
      tt2 = tt2 + h + ss1 + w[j]

      d = c
      c = rotl32(b, 9)
      b = a
      a = tt1
      h = g
      g = rotl32(f, 19)
      f = e
      e = p0(tt2)

    sm3V[0] = sm3V[0] xor a
    sm3V[1] = sm3V[1] xor b
    sm3V[2] = sm3V[2] xor c
    sm3V[3] = sm3V[3] xor d
    sm3V[4] = sm3V[4] xor e
    sm3V[5] = sm3V[5] xor f
    sm3V[6] = sm3V[6] xor g
    sm3V[7] = sm3V[7] xor h
  
  var reap = newSeq[uint8]()
  for sm3Vi in sm3V:
    reap.add([
      uint8(sm3Vi shr 24), uint8(sm3Vi shr 16), uint8(sm3Vi shr 8), uint8(sm3Vi)
    ])

  return reap


proc sm3Hmac*(sm3K: seq[uint8], val: seq[uint8]): seq[uint8] = 
  ## HMAC-SM3认证算法
  ##
  ## Parameters
  ## ----------
  ## sm3K: HMAC密钥
  ## val: 待签名消息
  let blk = 64
  var sm3K = sm3K

  if sm3K.len() > blk:
    sm3K = sm3Digest(sm3K)
  if sm3K.len() < blk:
    sm3K.add(repeat(0'u8, blk - sm3K.len()))
  
  let iPad = repeat(0x36'u8, blk)
  let oPad = repeat(0x5c'u8, blk)
  let iPadK = xorInBytes(sm3K, iPad)
  let oPadK = xorInBytes(sm3K, oPad)
  return sm3Digest(oPadK & sm3Digest(iPadK & val))
