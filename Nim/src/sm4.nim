import std/[strutils, sequtils, algorithm]

type
  CryptKind* = enum
    ENCRYPT, DECRYPT

  ModeKind* = enum
    ECB, CBC

  PaddingKind* = enum
    PKCS5, PKCS7, NONEPAD

const
  ROUND = 32
  BLOCK = 16

const SBOX: array[256, uint8] = [
  0xd6'u8, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28,
  0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44,
  0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98,
  0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9,
  0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47,
  0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85,
  0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f,
  0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
  0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f,
  0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf,
  0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
  0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
  0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0,
  0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd,
  0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
  0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8,
  0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9,
  0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d,
  0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

const CK: array[ROUND, uint32] = [
  0x00070e15'u32, 0x1c232a31'u32, 0x383f464d'u32, 0x545b6269'u32, 0x70777e85'u32, 0x8c939aa1'u32,
  0xa8afb6bd'u32, 0xc4cbd2d9'u32, 0xe0e7eef5'u32, 0xfc030a11'u32, 0x181f262d'u32, 0x343b4249'u32,
  0x50575e65'u32, 0x6c737a81'u32, 0x888f969d'u32, 0xa4abb2b9'u32, 0xc0c7ced5'u32, 0xdce3eaf1'u32,
  0xf8ff060d'u32, 0x141b2229'u32, 0x30373e45'u32, 0x4c535a61'u32, 0x686f767d'u32, 0x848b9299'u32,
  0xa0a7aeb5'u32, 0xbcc3cad1'u32, 0xd8dfe6ed'u32, 0xf4fb0209'u32, 0x10171e25'u32, 0x2c333a41'u32,
  0x484f565d'u32, 0x646b7279'u32
]

proc hexToArr(hexStr: string): seq[uint8] =
  ## 十六进制字符串转成数组
  let hexStrL = hexStr.len div 2
  return toSeq(0 ..< hexStrL).map(
    proc(i: int): uint8 = uint8(parseHexInt(hexStr[i * 2 ..< i * 2 + 2]))
  )

proc arrToHex(hexArrs: openArray[uint8]): string =
  ## 字节数组转十六进制字符串
  var hexTalks = ""
  for hexArri in hexArrs:
    hexTalks.add(hexArri.toHex(2))
  return hexTalks

proc utf8ToArr(utfTalks: string): seq[uint8] =
  ## utf-8字符串转成数组
  return cast[seq[uint8]](utfTalks)

proc arrToUtf8(utfArrs: openArray[uint8]): string =
  ## 字节数组转utf-8字符串
  return cast[string](utfArrs.toSeq)

proc rotl32(val: uint32; left_move_nums: int): uint32 {.inline.} =
  ## 32位循环左移
  (val shl left_move_nums) or (val shr (32 - left_move_nums))

proc byteSub(num: uint32): uint32 {.inline.} =
  ## 非线性变换，逐字节查s盒
  uint32(SBOX[(num shr 24) and 0xFF]) shl 24 or
  uint32(SBOX[(num shr 16) and 0xFF]) shl 16 or
  uint32(SBOX[(num shr 8)  and 0xFF]) shl 8  or
  uint32(SBOX[num and 0xFF])

proc l1(num: uint32): uint32 {.inline.} =
  ## 线性变换l，用于给轮函数加密/解密
  num xor rotl32(num, 2) xor rotl32(num, 10) xor rotl32(num, 18) xor rotl32(num, 24)

proc l2(num: uint32): uint32 {.inline.} =
  ## 线性变换l'，扩展密钥
  num xor rotl32(num, 13) xor rotl32(num, 23)

proc sms4Crypt(blk: seq[uint8]; rks: openArray[uint32]): seq[uint8] =
  ## 对16字节明/密文块执行一次SMS4轮变换
  ## 
  ## Parameters
  ## ----------
  ## blk: 16字节明文或密文块
  ## rks: 轮密钥
  ## 
  ## Returns
  ## -------
  ## SMS4轮变换结果
  var words: array[4, uint32]
  # 每32bit处理为一个字
  for i in 0 .. 3:
    words[i] = uint32(blk[i * 4]) shl 24 or
      uint32(blk[i * 4 + 1]) shl 16 or
      uint32(blk[i * 4 + 2]) shl 8 or
      uint32(blk[i * 4 + 3])

  for rki in rks:
    let gogga = words[1] xor words[2] xor words[3] xor rki
    let newWord = words[0] xor l1(byteSub(gogga))
    words = [words[1], words[2], words[3], newWord]

  var reaps: seq[uint8] = newSeq[uint8]()
  for i in countdown(3, 0):
    reaps.add(uint8(words[i] shr 24))
    reaps.add(uint8(words[i] shr 16))
    reaps.add(uint8(words[i] shr 8))
    reaps.add(uint8(words[i]))

  return reaps

proc sms4KeyExt(mk: seq[uint8]; cpKind: CryptKind): seq[uint32] =
  ## 密钥扩展，将128比特的密钥变成32个32比特的轮密钥
  ## 
  ## Parameters
  ## ----------
  ## mk: 128比特主密钥
  ## cpKind: 加密或解密
  ## 
  ## Returns
  ## -------
  ## 32个32比特的轮密钥
  var words: array[4, uint32]
  # 每32bit处理为一个字
  for i in 0 .. 3:
    words[i] = uint32(mk[i * 4]) shl 24 or
      uint32(mk[i * 4 + 1]) shl 16 or
      uint32(mk[i * 4 + 2]) shl 8 or
      uint32(mk[i * 4 + 3])

  words[0] = words[0] xor 0xa3b1bac6'u32
  words[1] = words[1] xor 0x56aa3350'u32
  words[2] = words[2] xor 0x677d9197'u32
  words[3] = words[3] xor 0xb27022dc'u32

  var reaps: seq[uint32] = newSeq[uint32]()
  for i in 0 ..< ROUND:
    let gogga = words[1] xor words[2] xor words[3] xor CK[i]
    let wordTo4 = words[0] xor l2(byteSub(gogga))
    reaps.add(wordTo4)
    words = [words[1], words[2], words[3], wordTo4]

  if cpKind == CryptKind.DECRYPT:
    reaps.reverse()

  return reaps

proc sm4(talks: var seq[uint8]; sm4K: seq[uint8]; cpKind: CryptKind;
         padding: PaddingKind = PaddingKind.PKCS7; mode: ModeKind = ModeKind.ECB;
         iv: seq[uint8] = newSeq[uint8]()): seq[uint8] =
  ## SM4加/解密主要逻辑
  ## 
  ## Parameters
  ## ----------
  ## talks: 字节数组格式的加密文本或者解密文本
  ## sm4K: 字节数组格式的SM4密钥
  ## cpKind: 加密或解密
  ## padding: padding方式，默认PKCS7，可选PKCS5、PKCS7、NONEPAD
  ## mode: 加密方式，默认ECB，可选CBC、ECB
  ## iv: CBC方式IV向量，默认为空数组
  ## 
  ## Returns
  ## -------
  ## 字节数组格式的结果
  if sm4K.len() != BLOCK:
    raise newException(ValueError, "Key must be 16 bytes")
  if mode == ModeKind.CBC and iv.len() != BLOCK:
    raise newException(ValueError, "IV must be 16 bytes for CBC")

  # 新增填充，sm4规定16字节作为一个分组，统一pkcs7
  if padding != PaddingKind.NONEPAD and cpKind != CryptKind.DECRYPT:
    let padL = BLOCK - (talks.len() mod BLOCK)
    talks.add(repeat(uint8(padL), padL))

  let rk: seq[uint32] = sms4KeyExt(sm4K, cpKind)
  var reap: seq[uint8] = newSeq[uint8]()
  var goggaIV: seq[uint8] = iv

  for ofs in countup(0, talks.len - 1, BLOCK):
    var blk: seq[uint8] = talks[ofs ..< ofs + BLOCK]
    if mode == ModeKind.CBC and cpKind != CryptKind.DECRYPT:
      for i in 0 ..< BLOCK:
        blk[i] = blk[i] xor goggaIV[i]
    var sms4Blk = sms4Crypt(blk, rk)
    if mode == ModeKind.CBC:
      if cpKind == CryptKind.DECRYPT:
        for i in 0 ..< BLOCK:
          sms4Blk[i] = sms4Blk[i] xor goggaIV[i]
        # 使用上一次输入作为解密向量
        goggaIV = blk
      else:
        # 使用上一次输出作为加密向量
        goggaIV = sms4Blk
    reap.add(sms4Blk)

  # 去除填充
  if padding in {PaddingKind.PKCS5, PaddingKind.PKCS7} and cpKind == CryptKind.DECRYPT:
    let padL = reap[^1].int
    if padL <= 0 or padL > BLOCK:
      raise newException(ValueError, "Invalid padding")
    reap.setLen(reap.len() - padL)
  return reap

proc encrypt*(talks: string; sm4K: string;
              padding: PaddingKind = PaddingKind.PKCS7; mode: ModeKind = ModeKind.ECB;
              iv: string = ""): string =
  ## SM4加密
  ## 
  ## Parameters
  ## ----------
  ## talks: UTF-8编码格式的加密文本
  ## sm4K: HEX格式的SM4密钥
  ## padding: padding方式，默认PKCS7，可选PKCS5、PKCS7、NONEPAD
  ## mode: 加密方式，默认ECB，可选CBC、ECB
  ## iv: CBC方式IV向量，默认为空数组
  ## 
  ## Returns
  ## -------
  ## 十六进制加密字符串
  let sm4K = hexToArr(sm4K)
  var ivArr = hexToArr(iv)
  var talkArr = utf8ToArr(talks)
  return arrToHex(sm4(talkArr, sm4K, CryptKind.ENCRYPT, padding, mode, ivArr))

proc encrypt*(talks: var seq[uint8]; sm4K: seq[uint8];
              padding: PaddingKind = PaddingKind.PKCS7; mode: ModeKind = ModeKind.ECB;
              iv: seq[uint8] = newSeq[uint8]()): seq[uint8] =
  ## SM4加密
  ## 
  ## Parameters
  ## ----------
  ## talks: 加密文本的字节数组
  ## sm4K: SM4密钥的字节数组
  ## padding: padding方式，默认PKCS7，可选PKCS5、PKCS7、NONEPAD
  ## mode: 加密方式，默认ECB，可选CBC、ECB
  ## iv: CBC方式IV向量，默认为空数组
  ## 
  ## Returns
  ## -------
  ## 十六进制加密字符串
  return sm4(talks, sm4K, CryptKind.ENCRYPT, padding, mode, iv)

proc decrypt*(talks: string; sm4K: string;
              padding: PaddingKind = PaddingKind.PKCS7; mode: ModeKind = ModeKind.ECB;
              iv: string = ""): string =
  ## SM4解密
  ## 
  ## Parameters
  ## ----------
  ## talks: HEX编码格式的解密文本。如果是字符串，要求
  ## sm4K: HEX格式的SM4密钥
  ## padding: padding方式，默认PKCS7，可选PKCS5、PKCS7、NONEPAD
  ## mode: 解密方式，默认ECB，可选CBC、ECB
  ## iv: CBC方式IV向量，默认为空数组
  ## 
  ## Returns
  ## -------
  ## utf-8编码解密字符串
  let sm4K = hexToArr(sm4K)
  var ivArr = hexToArr(iv)
  var talkArr = hexToArr(talks)
  return arrToUtf8(sm4(talkArr, sm4K, CryptKind.DECRYPT, padding, mode, ivArr))

proc decrypt*(talks: var seq[uint8]; sm4K: seq[uint8];
              padding: PaddingKind = PaddingKind.PKCS7; mode: ModeKind = ModeKind.ECB;
              iv: seq[uint8] = newSeq[uint8]()): seq[uint8] =
  ## SM4解密
  ## 
  ## Parameters
  ## ----------
  ## talks: 解密文本的字节数组
  ## sm4K: SM4密钥的字节数组
  ## padding: padding方式，默认PKCS7，可选PKCS5、PKCS7、NONEPAD
  ## mode: 解密方式，默认ECB，可选CBC、ECB
  ## iv: CBC方式IV向量，默认为空数组
  ## 
  ## Returns
  ## -------
  ## utf-8编码解密字符串
  return sm4(talks, sm4K, CryptKind.DECRYPT, padding, mode, iv)
