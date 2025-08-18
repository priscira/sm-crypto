from enum import Enum
from .util import *

ROUND = 32
BLOCK = 16

SBOX = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28,
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

CK = [
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
  0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
  0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
  0x484f565d, 0x646b7279
  ]


class _Sm4CryptoKind(Enum):
  ENCRYPT = 'e'
  DECRYPT = 'd'


class Sm4ModeKind(Enum):
  ECB = 'ecb'
  CBC = 'cbc'


class Sm4PaddingKind(Enum):
  PKCS5 = 'pkcs5'
  PKCS7 = 'pkcs7'
  NONE = 'none'


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
  ) & 0xFFFFFFFF


def _byte_sub(number):
  """
  非线性变换，逐字节查s盒

  Parameters
  ----------
  number: int

  Returns
  -------
  int
    s盒变换结果
  """
  return (
    (SBOX[(number >> 24) & 0xFF] << 24) | (SBOX[(number >> 16) & 0xFF] << 16) |
    (SBOX[(number >> 8) & 0xFF] << 8) | SBOX[number & 0xFF]
  ) & 0xFFFFFFFF


def _l1(number):
  """
  线性变换l，用于给轮函数加密/解密

  Parameters
  ----------
  number: int

  Returns
  -------
  int
  """
  return (
    number ^
    _rotl(number, 2) ^ _rotl(number, 10) ^ _rotl(number, 18) ^ _rotl(
    number,
    24
    )
  )


def _l2(number):
  """
  线性变换l'，扩展密钥

  Parameters
  ----------
  number: int

  Returns
  -------
  int
  """
  return number ^ _rotl(number, 13) ^ _rotl(number, 23)


def _sms4_crypt(block, round_keys):
  """
  对16字节明/密文块执行一次SMS4轮变换

  Parameters
  ----------
  block: list[int]
    16字节明文或密文块
  round_keys: list[int]
    轮密钥

  Returns
  -------
  list[int]
    SMS4轮变换结果
  """
  # 每32bit处理为一个字
  words = [(
             (block[4 * i] << 24) | (block[4 * i + 1] << 16) |
             (block[4 * i + 2] << 8) | block[4 * i + 3]
           ) & 0xFFFFFFFF for i in range(4)]

  for round_keyi in round_keys:
    gogga = words[1] ^ words[2] ^ words[3] ^ round_keyi
    word_to_4 = words[0] ^ _l1(_byte_sub(gogga))
    words = [words[1], words[2], words[3], word_to_4]

  # 反序并拆回字节
  results = []
  for wordi in reversed(words):
    results.extend(
      [
        (wordi >> 24) & 0xFF,
        (wordi >> 16) & 0xFF,
        (wordi >> 8) & 0xFF,
        wordi & 0xFF
        ]
      )
  return results


def _sms4_key_ext(master_key, crypt_flag):
  """
  密钥扩展，将128比特的密钥变成32个32比特的轮密钥

  Parameters
  ----------
  master_key: list[int]
    128比特主密钥
  crypt_flag: _Sm4CryptoKind
    加密或者解密

  Returns
  -------
  list[int]
    32个32比特的轮密钥
  """
  # 每32bit处理为一个字
  words = [(
             (master_key[4 * i] << 24) | (master_key[4 * i + 1] << 16) |
             (master_key[4 * i + 2] << 8) | master_key[4 * i + 3]
           ) & 0xFFFFFFFF for i in range(4)]

  words[0] ^= 0xa3b1bac6
  words[1] ^= 0x56aa3350
  words[2] ^= 0x677d9197
  words[3] ^= 0xb27022dc

  round_key = []
  for i in range(32):
    googa = words[1] ^ words[2] ^ words[3] ^ CK[i]
    word_to_4 = words[0] ^ _l2(_byte_sub(googa))
    round_key.append(word_to_4)
    words = [words[1], words[2], words[3], word_to_4]

  if crypt_flag == _Sm4CryptoKind.DECRYPT:
    round_key.reverse()

  return round_key


def _sm4(
  texts, sm4_key, crypt_flag, padding=Sm4PaddingKind.PKCS7, mode=Sm4ModeKind.ECB, iv=None
  ):
  """
  SM4加/解密主要逻辑

  Parameters
  ----------
  texts: list[int]
    加密文本或者解密文本。如果是字符串，加密要求UTF-8编码格式，解密要求HEX格式
  sm4_key: str | bytes | list[int]
    SM4密钥，如果是字符串需要满足HEX格式，否则应该提供字节数组
  crypt_flag: _Sm4CryptoKind
    加密或者解密
  padding: Sm4PaddingKind
    padding方式，默认pkcs7，可选pkcs5、pkcs7、None
  mode: Sm4ModeKind
    加/解密方式，默认ecb，可选cbc、ecb、None
  iv: str | list[int]
    CBC方式IV向量，默认为空数组

  Returns
  -------
  list[int]
    加密或解密的字节数组
  """
  if not iv:
    iv = []

  if mode == Sm4ModeKind.CBC:
    if isinstance(iv, str):
      iv = hex_to_arrs(iv)
    if len(iv) != BLOCK:
      raise ValueError('iv is invalid (must be 16 bytes)')

  if isinstance(sm4_key, str):
    sm4_key = hex_to_arrs(sm4_key)
  else:
    sm4_key = list(sm4_key)
  if len(sm4_key) != BLOCK:
    raise ValueError('key is invalid (must be 16 bytes)')

  # 新增填充，sm4规定16字节作为一个分组，统一pkcs7
  if padding in (Sm4PaddingKind.PKCS5, Sm4PaddingKind.PKCS7) and crypt_flag != _Sm4CryptoKind.DECRYPT:
    pad_len = BLOCK - (len(texts) % BLOCK)
    texts.extend([pad_len] * pad_len)

  # 轮密钥
  round_keys = _sms4_key_ext(sm4_key, crypt_flag)

  # 分块加/解密
  reaps = []
  temp_ivs = iv.copy()
  for offset in range(0, len(texts), BLOCK):
    blocks = texts[offset: offset + BLOCK]

    if mode == Sm4ModeKind.CBC and crypt_flag != _Sm4CryptoKind.DECRYPT:
      blocks = [
        blocki ^ temp_ivi for blocki, temp_ivi in zip(blocks, temp_ivs)
        ]

    sms4_blocks = _sms4_crypt(blocks, round_keys)

    if mode == Sm4ModeKind.CBC:
      if crypt_flag == _Sm4CryptoKind.DECRYPT:
        sms4_blocks = [
          sms4_blocki ^ temp_ivi
          for sms4_blocki, temp_ivi in zip(sms4_blocks, temp_ivs)
          ]
        # 使用上一次输入作为解密向量
        temp_ivs = blocks
      else:
        # 使用上一次输出作为加密向量
        temp_ivs = sms4_blocks

    reaps.extend(sms4_blocks)

  # 去除填充
  if padding in (Sm4PaddingKind.PKCS5, Sm4PaddingKind.PKCS7) and crypt_flag == _Sm4CryptoKind.DECRYPT:
    pad_len = reaps[-1]
    if (
      pad_len <= 0 or pad_len > BLOCK or
      reaps[-pad_len:] != [pad_len] * pad_len
    ):
      raise ValueError('padding is invalid')
    reaps = reaps[:-pad_len]

  return reaps


def encrypt(plain_text, sm4_key, padding=Sm4PaddingKind.PKCS7, mode=Sm4ModeKind.ECB, iv=None):
  """
  SM4加密

  Parameters
  ----------
  plain_text: str | bytes | list[int]
    加密文本。如果是字符串，要求UTF-8编码格式
  sm4_key: str | bytes | list[int]
    SM4密钥，如果是字符串需要满足HEX格式，否则应该提供字节数组
  padding: Sm4PaddingKind
    padding方式，默认pkcs7，可选pkcs5、pkcs7、None
  mode: Sm4ModeKind
    加/解密方式，默认ecb，可选cbc、ecb、None
  iv: str | list[int] | None
    CBC方式IV向量，默认为空数组

  Returns
  -------
  str | list[int]
    加密结果，如果plain_text是字符串，则返回十六进制字符串，否则返回字节数组
  """
  need_str = False
  if isinstance(plain_text, str):
    # 加密输出为utf8字节数组
    plain_text = utf8_to_arrs(plain_text)
    need_str = True
  else:
    plain_text = list(plain_text)
  encrypted_text = _sm4(
    plain_text, sm4_key, _Sm4CryptoKind.ENCRYPT,
    padding=padding, mode=mode, iv=iv
    )
  if need_str:
    # 加密，输出十六进制串
    return arrs_to_hex(encrypted_text)
  return encrypted_text


def decrypt(cipher_text, sm4_key, padding=Sm4PaddingKind.PKCS7, mode=Sm4ModeKind.ECB, iv=None):
  """
  SM4解密

  Parameters
  ----------
  cipher_text: str | bytes | list[int]
    解密文本。如果是字符串，要求HEX格式
  sm4_key: str | bytes | list[int]
    SM4密钥，如果是字符串需要满足HEX格式，否则应该提供字节数组
  padding: Sm4PaddingKind
    padding方式，默认pkcs7，可选pkcs5、pkcs7、None
  mode: Sm4ModeKind
    加/解密方式，默认ecb，可选cbc、ecb、None
  iv: str | list[int] | None
    CBC方式IV向量，默认为空数组

  Returns
  -------
  str | list[int]
    解密结果，如果cipher_text是字符串，则返回utf8字符串，否则返回字节数组
  """
  need_str = False
  if isinstance(cipher_text, str):
    # 解密输出为十六进制字节数组
    cipher_text = hex_to_arrs(cipher_text)
    need_str = True
  else:
    cipher_text = list(cipher_text)
  decrypted_text = _sm4(
    cipher_text, sm4_key, _Sm4CryptoKind.DECRYPT,
    padding=padding, mode=mode, iv=iv
    )
  if need_str:
    # 解密，输出utf8串
    return arrs_to_utf8(decrypted_text)
  return decrypted_text


class SM4:
  def __init__(self, sm4_key, padding=Sm4PaddingKind.PKCS7, mode=Sm4ModeKind.ECB, iv=None):
    self.sm4_key = sm4_key
    self.padding = padding
    self.mode = mode
    self.iv = iv

  def encrypt(self, plain_text):
    """
    SM4加密

    Parameters
    ----------
    plain_text: str | bytes | list[int]
      加密文本。如果是字符串，要求UTF-8编码格式

    Returns
    -------
    str | list[int]
      加密结果，如果plain_text是字符串，则返回十六进制字符串，否则返回字节数组
    """
    return encrypt(plain_text, self.sm4_key, padding=self.padding, mode=self.mode, iv=self.iv)

  def decrypt(self, cipher_text):
    """
    SM4解密

    Parameters
    ----------
    cipher_text: str | bytes | list[int]
      解密文本。如果是字符串，要求HEX格式

    Returns
    -------
    str | list[int]
      解密结果，如果cipher_text是字符串，则返回utf8字符串，否则返回字节数组
    """
    return decrypt(cipher_text, self.sm4_key, padding=self.padding, mode=self.mode, iv=self.iv)
