from enum import Enum
from .achieve import sm3_digest, sm3_hmac
from ..sm4.util import *


class Sm3ModeKind(Enum):
  Hmac = 1


def sm3_hash(plain_text, sm3_key=None, sm3_mode_kind=None):
  """
  SM3杂凑

  Parameters
  ----------
  plain_text: str | list[int] | bytearray
    明文
  sm3_key: None | str | list[int] | bytearray
    密钥，若杂凑模式为HMAC则必须提供
  sm3_mode_kind: None | Sm3ModeKind
    模式，目前仅支持HMAC

  Returns
  -------
  str | list[int]
    sm3杂凑结果
  """
  need_str = False
  if isinstance(plain_text, str):
    need_str = True
    plain_text = utf8_to_arrs(plain_text)
  plain_text_arrs = bytearray(plain_text)

  if sm3_mode_kind:
    try:
      sm3_mode_kind = Sm3ModeKind(sm3_mode_kind)
    except ValueError:
      raise ValueError(f"Unsupported mode: {sm3_mode_kind}")

    if sm3_mode_kind == Sm3ModeKind.Hmac:
      if not sm3_key:
        raise ValueError("HMAC mode requires a key")
      sm3_key_arrs = bytearray(hex_to_arrs(sm3_key))
      plain_text_arrs = sm3_hmac(sm3_key_arrs, plain_text_arrs)

  if need_str:
    return arrs_to_hex(list(sm3_digest(plain_text_arrs)))
  return list(sm3_digest(plain_text_arrs))


class Sm3:
  @staticmethod
  def hash(plain_text, sm3_key=None, sm3_mode_kind=None):
    """
    SM3杂凑

    Parameters
    ----------
    plain_text: str | list[int] | bytearray
      明文
    sm3_key: None | str | list[int] | bytearray
      密钥，若杂凑模式为HMAC则必须提供
    sm3_mode_kind: None | Sm3ModeKind
      模式，目前仅支持HMAC

    Returns
    -------
    str | list[int]
      sm3杂凑结果
    """
    return sm3_hash(plain_text, sm3_key, sm3_mode_kind)
