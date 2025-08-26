import "./achieve"
import "../sm4/util"


type Sm3ModeKind* {.pure.} = enum 
  Hmac


type Sm3* = object


proc sm3Hash*(sm3: Sm3, plainTxtArrs: seq[uint8]): seq[uint8] =
  ## 无模式SM3杂凑
  ## 
  ## Parameters
  ## ----------
  ## plain_text: 明文，支持字节数组类型
  ## 
  ## Returns
  ## -------
  ## SM3杂凑值
  sm3Digest(plainTxtArrs)


proc sm3Hash*(sm3: Sm3, plainTxt: string): string =
  ## 无模式SM3杂凑
  ## 
  ## Parameters
  ## ----------
  ## plain_text: 明文，支持字符串类型
  ## 
  ## Returns
  ## -------
  ## SM3杂凑值
  arrToHex(sm3Digest(utf8ToArr(plainTxt)))


proc sm3Hash*(sm3: Sm3, plainTxtArrs: seq[uint8], sm3KArrs: seq[uint8], sm3ModeKind: Sm3ModeKind): seq[uint8] =
  ## SM3杂凑
  ## 
  ## Parameters
  ## ----------
  ## plain_text: 明文，支持字节数组类型
  ## sm3_key: 密钥，支持字节数组类型，若杂凑模式为HMAC则必须提供
  ## sm3_mode_kind: 模式，目前仅支持HMAC
  ## 
  ## Returns
  ## -------
  ## SM3杂凑值
  if sm3ModeKind != Sm3ModeKind.Hmac:
    raise newException(ValueError, "Sm3 can only support HMAC mode")
  var plainTxtArrs = sm3Hmac(sm3KArrs, plainTxtArrs)
  return sm3.sm3Hash(plainTxtArrs)


proc sm3Hash*(sm3: Sm3, plainTxt: string, sm3K: string, sm3ModeKind: Sm3ModeKind): string =
  ## SM3杂凑
  ## 
  ## Parameters
  ## ----------
  ## plain_text: 明文，支持字符串类型
  ## sm3_key: 密钥，若杂凑模式为HMAC则必须提供
  ## sm3_mode_kind: 模式，目前仅支持HMAC
  ## 
  ## Returns
  ## -------
  ## SM3杂凑值
  var plainTxtArrs = utf8ToArr(plainTxt)
  var sm3KArrs = hexToArr(sm3K)
  return arrToHex(sm3.sm3Hash(plainTxtArrs, sm3KArrs, sm3ModeKind))
