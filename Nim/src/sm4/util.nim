import std/[strutils, sequtils]


proc hexToArr*(hexStr: string): seq[uint8] =
  ## 十六进制字符串转成数组
  let hexStrL = hexStr.len div 2
  return toSeq(0 ..< hexStrL).map(
    proc(i: int): uint8 = uint8(parseHexInt(hexStr[i * 2 ..< i * 2 + 2]))
  )


proc arrToHex*(hexArrs: openArray[uint8]): string =
  ## 字节数组转十六进制字符串
  var hexTalks = ""
  for hexArri in hexArrs:
    hexTalks.add(hexArri.toHex(2))
  return hexTalks


proc utf8ToArr*(utfTalks: string): seq[uint8] =
  ## utf-8字符串转成数组
  return cast[seq[uint8]](utfTalks)


proc arrToUtf8*(utfArrs: openArray[uint8]): string =
  ## 字节数组转utf-8字符串
  return cast[string](utfArrs.toSeq)
