def hex_to_arrs(hex_talks):
  """
  十六进制字符串转成数组

  Parameters
  ----------
  hex_talks: str
    十六进制字符串

  Returns
  -------
  list[int]
    十六进制字符串各字节对应的整数组成的数组
  """
  return list(bytes.fromhex(hex_talks))


def arrs_to_hex(hex_arrs):
  """
  字节数组转十六进制字符串

  Parameters
  ----------
  hex_arrs: list[int]
    字节数组

  Returns
  -------
  str
    十六进制字符串
  """
  return bytes(hex_arrs).hex()


def utf8_to_arrs(talks):
  """
  utf-8字符串转成数组

  Parameters
  ----------
  talks: str
    utf-8字符串

  Returns
  -------
  list[int]
    utf-8字符串各字节对应的整数组成的数组
  """
  return list(talks.encode('utf-8'))


def arrs_to_utf8(arrs):
  """
  字节数组转utf-8字符串

  Parameters
  ----------
  arrs: list[int]
    字节数组

  Returns
  -------
  str
    utf-8字符串
  """
  return bytes(arrs).decode('utf-8', errors='strict')
