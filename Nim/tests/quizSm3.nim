# testament p "tests/quizSm3.nim"

discard """
  action: "run"
  targets: "cpp"
"""
import std/[strutils]
import "smCrypto"


proc quizSm3HashWithoutHmac() =
  let sm3Quin = Sm3()
  let sm3HashReap = sm3Quin.sm3Hash("hello world")
  echo "quizSm3HashWithoutHmac ", sm3HashReap
  assert sm3HashReap == "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88".toUpperAscii()


proc quizSm3HashWithHmac() = 
  let sm3Quin = Sm3()
  var sm3HashReap = sm3Quin.sm3Hash("hello world", "abe12300985eef", Sm3ModeKind.Hmac)
  assert sm3HashReap == "1b14935d91305eb7a91cec2f16b6bbe75112498c804591c3200633632972632c".toUpperAscii()
  sm3HashReap = sm3Quin.sm3Hash(
    "hello world",
    "daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e" &
    "0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9".toUpperAscii(),
    Sm3ModeKind.Hmac
  )
  echo "quizSm3HashWithHmac ", sm3HashReap
  assert sm3HashReap == "6693881715637cc7f347bc7cdb5bdd86f65c3076388bf45f84b1ac276a647095".toUpperAscii()


quizSm3HashWithoutHmac()
quizSm3HashWithHmac()
