# testament p "tests/quiz_sm4.nim"

discard """
  action: "run"
"""
import std/sequtils
import sm4/sm4


proc quizSm4TalkEcb() =
  let
    sm4K = "af32409cf34aeef23f4b328a96100ce1"
    cnTalks = "臂上妆犹在，襟间泪尚盈。"
    enTalks = "When I was young I'd listen to the radio, waiting for my favorite songs."

  let sm4Quin: Sm4 = Sm4()

  let
    cnTalksEcb = sm4Quin.encrypt(cnTalks, sm4K)
    enTalksEcb = sm4Quin.encrypt(enTalks, sm4K)

  assert cnTalksEcb == "0FB9045738BF0C9E660743C52753CA36B374A46153697189" &
                       "0E8143AA1AE425544C0F0F0BEE82D5B2518CD9F89C931709"
  assert enTalksEcb == "2009305F19F25E5386CB425A44EEE723C83BFB72292AF287D8DF1" &
                       "A9455C24D8ED92B3AA517DE87D54EBE29FCD5094F1F92A37B147E" &
                       "AC20EEC83323454FC07E1742F00704D2F76109A7B306B7BB530937"

  assert cnTalks == sm4Quin.decrypt(cnTalksEcb, sm4K)
  assert enTalks == sm4Quin.decrypt(enTalksEcb, sm4K)


proc quizSm4ArrEcb() =
  let
    sm4KArr: seq[uint8] = toSeq([175'u8, 50, 64, 156, 243, 74, 238, 242, 63, 75, 50, 138, 150, 16, 12, 225])
  var
    cnArrs: seq[uint8] = toSeq([232'u8, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156,
                                168, 239, 188, 140, 232, 165, 159, 233, 151, 180, 230, 179, 170, 229,
                                176, 154, 231, 155, 136, 227, 128, 130])
    enArrs: seq[uint8] = toSeq([87'u8, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110,
                                103, 32, 73, 39, 100, 32, 108, 105, 115, 116, 101, 110, 32, 116, 111,
                                32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97, 105,
                                116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118,
                                111, 114, 105, 116, 101, 32, 115, 111, 110, 103, 115, 46])

  let sm4Quin: Sm4 = Sm4()

  # 自己决定后续是否还需要使用旧值
  var
    cnArrsStale = toSeq(cnArrs)
    enArrsStale = toSeq(enArrs)

  var
    cnArrsEcb = sm4Quin.encrypt(cnArrs, sm4KArr)
    enArrsEcb = sm4Quin.encrypt(enArrs, sm4KArr)

  assert cnArrsEcb == toSeq([15'u8, 185, 4, 87, 56, 191, 12, 158, 102, 7, 67, 197, 39, 83, 202, 54, 179,
                             116, 164, 97, 83, 105, 113, 137, 14, 129, 67, 170, 26, 228, 37, 84, 76, 15,
                             15, 11, 238, 130, 213, 178, 81, 140, 217, 248, 156, 147, 23, 9])
  assert enArrsEcb == toSeq([32'u8, 9, 48, 95, 25, 242, 94, 83, 134, 203, 66, 90, 68, 238, 231, 35, 200,
                             59, 251, 114, 41, 42, 242, 135, 216, 223, 26, 148, 85, 194, 77, 142, 217,
                             43, 58, 165, 23, 222, 135, 213, 78, 190, 41, 252, 213, 9, 79, 31, 146, 163,
                             123, 20, 126, 172, 32, 238, 200, 51, 35, 69, 79, 192, 126, 23, 66, 240, 7,
                             4, 210, 247, 97, 9, 167, 179, 6, 183, 187, 83, 9, 55])

  assert cnArrsStale == sm4Quin.decrypt(cnArrsEcb, sm4KArr)
  assert enArrsStale == sm4Quin.decrypt(enArrsEcb, sm4KArr)


proc quizSm4TalkCbc() =
  let
    sm4K = "fa4f311bd2765bb23f4b328a0001ac00"
    cnTalks = "臂上妆犹在，襟间泪尚盈。"
    enTalks = "When I was young I'd listen to the radio, waiting for my favorite songs."
    iv = "32ef4500ad3ecb2a34dcb09aac34bfea"

  let sm4Quin: Sm4 = Sm4()

  let
    cnTalksCbc = sm4Quin.encrypt(cnTalks, sm4K, PaddingKind.PKCS7, ModeKind.CBC, iv)
    enTalksCbc = sm4Quin.encrypt(enTalks, sm4K, PaddingKind.PKCS7, ModeKind.CBC, iv)

  assert cnTalksCbc == "BF484CB9EE733CEA62377187BA0CD6CD522A4941BA87A73E" &
                       "4632FC706A6C3860A00C029D50F611A333D37A6EB73CCC6D"
  assert enTalksCbc == "527BAF83366542B2A5DAB3C6A1808A42BBCF656D194114DE4825E" &
                       "4A84E3C407DED4449627652A383036F541FB8DFA762BBC2AE0686" &
                       "BF6D204775C1CF342130DF251A74AD7EE12AE59248FBCB69EF190D"

  assert cnTalks == sm4Quin.decrypt(cnTalksCbc, sm4K, PaddingKind.PKCS7, ModeKind.CBC, iv)
  assert enTalks == sm4Quin.decrypt(enTalksCbc, sm4K, PaddingKind.PKCS7, ModeKind.CBC, iv)


proc quizSm4ArrCbc() =
  let
    sm4KArr: seq[uint8] = toSeq([250'u8, 79, 49, 27, 210, 118, 91, 178, 63, 75, 50, 138, 0, 1, 172, 0])
    ivArrs: seq[uint8] = toSeq([50'u8, 239, 69, 0, 173, 62, 203, 42, 52, 220, 176, 154, 172, 52, 191, 234])

  let sm4Quin: Sm4 = Sm4()

  var
    cnArrs: seq[uint8] = toSeq([232'u8, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156,
                                168, 239, 188, 140, 232, 165, 159, 233, 151, 180, 230, 179, 170, 229,
                                176, 154, 231, 155, 136, 227, 128, 130])
    enArrs: seq[uint8] = toSeq([87'u8, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110,
                                103, 32, 73, 39, 100, 32, 108, 105, 115, 116, 101, 110, 32, 116, 111,
                                32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97, 105,
                                116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118,
                                111, 114, 105, 116, 101, 32, 115, 111, 110, 103, 115, 46])

  # 自己决定后续是否还需要使用旧值
  var
    cnArrsStale = toSeq(cnArrs)
    enArrsStale = toSeq(enArrs)

  var
    cnArrsCbc = sm4Quin.encrypt(cnArrs, sm4KArr, PaddingKind.PKCS7, ModeKind.CBC, ivArrs)
    enArrsCbc = sm4Quin.encrypt(enArrs, sm4KArr, PaddingKind.PKCS7, ModeKind.CBC, ivArrs)

  assert cnArrsCbc == toSeq([191'u8, 72, 76, 185, 238, 115, 60, 234, 98, 55, 113, 135, 186, 12, 214, 205,
                             82, 42, 73, 65, 186, 135, 167, 62, 70, 50, 252, 112, 106, 108, 56, 96, 160, 12,
                             2, 157, 80, 246, 17, 163, 51, 211, 122, 110, 183, 60, 204, 109])
  assert enArrsCbc == toSeq([82'u8, 123, 175, 131, 54, 101, 66, 178, 165, 218, 179, 198, 161, 128, 138, 66,
                             187, 207, 101, 109, 25, 65, 20, 222, 72, 37, 228, 168, 78, 60, 64, 125, 237,
                             68, 73, 98, 118, 82, 163, 131, 3, 111, 84, 31, 184, 223, 167, 98, 187, 194,
                             174, 6, 134, 191, 109, 32, 71, 117, 193, 207, 52, 33, 48, 223, 37, 26, 116,
                             173, 126, 225, 42, 229, 146, 72, 251, 203, 105, 239, 25, 13])

  assert cnArrsStale == sm4Quin.decrypt(cnArrsCbc, sm4KArr, PaddingKind.PKCS7, ModeKind.CBC, ivArrs)
  assert enArrsStale == sm4Quin.decrypt(enArrsCbc, sm4KArr, PaddingKind.PKCS7, ModeKind.CBC, ivArrs)


quizSm4TalkEcb()
quizSm4ArrEcb()
quizSm4TalkCbc()
quizSm4ArrCbc()
