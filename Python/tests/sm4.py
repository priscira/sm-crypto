# python -m unittest tests/sm4.py
import unittest
from src.sm4 import *


class TestSm4(unittest.TestCase):
  def test_sm4_func_ecb_string(self):
    sm4_key = "af32409cf34aeef23f4b328a96100ce1"

    cn_talks = "臂上妆犹在，襟间泪尚盈。"
    en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs."

    cn_talks_ecb = encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)
    en_talks_ecb = encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

    self.assertEqual(
      cn_talks_ecb,
      "0fb9045738bf0c9e660743c52753ca36b374a46153697189"
      "0e8143aa1ae425544c0f0f0bee82d5b2518cd9f89c931709"
      )
    self.assertEqual(
      en_talks_ecb,
      "2009305f19f25e5386cb425a44eee723c83bfb72292af287d8df1a9455c24d8ed92b3aa517de87d5"
      "4ebe29fcd5094f1f92a37b147eac20eec83323454fc07e1742f00704d2f76109a7b306b7bb530937"
      )

    self.assertEqual(decrypt(cn_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), cn_talks)
    self.assertEqual(decrypt(en_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), en_talks)

  def test_sm4_class_ecb_string(self):
    sm4_key = "1b4f311bd2765bb23f4b328a0001acfa"
    cn_talks = "此事古难全，但愿人长久，千里共婵娟。"
    en_talks = "Looking back on how it was in years gone by, and the good times that I had."
    sm4 = SM4(sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

    cn_talks_ecb = sm4.encrypt(cn_talks)
    en_talks_ecb = sm4.encrypt(en_talks)

    self.assertEqual(
      cn_talks_ecb,
      "e788d8f6c40326f62e30a6759b4b564159d861e3412ddfb57cf70ba96ecd4397"
      "fdc1466a9304498a3fdb9435e4d19472cc523905c855efb96f765ccd4f0f314c"
      )
    self.assertEqual(
      en_talks_ecb,
      "eb42380be535351f12b8dd67e2eab86bdb49da84b9a26f318dc85378a307a2e857be839019b72ebb"
      "6eb65471b3d029715d6c954683bbd00c8f502b6d7e411155694357fa568eb7f811d657d062cafe19"
      )

    self.assertEqual(sm4.decrypt(cn_talks_ecb), cn_talks)
    self.assertEqual(sm4.decrypt(en_talks_ecb), en_talks)

  def test_sm4_func_ecb_list(self):
    sm4_key = [175, 50, 64, 156, 243, 74, 238, 242, 63, 75, 50, 138, 150, 16, 12, 225]
    cn_talks = [
      232, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156, 168, 239, 188, 140, 232, 165,
      159, 233, 151, 180, 230, 179, 170, 229, 176, 154, 231, 155, 136, 227, 128, 130
      ]
    en_talks = [
      87, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110, 103, 32, 73, 39, 100, 32, 108,
      105, 115, 116, 101, 110, 32, 116, 111, 32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97,
      105, 116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118, 111, 114, 105, 116, 101,
      32, 115, 111, 110, 103, 115, 46,
      ]

    cn_talks_ecb = encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)
    en_talks_ecb = encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

    self.assertEqual(
      cn_talks_ecb, [
        15, 185, 4, 87, 56, 191, 12, 158, 102, 7, 67, 197, 39, 83, 202, 54, 179, 116, 164, 97, 83, 105, 113,
        137, 14, 129, 67, 170, 26, 228, 37, 84, 76, 15, 15, 11, 238, 130, 213, 178, 81, 140, 217, 248, 156,
        147, 23, 9
        ]
      )
    self.assertEqual(
      en_talks_ecb, [
        32, 9, 48, 95, 25, 242, 94, 83, 134, 203, 66, 90, 68, 238, 231, 35, 200, 59, 251, 114, 41, 42, 242,
        135, 216, 223, 26, 148, 85, 194, 77, 142, 217, 43, 58, 165, 23, 222, 135, 213, 78, 190, 41, 252,
        213, 9, 79, 31, 146, 163, 123, 20, 126, 172, 32, 238, 200, 51, 35, 69, 79, 192, 126, 23, 66, 240, 7,
        4, 210, 247, 97, 9, 167, 179, 6, 183, 187, 83, 9, 55
        ]
      )

    self.assertEqual(decrypt(cn_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), cn_talks)
    self.assertEqual(decrypt(en_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), en_talks)

  def test_sm4_class_ecb_list(self):
    sm4_key = [27, 79, 49, 27, 210, 118, 91, 178, 63, 75, 50, 138, 0, 1, 172, 250]
    cn_talks = [
      230, 173, 164, 228, 186, 139, 229, 143, 164, 233, 154, 190, 229, 133, 168, 239, 188, 140, 228, 189,
      134, 230, 132, 191, 228, 186, 186, 233, 149, 191, 228, 185, 133, 239, 188, 140, 229, 141, 131, 233,
      135, 140, 229, 133, 177, 229, 169, 181, 229, 168, 159, 227, 128, 130
      ]
    en_talks = [
      76, 111, 111, 107, 105, 110, 103, 32, 98, 97, 99, 107, 32, 111, 110, 32, 104, 111, 119, 32, 105, 116,
      32, 119, 97, 115, 32, 105, 110, 32, 121, 101, 97, 114, 115, 32, 103, 111, 110, 101, 32, 98, 121, 44,
      32, 97, 110, 100, 32, 116, 104, 101, 32, 103, 111, 111, 100, 32, 116, 105, 109, 101, 115, 32, 116,
      104, 97, 116, 32, 73, 32, 104, 97, 100, 46
      ]
    sm4 = SM4(sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

    cn_talks_ecb = sm4.encrypt(cn_talks)
    en_talks_ecb = sm4.encrypt(en_talks)

    self.assertEqual(
      cn_talks_ecb, [
        231, 136, 216, 246, 196, 3, 38, 246, 46, 48, 166, 117, 155, 75, 86, 65, 89, 216, 97, 227, 65, 45,
        223, 181, 124, 247, 11, 169, 110, 205, 67, 151, 253, 193, 70, 106, 147, 4, 73, 138, 63, 219, 148,
        53, 228, 209, 148, 114, 204, 82, 57, 5, 200, 85, 239, 185, 111, 118, 92, 205, 79, 15, 49, 76
        ]
      )
    self.assertEqual(
      en_talks_ecb, [
        235, 66, 56, 11, 229, 53, 53, 31, 18, 184, 221, 103, 226, 234, 184, 107, 219, 73, 218, 132, 185,
        162, 111, 49, 141, 200, 83, 120, 163, 7, 162, 232, 87, 190, 131, 144, 25, 183, 46, 187, 110, 182,
        84, 113, 179, 208, 41, 113, 93, 108, 149, 70, 131, 187, 208, 12, 143, 80, 43, 109, 126, 65, 17, 85,
        105, 67, 87, 250, 86, 142, 183, 248, 17, 214, 87, 208, 98, 202, 254, 25
        ]
      )

    self.assertEqual(sm4.decrypt(cn_talks_ecb), cn_talks)
    self.assertEqual(sm4.decrypt(en_talks_ecb), en_talks)

  def test_sm4_func_cbc_string(self):
    sm4_key = "fa4f311bd2765bb23f4b328a0001ac00"
    cn_talks = "臂上妆犹在，襟间泪尚盈。"
    en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs."
    iv = "32ef4500ad3ecb2a34dcb09aac34bfea"

    cn_talks_cbc = encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)
    en_talks_cbc = encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

    self.assertEqual(
      cn_talks_cbc,
      "bf484cb9ee733cea62377187ba0cd6cd522a4941ba87a73e"
      "4632fc706a6c3860a00c029d50f611a333d37a6eb73ccc6d"
      )
    self.assertEqual(
      en_talks_cbc,
      "527baf83366542b2a5dab3c6a1808a42bbcf656d194114de4825e4a84e3c407ded4449627652a38"
      "3036f541fb8dfa762bbc2ae0686bf6d204775c1cf342130df251a74ad7ee12ae59248fbcb69ef190d"
      )

    self.assertEqual(decrypt(cn_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), cn_talks)
    self.assertEqual(decrypt(en_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), en_talks)

  def test_sm4_class_cbc_string(self):
    sm4_key = "1b4f311bd2765bb23f4b328a0001acfa"
    cn_talks = "此事古难全，但愿人长久，千里共婵娟。"
    en_talks = "Looking back on how it was in years gone by, and the good times that I had."
    iv = "47ef4500ad3ecb2a34dcb09aac34bf00"
    sm4 = SM4(sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

    cn_talks_cbc = sm4.encrypt(cn_talks)
    en_talks_cbc = sm4.encrypt(en_talks)

    self.assertEqual(
      cn_talks_cbc,
      "58c1b54d7ce38b6338c959bdb70bef69d3d7878a4d184ffd85bfbbf3d8044303"
      "e47d0cb30a465f5c6e6b329bad14e536d8b23c062b6529138edc4d3f968055bd"
      )
    self.assertEqual(
      en_talks_cbc,
      "5180c865ba8c25ffa094c181222a2d3b6d0c8397bf474a5cdae45f2f7f2e108d15e916c55cadabd4"
      "9da2817cebd3d8d7d21885c8467ee865988ccde87689409b40173f1564862a873f774da15f8e1779"
      )

    self.assertEqual(sm4.decrypt(cn_talks_cbc), cn_talks)
    self.assertEqual(sm4.decrypt(en_talks_cbc), en_talks)

  def test_sm4_func_cbc_list(self):
    sm4_key = [250, 79, 49, 27, 210, 118, 91, 178, 63, 75, 50, 138, 0, 1, 172, 0]
    cn_talks = [
      232, 135, 130, 228, 184, 138, 229, 166, 134, 231, 138, 185, 229, 156, 168, 239, 188, 140, 232, 165,
      159, 233, 151, 180, 230, 179, 170, 229, 176, 154, 231, 155, 136, 227, 128, 130
      ]
    en_talks = [
      87, 104, 101, 110, 32, 73, 32, 119, 97, 115, 32, 121, 111, 117, 110, 103, 32, 73, 39, 100, 32, 108,
      105, 115, 116, 101, 110, 32, 116, 111, 32, 116, 104, 101, 32, 114, 97, 100, 105, 111, 44, 32, 119, 97,
      105, 116, 105, 110, 103, 32, 102, 111, 114, 32, 109, 121, 32, 102, 97, 118, 111, 114, 105, 116, 101,
      32, 115, 111, 110, 103, 115, 46,
      ]
    iv = [50, 239, 69, 0, 173, 62, 203, 42, 52, 220, 176, 154, 172, 52, 191, 234]

    cn_talks_cbc = encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)
    en_talks_cbc = encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

    self.assertEqual(
      cn_talks_cbc, [
        191, 72, 76, 185, 238, 115, 60, 234, 98, 55, 113, 135, 186, 12, 214, 205, 82, 42, 73, 65, 186, 135,
        167, 62, 70, 50, 252, 112, 106, 108, 56, 96, 160, 12, 2, 157, 80, 246, 17, 163, 51, 211, 122, 110,
        183, 60, 204, 109
        ]
      )
    self.assertEqual(
      en_talks_cbc, [
        82, 123, 175, 131, 54, 101, 66, 178, 165, 218, 179, 198, 161, 128, 138, 66, 187, 207, 101, 109, 25,
        65, 20, 222, 72, 37, 228, 168, 78, 60, 64, 125, 237, 68, 73, 98, 118, 82, 163, 131, 3, 111, 84, 31,
        184, 223, 167, 98, 187, 194, 174, 6, 134, 191, 109, 32, 71, 117, 193, 207, 52, 33, 48, 223, 37, 26,
        116, 173, 126, 225, 42, 229, 146, 72, 251, 203, 105, 239, 25, 13
        ]
      )

    self.assertEqual(decrypt(cn_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), cn_talks)
    self.assertEqual(decrypt(en_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), en_talks)

  def test_sm4_class_cbc_list(self):
    sm4_key = [27, 79, 49, 27, 210, 118, 91, 178, 63, 75, 50, 138, 0, 1, 172, 250]
    cn_talks = [
      230, 173, 164, 228, 186, 139, 229, 143, 164, 233, 154, 190, 229, 133, 168, 239, 188, 140, 228, 189,
      134, 230, 132, 191, 228, 186, 186, 233, 149, 191, 228, 185, 133, 239, 188, 140, 229, 141, 131, 233,
      135, 140, 229, 133, 177, 229, 169, 181, 229, 168, 159, 227, 128, 130
      ]
    en_talks = [
      76, 111, 111, 107, 105, 110, 103, 32, 98, 97, 99, 107, 32, 111, 110, 32, 104, 111, 119, 32, 105, 116,
      32, 119, 97, 115, 32, 105, 110, 32, 121, 101, 97, 114, 115, 32, 103, 111, 110, 101, 32, 98, 121, 44,
      32, 97, 110, 100, 32, 116, 104, 101, 32, 103, 111, 111, 100, 32, 116, 105, 109, 101, 115, 32, 116,
      104, 97, 116, 32, 73, 32, 104, 97, 100, 46
      ]
    iv = [71, 239, 69, 0, 173, 62, 203, 42, 52, 220, 176, 154, 172, 52, 191, 0]
    sm4 = SM4(sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

    cn_talks_cbc = sm4.encrypt(cn_talks)
    en_talks_cbc = sm4.encrypt(en_talks)

    self.assertEqual(
      cn_talks_cbc, [
        88, 193, 181, 77, 124, 227, 139, 99, 56, 201, 89, 189, 183, 11, 239, 105, 211, 215, 135, 138, 77,
        24, 79, 253, 133, 191, 187, 243, 216, 4, 67, 3, 228, 125, 12, 179, 10, 70, 95, 92, 110, 107, 50,
        155, 173, 20, 229, 54, 216, 178, 60, 6, 43, 101, 41, 19, 142, 220, 77, 63, 150, 128, 85, 189
        ]
      )
    self.assertEqual(
      en_talks_cbc, [
        81, 128, 200, 101, 186, 140, 37, 255, 160, 148, 193, 129, 34, 42, 45, 59, 109, 12, 131, 151, 191,
        71, 74, 92, 218, 228, 95, 47, 127, 46, 16, 141, 21, 233, 22, 197, 92, 173, 171, 212, 157, 162, 129,
        124, 235, 211, 216, 215, 210, 24, 133, 200, 70, 126, 232, 101, 152, 140, 205, 232, 118, 137, 64,
        155, 64, 23, 63, 21, 100, 134, 42, 135, 63, 119, 77, 161, 95, 142, 23, 121
        ]
      )

    self.assertEqual(sm4.decrypt(cn_talks_cbc), cn_talks)
    self.assertEqual(sm4.decrypt(en_talks_cbc), en_talks)


if __name__ == "__main__":
  unittest.main()
