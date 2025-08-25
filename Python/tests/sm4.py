# python -m unittest tests/sm4.py
import unittest
from src import Sm4, Sm4ModeKind, Sm4PaddingKind


class TestSm4(unittest.TestCase):
  def test_sm4_ecb_string(self):
    sm4_key = "1b4f311bd2765bb23f4b328a0001acfa"
    cn_talks = "此事古难全，但愿人长久，千里共婵娟。"
    en_talks = "Looking back on how it was in years gone by, and the good times that I had."
    sm4 = Sm4()

    cn_talks_ecb = sm4.encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)
    en_talks_ecb = sm4.encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

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

    self.assertEqual(
      sm4.decrypt(cn_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), cn_talks
      )
    self.assertEqual(
      sm4.decrypt(en_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), en_talks
      )

  def test_sm4_ecb_list(self):
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
    sm4 = Sm4()

    cn_talks_ecb = sm4.encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)
    en_talks_ecb = sm4.encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None)

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

    self.assertEqual(
      sm4.decrypt(cn_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), cn_talks
      )
    self.assertEqual(
      sm4.decrypt(en_talks_ecb, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.ECB, None), en_talks
      )

  def test_sm4_cbc_string(self):
    sm4_key = "fa4f311bd2765bb23f4b328a0001ac00"
    cn_talks = "臂上妆犹在，襟间泪尚盈。"
    en_talks = "When I was young I'd listen to the radio, waiting for my favorite songs."
    iv = "32ef4500ad3ecb2a34dcb09aac34bfea"
    sm4 = Sm4()

    cn_talks_cbc = sm4.encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)
    en_talks_cbc = sm4.encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

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

    self.assertEqual(
      sm4.decrypt(cn_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), cn_talks
      )
    self.assertEqual(
      sm4.decrypt(en_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), en_talks
      )

  def test_sm4_cbc_list(self):
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
    sm4 = Sm4()

    cn_talks_cbc = sm4.encrypt(cn_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)
    en_talks_cbc = sm4.encrypt(en_talks, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv)

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

    self.assertEqual(
      sm4.decrypt(cn_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), cn_talks
      )
    self.assertEqual(
      sm4.decrypt(en_talks_cbc, sm4_key, Sm4PaddingKind.PKCS7, Sm4ModeKind.CBC, iv), en_talks
      )


if __name__ == "__main__":
  unittest.main()
