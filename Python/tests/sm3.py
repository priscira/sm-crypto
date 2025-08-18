# python -m unittest tests/sm3.py
import unittest
from src.sm3 import *


class TestSm3(unittest.TestCase):
  def test_sm3_hash_without_hmac(self):
    sm3_obj = Sm3()
    sm3_hash_reap = sm3_obj.hash("hello world", None, None)
    print("sm3_hash_reap: {}".format(sm3_hash_reap))
    self.assertEqual(sm3_hash_reap, "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88")

  def test_sm3_hash_with_hmac(self):
    sm3_obj = Sm3()
    sm3_hash_reap = sm3_obj.hash("hello world", "abe12300985eef", Sm3ModeKind.Hmac)
    print("sm3_hash_reap: {}".format(sm3_hash_reap))
    self.assertEqual(sm3_hash_reap, "1b14935d91305eb7a91cec2f16b6bbe75112498c804591c3200633632972632c")

    sm3_hash_reap = sm3_obj.hash(
      "hello world",
      "daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e"
      "0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9",
      Sm3ModeKind.Hmac
      )
    self.assertEqual(sm3_hash_reap, "6693881715637cc7f347bc7cdb5bdd86f65c3076388bf45f84b1ac276a647095")
    print("sm3_hash_reap: {}".format(sm3_hash_reap))
