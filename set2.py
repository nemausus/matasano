#! /usr/bin/env python
# author : Naresh Kumar
"""Block Crypto."""

import base64
import unittest
import urllib
from Crypto.Cipher import AES
from crypto import Crypto
from crypto import logger

class TestSet2(unittest.TestCase):
    """Tests for set 2 solutions."""

    @logger
    def test_padding(self):
        """Challenge 9"""
        text = "YELLOW SUBMARINE"
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(expected, Crypto.pad_pkcs7(text, 20))
        text = "1234567890123456"
        self.assertEqual(text + '\x10'*16, Crypto.pad_pkcs7(text, 16))

    @logger
    def test_unpadding(self):
        """Tests for unpadding."""
        self.assertEqual(
            "ICE ICE BABY", Crypto.unpad_pkcs7("ICE ICE BABY\x04\x04\x04\x04"))
        self.assertRaises(
            ValueError, Crypto.unpad_pkcs7, "ICE ICE BABY\x05\x05\x05\x05")
        self.assertRaises(
            ValueError, Crypto.unpad_pkcs7, "ICE ICE BABY\x01\x02\x03\x04")

    @logger
    def test_cbc_using_ecb(self):
        """Challenge 10"""
        cipher = base64.b64decode(open("data/10.txt").read())
        key = "YELLOW SUBMARINE"
        text = Crypto.decrypt_cbc_using_ecb(cipher, key)
        self.assertEqual(open('data/plaintext.txt').read(), text)
        self.assertEquals(cipher, Crypto.encrypt_cbc_using_ecb(text, key))

    @logger
    def test_ecb_or_cbc_mode(self):
        """Challenge 11"""
        text = open('data/plaintext.txt').read()
        for _ in range(20):
            cipher, mode = Crypto.oracle_encryption(text)
            expected = True if mode == AES.MODE_ECB else False
            self.assertEqual(expected, Crypto.is_aes_ecb_cipher(cipher))

    @logger
    def test_aes_ecb_decryption(self):
        """Challenge 12"""
        data = Crypto.get_lines('data/12.txt')[0]
        target = base64.b64decode(data)
        quote = lambda text: text
        oracle, _, _ = Crypto.generate_aes_oracle(
            '', target, AES.MODE_ECB, quote)
        text = Crypto.decrypts_aes_ecb_byte_wise(oracle)
        self.assertEqual(target, text)

    @logger
    def test_prefix_aes_ecb_decryption(self):
        """Challenge 14"""
        prefix = Crypto.gen_random_key(18)
        target = "This is the target"
        quote = lambda text: text
        oracle, _, _ = Crypto.generate_aes_oracle(
            prefix, target, AES.MODE_ECB, quote)
        self.assertEqual(target, Crypto.decrypts_aes_ecb_byte_wise(oracle))

        target = "A"*16
        oracle, _, _ = Crypto.generate_aes_oracle(
            prefix, target, AES.MODE_ECB, quote)
        self.assertEqual(target, Crypto.decrypts_aes_ecb_byte_wise(oracle))

    @logger
    def test_cbc_bit_flipping(self):
        """Challenge 16"""
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        oracle, key, _ = Crypto.generate_aes_oracle(
            prefix, suffix, AES.MODE_CBC, urllib.quote)

        def has_admin(cipher):
            """Checks if cipher has admin."""
            text = Crypto.decrypt_aes(cipher, key, AES.MODE_CBC)
            return text.find(';admin=true;') != -1

        self.assertTrue(Crypto.flip_cipher_to_add_admin(oracle, has_admin))


if __name__ == '__main__':
    unittest.main(verbosity=0)
