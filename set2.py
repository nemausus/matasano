#! /usr/bin/env python
# author : Naresh Kumar

import binascii
import base64
import random
import string
import sys
import unittest
from collections import Counter
from Crypto.Cipher import AES
from Crypto import Random
from crypto import Crypto

class TestSet2(unittest.TestCase):

    def Logger(test):
        def func(*args):
            print "\nRunning %s" % test.func_name
            test(*args)
        return func

    @Logger
    def testPadding(self):
        text = "YELLOW SUBMARINE"
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(expected, Crypto.PadPkcs7(text, 20))
        text = "1234567890123456"
        self.assertEqual(text, Crypto.PadPkcs7(text, 16))

    @Logger
    def testAesDecryptionCbcMode(self):
        cipher = base64.b64decode(open("10.txt").read())
        iv = '\x00'*16
        text = Crypto.DecryptAes(cipher, "YELLOW SUBMARINE", AES.MODE_CBC, iv)
        self.assertEqual(open('plaintext.txt').read(), text)

    @Logger
    def testAesEcbCbcMode(self):
        text = open('plaintext.txt').read()
        for i in range(20):
            cipher, mode = Crypto.OracleEncryption(text)
            expected = True if mode == AES.MODE_ECB else False
            self.assertEqual(expected, Crypto.IsAesEcbCipher(cipher))

    @Logger
    def testAesEcbDecryptionByteWise(self):
        unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                   YnkK"
        unknown = base64.b64decode(unknown)
        key = Crypto.GenRandomKey(16)
        append_and_encrypt = \
            lambda text : Crypto.EncryptAes(text + unknown, key, AES.MODE_ECB)
        text = Crypto.DecryptsAesEcbByteWise(append_and_encrypt)
        self.assertEqual(unknown, text)


if __name__ == '__main__':
    unittest.main()
