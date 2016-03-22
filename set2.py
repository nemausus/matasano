#! /usr/bin/env python
# author : Naresh Kumar

import binascii
import base64
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

    @Logger
    def testAesCbcMode(self):
        cipher = base64.b64decode(open("10.txt").read())
        iv = '\x00'*16
        text = Crypto.DecryptAes(cipher, "YELLOW SUBMARINE", AES.MODE_CBC, iv)
        self.assertEqual(open('plaintext.txt').read(), text)

if __name__ == '__main__':
    unittest.main()
