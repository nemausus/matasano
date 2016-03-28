#! /usr/bin/env python
# author : Naresh Kumar

import binascii
import base64
import random
import string
import sys
import unittest
import urllib
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
    def testBreakAesUsingPaddingLeak(self):
        quote = lambda text: text
        aes_cbc,key,iv = Crypto.GenerateAesOracle('', '', AES.MODE_CBC, quote)

        def has_valid_padding(cipher, iv):
            try:
                Crypto.DecryptAes(cipher, key, AES.MODE_CBC, iv)
            except ValueError:
                return False
            return True

        lines = map(lambda l : base64.b64decode(l), open('17.txt').readlines())
        for line in lines:
            cipher = Crypto.EncryptAes(line, key, AES.MODE_CBC, iv)
            self.assertEqual(
                line,
                Crypto.BreakAesUsingPaddingLeak(cipher, iv, has_valid_padding))


if __name__ == '__main__':
    unittest.main()
