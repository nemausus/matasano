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

    @Logger
    def testAesCtrEncryption(self):
        counter = Crypto.GenAesStreamCounter()
        key = "YELLOW SUBMARINE"
        cipher = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLX" +\
                "zhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        text = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        self.assertEqual(
            text, Crypto.DecryptAes(cipher, key, AES.MODE_CTR, counter=counter))
        # another test
        key = Crypto.GenRandomKey(16)
        text = "Let there be light!"
        counter = Crypto.GenAesStreamCounter()
        cipher = Crypto.EncryptAes(text, key, AES.MODE_CTR, counter=counter)
        counter = Crypto.GenAesStreamCounter()
        self.assertEqual(
            text, Crypto.DecryptAes(cipher, key, AES.MODE_CTR, counter=counter))

    @Logger
    def testBreakAesCtrWithFixedNonce(self):
        key = Crypto.GenRandomKey(16)
        counter = lambda : chr(0)*16
        texts = map(lambda l : base64.b64decode(l), open('19.txt').readlines())
        ciphers = map(
            lambda t : Crypto.EncryptAes(t, key, AES.MODE_CTR, counter=counter),
            texts)
        expected = Crypto.GetRepeatingXor(ciphers[0] , texts[0])[:16]
        actual = Crypto.BreakAesCtrWithFixedNonce(ciphers)
        if expected != actual:
            print sum(map(lambda (a,b): a == b, zip(expected, actual)))
        self.assertEquals(expected, actual)


if __name__ == '__main__':
    unittest.main()
