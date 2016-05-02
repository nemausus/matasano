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
from mt19937 import MT19937
from time import time

class TestSet2(unittest.TestCase):

    def Logger(test):
        def func(*args):
            print "\nRunning %s" % test.func_name
            test(*args)
        return func

    @Logger
    def testBreakAesUsingPaddingLeak(self):
        """Challenge 17"""
        quote = lambda text: text
        aes_cbc,key,iv = Crypto.GenerateAesOracle('', '', AES.MODE_CBC, quote)

        def has_valid_padding(cipher, iv):
            try:
                Crypto.DecryptAes(cipher, key, AES.MODE_CBC, iv)
            except ValueError:
                return False
            return True

        lines = map(lambda l : base64.b64decode(l),
                open('data/17.txt').readlines())
        for line in lines:
            cipher = Crypto.EncryptAes(line, key, AES.MODE_CBC, iv)
            self.assertEqual(
                line,
                Crypto.BreakAesUsingPaddingLeak(cipher, iv, has_valid_padding))

    @Logger
    def testAesCtrEncryption(self):
        """Challenge 18"""
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
    def testBreakAesCtrWithFixedNonce1(self):
        """Challenge 19"""
        bs = 16
        key = Crypto.GenRandomKey(bs)
        counter = lambda : chr(25)*bs
        texts = map(lambda l : base64.b64decode(l),
                open('data/19.txt').readlines())
        ciphers = map(
            lambda t : Crypto.EncryptAes(t, key, AES.MODE_CTR, counter=counter),
            texts)
        expected = Crypto.GetRepeatingXor(ciphers[0] , texts[0])[:bs]
        actual = Crypto.BreakAesCtrWithFixedNonce(ciphers, bs)
        self.assertEquals(expected, actual)

    @Logger
    def testBreakAesCtrWithFixedNonce2(self):
        """Challenge 20"""
        bs = 16
        key = Crypto.GenRandomKey(bs)
        counter = lambda : chr(25)*bs
        texts = map(lambda l : base64.b64decode(l),
                open('data/20.txt').readlines())
        ciphers = map(
            lambda t : Crypto.EncryptAes(t, key, AES.MODE_CTR, counter=counter),
            texts)
        expected = Crypto.GetRepeatingXor(ciphers[0], texts[0])[:bs]
        actual = Crypto.BreakAesCtrWithFixedNonce(ciphers, bs)
        self.assertEquals(expected, actual)

    @Logger
    def testMt19937Seed(self):
        """Challenge 22"""
        num = Crypto.GenRandomNumber()
        timenow = int(time())
        found = False
        for seed in range(timenow-1000,timenow):
            if MT19937(seed).extract_number() == num:
                found = True
                break
        self.assertTrue(found)

    @Logger
    def testMt19937Clone(self):
        """Challenge 23"""
        rng = MT19937(int(time()))
        clone = Crypto.CloneMt19937Rng(rng)
        for i in range(624):
            self.assertEquals(rng.extract_number(), clone.extract_number())


if __name__ == '__main__':
    unittest.main()
