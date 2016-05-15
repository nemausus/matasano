#! /usr/bin/env python
# author : Naresh Kumar

import binascii
import base64
from collections import Counter
import random
import string
import sys
from time import time
import unittest
import urllib

from Crypto.Cipher import AES
from Crypto import Random
from crypto import Crypto
from mt19937 import MT19937
from mt19937_cipher import MT19937Cipher

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
        counter = Crypto.GenAesStreamCounterSimple()
        key = "YELLOW SUBMARINE"
        cipher = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLX" +\
                "zhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        text = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        self.assertEqual(
            text, Crypto.DecryptAes(cipher, key, AES.MODE_CTR, counter=counter))
        # another test
        key = Crypto.GenRandomKey(16)
        text = "Let there be light!"
        counter = Crypto.GenAesStreamCounterSimple()
        cipher = Crypto.EncryptAes(text, key, AES.MODE_CTR, counter=counter)
        counter = Crypto.GenAesStreamCounterSimple()
        self.assertEqual(
            text, Crypto.DecryptAes(cipher, key, AES.MODE_CTR, counter=counter))

    @Logger
    def testBreakAesCtrWithFixedNonce1(self):
        """Challenge 19"""
        bs = 16
        quote = lambda t : t
        counter = lambda : chr(25)*bs
        aes_ctr, key = Crypto.GenerateAesOracle(
            '', '', AES.MODE_CTR, quote, bs, counter)
        texts = map(lambda l : base64.b64decode(l),
            open('data/19.txt').readlines())
        ciphers = map(aes_ctr, texts)
        expected = Crypto.GetRepeatingXor(ciphers[0], texts[0])[:bs]
        actual = Crypto.BreakAesCtrWithFixedNonce(ciphers, bs)
        self.assertEquals(expected, actual)

    @Logger
    def testBreakAesCtrWithFixedNonce2(self):
        """Challenge 20"""
        bs = 16
        quote = lambda t : t
        counter = lambda : chr(25)*bs
        aes_ctr, key = Crypto.GenerateAesOracle(
            '', '', AES.MODE_CTR, quote, bs, counter)
        texts = map(lambda l : base64.b64decode(l),
            open('data/20.txt').readlines())
        ciphers = map(aes_ctr, texts)
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
            if MT19937(seed).next() == num:
                found = True
                break
        self.assertTrue(found)

    @Logger
    def testMt19937Clone(self):
        """Challenge 23"""
        rng = MT19937(int(time()))
        clone = Crypto.CloneMt19937Rng(rng)
        for i in range(624):
            self.assertEquals(rng.next(), clone.next())

    @Logger
    def testBreakRNGStreamCipher(self):
        """Challenge 24"""
        seed_str = Crypto.GenRandomKey(2)
        seed = ord(seed_str[0]) << 8 | ord(seed_str[1])
        mt_cipher = MT19937Cipher(seed)
        prefix = Crypto.GenRandomKey(23)
        text = 'A'*14
        cipher = mt_cipher.encrypt(prefix + text)
        self.assertEquals(seed, Crypto.BreakRngStreamCipher(cipher, text))

if __name__ == '__main__':
    unittest.main()
