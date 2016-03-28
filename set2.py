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
    def testPadding(self):
        text = "YELLOW SUBMARINE"
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(expected, Crypto.PadPkcs7(text, 20))
        text = "1234567890123456"
        self.assertEqual(text + '\x10'*16, Crypto.PadPkcs7(text, 16))

    @Logger
    def testUnpadding(self):
        self.assertEqual(
            "ICE ICE BABY", Crypto.UnadPkcs7("ICE ICE BABY\x04\x04\x04\x04"))
        self.assertRaises(
            ValueError, Crypto.UnadPkcs7, "ICE ICE BABY\x05\x05\x05\x05")
        self.assertRaises(
            ValueError, Crypto.UnadPkcs7, "ICE ICE BABY\x01\x02\x03\x04")

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
        target = base64.b64decode(unknown)
        quote = lambda text: text
        oracle,_,_ = Crypto.GenerateAesOracle('', target, AES.MODE_ECB, quote)
        text = Crypto.DecryptsAesEcbByteWise(oracle)
        self.assertEqual(target, text)

    @Logger
    def testPrefixAesEcbDecryptionByteWise(self):
        prefix = Crypto.GenRandomKey(18)
        target = "This is the target"
        quote = lambda text: text
        oracle,_,_ = Crypto.GenerateAesOracle(prefix, target, AES.MODE_ECB, quote)
        self.assertEqual(target, Crypto.DecryptsAesEcbByteWise(oracle))

        target = "A"*16
        oracle,_,_ = Crypto.GenerateAesOracle(prefix, target, AES.MODE_ECB, quote)
        self.assertEqual(target, Crypto.DecryptsAesEcbByteWise(oracle))

    @Logger
    def testParseUrlParams(self):
        params = Crypto.ParseUrlParams("foo=bar&baz=qux&zap=zazzle")
        self.assertEqual(3, len(params))
        self.assertEqual('bar', params['foo'])
        self.assertEqual('qux', params['baz'])
        self.assertEqual('zazzle', params['zap'])

    @Logger
    def testGetProfile(self):
        self.assertEqual(
            'email=foo@bar.com&uid=10&role=admin',
            Crypto.GetProfile('foo&=@bar.com'))

    @Logger
    def testCbcBitFlipping(self):
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        oracle, key, _ = Crypto.GenerateAesOracle(
            prefix, suffix, AES.MODE_CBC, urllib.quote)

        def has_admin(cipher):
            text = Crypto.DecryptAes(cipher, key, AES.MODE_CBC)
            return text.find(';admin=true;') != -1

        self.assertTrue(Crypto.FlipCipherToAddAdmin(oracle, has_admin))


if __name__ == '__main__':
    unittest.main()
