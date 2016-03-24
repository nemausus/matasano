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
    def testUnpadding(self):
        self.assertEqual("ICE ICE BABY",
                         Crypto.UnadPkcs7("ICE ICE BABY\x04\x04\x04\x04"))
        self.assertEqual("ICE ICE BABY\x05\x05\x05\x05",
                         Crypto.UnadPkcs7("ICE ICE BABY\x05\x05\x05\x05"))
        self.assertEqual("ICE ICE BABY\x01\x02\x03\x04",
                         Crypto.UnadPkcs7("ICE ICE BABY\x01\x02\x03\x04"))

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
        key = Crypto.GenRandomKey(16)
        aes_ecb = \
            lambda text : Crypto.EncryptAes(text + target, key, AES.MODE_ECB)
        text = Crypto.DecryptsAesEcbByteWise(aes_ecb)
        self.assertEqual(target, text)

    @Logger
    def testPrefixAesEcbDecryptionByteWise(self):
        key = Crypto.GenRandomKey(16)
        prefix = Crypto.GenRandomKey(18)
        target = "This is the target"
        aes_ecb = lambda text : \
            Crypto.EncryptAes(prefix + text + target, key, AES.MODE_ECB)
        text = Crypto.DecryptsAesEcbByteWise(aes_ecb)
        self.assertEqual(target, text)

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


if __name__ == '__main__':
    unittest.main()
