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

class TestSet1(unittest.TestCase):

    def Logger(test):
        def func(*args):
            print "Running %s" % test.func_name
            test(*args)
        return func

    @Logger
    def testHexToBase64(self):
        """Challenge 1"""
        expected, hex_str = Crypto.GetLines('data/1.txt')
        actual = Crypto.HexToBase64(hex_str)
        self.assertEqual(expected, actual)

    @Logger
    def testFixedXor(self):
        """Challenge 2"""
        expected = '746865206b696420646f6e277420706c6179'
        actual = Crypto.GetFixedXor('1c0111001f010100061a024b53535009181c',
                                    '686974207468652062756c6c277320657965')
        self.assertEqual(expected, actual)

    @Logger
    def testBreakSingleByteXor(self):
        """Challenge 3"""
        expected = "Cooking MC's like a pound of bacon"
        hex_str = Crypto.GetLines('data/3.txt')[0]
        cipher = binascii.unhexlify(hex_str)
        text, key = Crypto.BreakSingleByteXor(cipher)
        self.assertEqual(expected, text)

    @Logger
    def testDetectSingleByteXor(self):
        """Challenge 4"""
        expected = 'Now that the party is jumping\n'
        ciphers = map(
            lambda line: binascii.unhexlify(line.replace('\n', '')),
            open('data/4.txt').readlines()
        )
        self.assertEqual(expected, Crypto.DetectSingleByteXor(ciphers))

    @Logger
    def testGetRepeatingXor(self):
        """Challenge 5"""
        expected, one, two = Crypto.GetLines('data/5.txt')
        xor = Crypto.GetRepeatingXor(one + '\n' + two, "ICE")
        self.assertEqual(expected, binascii.hexlify(xor))

    @Logger
    def testGetHammingDistance(self):
        dist = Crypto.GetHammingDistance('this is a test', 'wokka wokka!!!')
        self.assertEqual(37, dist)

    @Logger
    def testBreakRepeatingXor(self):
        """Challenge 6"""
        cipher = base64.b64decode(open("data/6.txt").read())
        actual = Crypto.GetRepeatingXor(cipher, "Terminator X: Bring the noise")
        text, key = Crypto.BreakRepeatingXor(cipher)
        self.assertEqual("Terminator X: Bring the noise", key)
        self.assertEqual(open('data/plaintext.txt').read(), text)

    @Logger
    def testAesDecryptionEcbMode(self):
        """Challenge 7"""
        cipher = base64.b64decode(open("data/7.txt").read())
        key = 'YELLOW SUBMARINE'
        text = Crypto.DecryptAes(cipher, key, AES.MODE_ECB)
        self.assertEqual(open('data/plaintext.txt').read(), text)

    @Logger
    def testDetectAesEcbCipher(self):
        """Challenge 8"""
        ciphers = Crypto.GetLines("data/8.txt")
        num_detected = 0
        for cipher in ciphers:
            if Crypto.IsAesEcbCipher(binascii.unhexlify(cipher)):
                num_detected += 1
        self.assertEqual(1, num_detected)

if __name__ == '__main__':
    unittest.main(verbosity=0)
