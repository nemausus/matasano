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
            print "\nRunning %s" % test.func_name
            test(*args)
        return func

    @Logger
    def testHexToBase64(self):
        expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        actual = Crypto.ConvertHexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
        self.assertEqual(expected, actual)

    @Logger
    def testFixedXor(self):
        expected = '746865206b696420646f6e277420706c6179'
        actual = Crypto.GetFixedXor('1c0111001f010100061a024b53535009181c',
                                    '686974207468652062756c6c277320657965')
        self.assertEqual(expected, actual)

    @Logger
    def testBreakSingleByteXor(self):
        expected = "Cooking MC's like a pound of bacon"
        hex_str =  "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        cipher = binascii.unhexlify(hex_str)
        text, key = Crypto.BreakSingleByteXor(cipher)
        self.assertEqual(expected, text)

    @Logger
    def testDetectSingleByteXorCipher(self):
        expected = 'Now that the party is jumping\n'
        ciphers = map(
            lambda line: binascii.unhexlify(line.replace('\n', '')),
            open('4.txt').readlines()
        )
        self.assertEqual(expected, Crypto.DetectSingleByteXorCipher(ciphers))

    @Logger
    def testGetRepeatingXor(self):
        expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        xor = Crypto.GetRepeatingXor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
        self.assertEqual(expected, binascii.hexlify(xor))

    @Logger
    def testGetHammingDistance(self):
        dist = Crypto.GetHammingDistance('this is a test', 'wokka wokka!!!')
        self.assertEqual(37, dist)

    @Logger
    def testBreakRepeatingXor(self):
        cipher = base64.b64decode(open("6.txt").read())
        actual = Crypto.GetRepeatingXor(cipher, "Terminator X: Bring the noise")
        text, key = Crypto.BreakRepeatingXor(cipher)
        self.assertEqual("Terminator X: Bring the noise", key)
        self.assertEqual(open('plaintext.txt').read(), text)

    @Logger
    def testAesEcbMode(self):
        cipher = base64.b64decode(open("7.txt").read())
        key = 'YELLOW SUBMARINE'
        text = Crypto.DecryptAes(cipher, key, AES.MODE_ECB)
        self.assertEqual(open('plaintext.txt').read(), text)

    @Logger
    def testDetectAesEcbCipher(self):
        content = open("8.txt").readlines()
        ciphers = map(lambda x: x.replace('\n', ''), content)
        num_detected = 0
        for cipher in ciphers:
            if Crypto.IsAesEcbCipher(binascii.unhexlify(cipher)):
                num_detected += 1
        self.assertEqual(1, num_detected)

if __name__ == '__main__':
    unittest.main()
