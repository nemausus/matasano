#! /usr/bin/env python
# author : Naresh Kumar
"""Tests for set1 solutions."""

import binascii
import base64
import unittest
from Crypto.Cipher import AES
from crypto import Crypto
from crypto import logger
from frequency_analyzer import FrequencyAnalyzer

class TestSet1(unittest.TestCase):
    """Tests for set1 solutions."""


    @logger
    def test_hex_to_base64(self):
        """Challenge 1"""
        expected, hex_str = Crypto.get_lines('data/1.txt')
        ascii_str = binascii.unhexlify(hex_str)
        # b2a_base64 appends a new line to result
        actual = binascii.b2a_base64(ascii_str)[:-1]
        self.assertEqual(expected, actual)

    @logger
    def test_fixed_xor(self):
        """Challenge 2"""
        expected = binascii.unhexlify('746865206b696420646f6e277420706c6179')
        actual = FrequencyAnalyzer.get_repeating_xor(
            binascii.unhexlify('1c0111001f010100061a024b53535009181c'),
            binascii.unhexlify('686974207468652062756c6c277320657965'))
        self.assertEqual(expected, actual)

    @logger
    def test_break_single_byte_xor(self):
        """Challenge 3"""
        expected = "Cooking MC's like a pound of bacon"
        hex_str = Crypto.get_lines('data/3.txt')[0]
        cipher = binascii.unhexlify(hex_str)
        text, _ = FrequencyAnalyzer.break_single_byte_xor(cipher)
        self.assertEqual(expected, text)

    @logger
    def test_detect_single_byte_xor(self):
        """Challenge 4"""
        expected = 'Now that the party is jumping\n'
        ciphers = [binascii.unhexlify(line.replace('\n', ''))
                   for line in open('data/4.txt').readlines()]
        self.assertEqual(expected, Crypto.detect_single_byte_xor(ciphers))

    @logger
    def test_get_repeating_xor(self):
        """Challenge 5"""
        expected, one, two = Crypto.get_lines('data/5.txt')
        xor = FrequencyAnalyzer.get_repeating_xor(one + '\n' + two, "ICE")
        self.assertEqual(expected, binascii.hexlify(xor))

    @logger
    def test_get_hamming_distance(self):
        """Tests @get_hamming_distance"""
        dist = Crypto.get_hamming_distance('this is a test', 'wokka wokka!!!')
        self.assertEqual(37, dist)

    @logger
    def test_break_repeating_xor(self):
        """Challenge 6"""
        cipher = base64.b64decode(open("data/6.txt").read())
        text, key = Crypto.break_repeating_xor(cipher)
        self.assertEqual("Terminator X: Bring the noise", key)
        self.assertEqual(open('data/plaintext.txt').read(), text)

    @logger
    def test_aes_decryption_ecb_mode(self):
        """Challenge 7"""
        cipher = base64.b64decode(open("data/7.txt").read())
        key = 'YELLOW SUBMARINE'
        text = Crypto.decrypt_aes(cipher, key, AES.MODE_ECB)
        self.assertEqual(open('data/plaintext.txt').read(), text)

    @logger
    def test_detect_aes_ecb_cipher(self):
        """Challenge 8"""
        ciphers = Crypto.get_lines("data/8.txt")
        num_detected = 0
        for cipher in ciphers:
            if Crypto.is_aes_ecb_cipher(binascii.unhexlify(cipher)):
                num_detected += 1
        self.assertEqual(1, num_detected)

if __name__ == '__main__':
    unittest.main(verbosity=0)
