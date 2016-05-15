#! /usr/bin/env python
# author : Naresh Kumar
"""Tests for set 3 solutions."""

import base64
import unittest
from time import time

from Crypto.Cipher import AES
from crypto import Crypto
from crypto import logger
from frequency_analyzer import FrequencyAnalyzer
from mt19937 import MT19937RNG
from mt19937 import MT19937Cipher

class TestSet3(unittest.TestCase):
    """Tests for set 3 solutions."""

    @logger
    def test_break_aes_padding_leak(self):
        """Challenge 17"""
        quote = lambda text: text
        _, key, init_vector = Crypto.generate_aes_oracle(
            '', '', AES.MODE_CBC, quote)

        def has_valid_padding(cipher, init_vector):
            """Checks if cipher has valid padding."""
            try:
                Crypto.decrypt_aes(cipher, key, AES.MODE_CBC, init_vector)
            except ValueError:
                return False
            return True

        lines = [base64.b64decode(l) for l in open('data/17.txt').readlines()]
        for line in lines:
            cipher = Crypto.encrypt_aes(line, key, AES.MODE_CBC, init_vector)
            self.assertEqual(line, Crypto.break_aes_using_padding_leak(
                cipher, init_vector, has_valid_padding))

    @logger
    def test_aes_ctr_encryption(self):
        """Challenge 18"""
        counter = Crypto.gen_aes_stream_counter_simple()
        key = "YELLOW SUBMARINE"
        cipher = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLX" +\
                "zhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        text = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        self.assertEqual(text, Crypto.decrypt_aes(
            cipher, key, AES.MODE_CTR, counter=counter))
        # another test
        key = Crypto.gen_random_key(16)
        text = "Let there be light!"
        counter = Crypto.gen_aes_stream_counter_simple()
        cipher = Crypto.encrypt_aes(text, key, AES.MODE_CTR, counter=counter)
        counter = Crypto.gen_aes_stream_counter_simple()
        self.assertEqual(text, Crypto.decrypt_aes(
            cipher, key, AES.MODE_CTR, counter=counter))

    @logger
    def test_break_aes_ctr_fixed_nonce1(self):
        """Challenge 19"""
        block_size = 16
        quote = lambda t: t
        counter = lambda: chr(25)*block_size
        aes_ctr, _ = Crypto.generate_aes_oracle(
            '', '', AES.MODE_CTR, quote, block_size, counter)
        texts = [base64.b64decode(l) for l in open('data/19.txt').readlines()]
        ciphers = [aes_ctr(text) for text in texts]
        expected = FrequencyAnalyzer.get_repeating_xor(
            ciphers[0], texts[0])[:block_size]
        actual = Crypto.break_aes_ctr_with_fixed_nonce(ciphers, block_size)
        self.assertEquals(expected, actual)

    @logger
    def test_break_aes_ctr_fixed_nonce2(self):
        """Challenge 20"""
        block_size = 16
        quote = lambda t: t
        counter = lambda: chr(25)*block_size
        aes_ctr, _ = Crypto.generate_aes_oracle(
            '', '', AES.MODE_CTR, quote, block_size, counter)
        texts = [base64.b64decode(l) for l in open('data/20.txt').readlines()]
        ciphers = [aes_ctr(text) for text in texts]
        expected = FrequencyAnalyzer.get_repeating_xor(
            ciphers[0], texts[0])[:block_size]
        actual = Crypto.break_aes_ctr_with_fixed_nonce(ciphers, block_size)
        self.assertEquals(expected, actual)

    @logger
    def test_mt19937_seed(self):
        """Challenge 22"""
        num = Crypto.gen_random_number()
        timenow = int(time())
        found = False
        for seed in range(timenow-1000, timenow):
            if MT19937RNG(seed).next() == num:
                found = True
                break
        self.assertTrue(found)

    @logger
    def test_mt19937_clone(self):
        """Challenge 23"""
        rng = MT19937RNG(int(time()))
        clone = MT19937RNG.clone(rng)
        for _ in range(624):
            self.assertEquals(rng.next(), clone.next())

    @logger
    def test_break_rng_stream_cipher(self):
        """Challenge 24"""
        seed_str = Crypto.gen_random_key(2)
        seed = ord(seed_str[0]) << 8 | ord(seed_str[1])
        mt_cipher = MT19937Cipher(seed)
        prefix = Crypto.gen_random_key(23)
        text = 'A'*14
        cipher = mt_cipher.encrypt(prefix + text)
        self.assertEquals(seed, Crypto.break_rng_stream_cipher(cipher, text))

if __name__ == '__main__':
    unittest.main(verbosity=0)
