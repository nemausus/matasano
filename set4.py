#! /usr/bin/env python
# author : Naresh Kumar
"""Stream Crypto and Randomness."""

import base64
import unittest
from time import time

from Crypto.Cipher import AES
from crypto import Crypto
from crypto import logger
from frequency_analyzer import FrequencyAnalyzer
from mt19937 import MT19937RNG
from mt19937 import MT19937Cipher

class TestSet4(unittest.TestCase):
    """Tests for set 4 solutions."""

    @logger
    def test_break_random_access_read_write(self):
        """Challenge 25"""
        f = open('data/25.txt')
        data = f.read()
        f.close()
        key = 'YELLOW SUBMARINE'
        known = Crypto.decrypt_aes(base64.b64decode(data), key, AES.MODE_ECB)
        seed = 23232232;
        def edit(cipher, offset, newtext):
            counter = Crypto.gen_aes_stream_counter_mt19973(seed);
            text = Crypto.decrypt_aes(
                    cipher, key, AES.MODE_CTR, counter=counter)
            text = text[:offset] + newtext + text[offset + 1:]
            counter = Crypto.gen_aes_stream_counter_mt19973(seed);
            return Crypto.encrypt_aes(text, key, AES.MODE_CTR, counter=counter)

        def edit_fast(cipher, newtext):
            counter = Crypto.gen_aes_stream_counter_mt19973(seed);
            text = Crypto.decrypt_aes(
                    cipher, key, AES.MODE_CTR, counter=counter)
            text = newtext
            counter = Crypto.gen_aes_stream_counter_mt19973(seed);
            return Crypto.encrypt_aes(text, key, AES.MODE_CTR, counter=counter)

        counter = Crypto.gen_aes_stream_counter_mt19973(seed);
        cipher = Crypto.encrypt_aes(known, key, AES.MODE_CTR, counter=counter)
        text = edit_fast(cipher, cipher)
        # replacing text with cipher is same is decrypting cipher.
        #for i in range(len(cipher)):
        #    text += edit(cipher, i, cipher[i])[i]

        self.assertEqual(known, text)


if __name__ == '__main__':
    unittest.main(verbosity=0)