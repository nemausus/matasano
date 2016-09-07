#! /usr/bin/env python
# author : Naresh Kumar
"""Stream Crypto and Randomness."""

import base64
import hashlib
import unittest
import urllib
from time import time

from Crypto.Cipher import AES
from Crypto.Hash import MD4
from crypto import Crypto
from crypto import logger
from frequency_analyzer import FrequencyAnalyzer
from mt19937 import MT19937RNG
from mt19937 import MT19937Cipher
from sha1 import add_padding
from sha1 import extend_sha
from sha1 import sha1
from sha1 import Sha1Hash
from md4 import MD4Hash

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

    @logger
    def test_ctr_bit_flipping(self):
        """Challenge 26"""
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        counter = Crypto.gen_aes_stream_counter_mt19973(3453243);
        oracle, key = Crypto.generate_aes_oracle(
            prefix, suffix, AES.MODE_CTR, urllib.quote, 16, counter=counter)

        def has_admin(cipher):
            """Checks if cipher has admin."""
            counter = Crypto.gen_aes_stream_counter_mt19973(3453243);
            text = Crypto.decrypt_aes(cipher, key, AES.MODE_CTR, counter=counter)
            return text.find(';admin=true;') != -1

        self.assertTrue(Crypto.flip_cipher_to_add_admin_ctr(oracle, has_admin))

    @logger
    def test_break_if_iv_is_same_as_key(self):
        """Challenge 27"""
        key = Crypto.gen_random_key(16)
        iv = key
        oracle = lambda c: Crypto.decrypt_aes(c, key, AES.MODE_CBC, iv)
        cipher = Crypto.encrypt_aes("X"*48, key, AES.MODE_CBC, iv)
        self.assertEquals(key,
                Crypto.extract_key_if_key_is_same_as_key(cipher, oracle))

    @logger
    def test_sha1(self):
        """Challenge 28"""
        text = "naresh"
        m = hashlib.sha1()
        m.update(text)
        self.assertEquals(m.hexdigest(), sha1(text))

    @logger
    def test_sha_length_extension(self):
        """Challenge 29"""
        orig_message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        # this is not known to attacker.
        key = Crypto.gen_random_key(100)
        suffix = ';admin=true;'
        orig_sha = Sha1Hash().update(key + orig_message).digest()
        forged_message = add_padding(key + orig_message) + suffix
        forged_sha = Sha1Hash().update(forged_message).digest()
        validate = lambda sha: sha == forged_sha
        self.assertTrue(extend_sha(orig_sha, orig_message, suffix, validate))

    @logger
    def test_md4(self):
        """Challenge 30"""
        text = "naresh"
        m = MD4.new()
        m.update(text)
        self.assertEquals(m.digest(), MD4Hash().update(text).digest())

if __name__ == '__main__':
    unittest.main(verbosity=0)
