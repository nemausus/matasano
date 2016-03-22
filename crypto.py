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

class Crypto(object):

    EN_MOST_FREQUENT = '. etaoinshrd'
    EN_AVG_LEN = 4.56
    EN_FREQUENCY = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074]                    # V-Z ]

    @staticmethod
    def GenRandomKey(length=16):
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
        return ''.join(map(
            lambda i: alphabet[random.randint(0,63)],
            range(length)
        ))

    @staticmethod
    def GetChiSquaredError(text):
        text = text.lower()
        frequency = Counter(text)
        error = 0.0
        text_len = len(text)
        alpha = 0
        for c in string.lowercase:
            expected = Crypto.EN_FREQUENCY[ord(c) - ord('a')]
            observed = frequency[c] / float(text_len)
            error += (expected - observed)**2 / expected
            alpha += frequency[c]

        # Add error for space
        observed = text.count(' ') / float(text_len)
        expected = 1.0 / 1.0 + Crypto.EN_AVG_LEN
        error += (expected - observed)**2 / expected

        # Add error for non alpha characters
        observed = alpha / float(text_len)
        expected = 0.8
        error += (expected - observed)**2 / expected
        return error

    @staticmethod
    def IsEnglish(text):
        "Checks if given ascii text is valid English."
        text = text.lower()
        # check if all characters are printable
        if not all(c in string.printable for c in text):
            return False
        # check if 2 most common letters in text are among English's most
        # frequent letters.
        frequency = Counter(text)
        if not all(c in Crypto.EN_MOST_FREQUENT for c,_ in frequency.most_common(2)):
            return False
        # check if at least 90% of letters are among a-z and space.
        myset = 'abcdefghijklmnopqrstuvwxyz '
        count = sum(map(lambda c: 1 if c in myset else 0, text))
        if not count/float(len(text)) > 0.90:
            return False
        # check if average word length in text is close to average word length
        # of English.
        word_len = len(text)/float(len(text.split()))
        diff = abs(word_len - Crypto.EN_AVG_LEN)
        if diff > 2.0:
            return False
        return True

    @staticmethod
    def ConvertHexToBase64(hex_str):
        """Converts hex string to base64 string."""
        ascii_str = binascii.unhexlify(hex_str)
        # b2a_base64 appends a new line to result
        return binascii.b2a_base64(ascii_str)[:-1]

    @staticmethod
    def GetFixedXor(hex1, hex2):
        """Performs xor on two fixed size hex strings."""
        ascii1 = binascii.unhexlify(hex1)
        ascii2 = binascii.unhexlify(hex2)
        xor = ''.join(map(lambda a,b : chr(ord(a)^ord(b)), ascii1, ascii2))
        return binascii.hexlify(xor)

    @staticmethod
    def GetRepeatingXor(text, key):
        """Sequentially apply each byte of the key to text and repeat"""
        xor = []
        for i, char in enumerate(text):
            key_char = key[i%len(key)]
            xor.append(chr(ord(key_char) ^ ord(char)))
        return ''.join(xor)

    @staticmethod
    def GetHammingDistance(text1, text2):
        xor = map(lambda a,b : bin(ord(a) ^ ord(b)).count("1"), text1, text2)
        return sum(xor)

    @staticmethod
    def BreakSingleByteXor(cipher):
        """Breaks single byte xor cipher. Returns (text,key) on success."""

        errors = []
        for key in range(1,256):
            text = Crypto.GetRepeatingXor(cipher, chr(key))
            if all(c in string.printable for c in text):
                errors.append((Crypto.GetChiSquaredError(text), chr(key)))

        if len(errors) == 0:
            return None, None
        else:
            errors.sort()
            key = errors[0][1]
            return Crypto.GetRepeatingXor(cipher, key), key

    @staticmethod
    def DetectSingleByteXor(ciphers):
        """Detects single byte xor cipher."""
        for cipher in ciphers:
            text,_ = Crypto.BreakSingleByteXor(cipher)
            if text and Crypto.IsEnglish(text): return text
        return None

    @staticmethod
    def BreakKeyLength(cipher):
        def GetHammingDistanceAverage(text, key_len):
            # text_len = len(text)
            # num_blocks = int(text_len / (2*key_len))
            # TODO(naresh) : this is a hack
            num_blocks = 10
            left = map(lambda x : x*key_len, range(num_blocks))
            right = map(lambda x : x*key_len + key_len, range(num_blocks))
            blocks = zip(left, right)

            dist = sum(map(lambda (i,j) : Crypto.GetHammingDistance(text[i:i+key_len], text[j:j+key_len]), blocks))
            return (dist / float(key_len)), key_len

        key_lengths = [GetHammingDistanceAverage(cipher, key_len) for key_len in range(2, 41)]
        key_lengths.sort()
        return key_lengths[0][1]

    @staticmethod
    def BreakRepeatingXor(cipher):
        key_len = Crypto.BreakKeyLength(cipher)
        key = ''.join(map(
            lambda i: Crypto.BreakSingleByteXor(cipher[i::key_len])[1],
            range(0, key_len)))
        return Crypto.GetRepeatingXor(cipher, key), key

    @staticmethod
    def DecryptAes(cipher, key, mode, iv=None):
        iv = iv if iv else Random.new().read(16)
        aes = AES.new(key, mode, iv)
        unpad = lambda s : s[:-ord(s[len(s)-1:])]
        return unpad(aes.decrypt(cipher))

    @staticmethod
    def EncryptAes(text, key, mode, iv=None):
        iv = iv if iv else Random.new().read(16)
        aes = AES.new(key, mode, iv)
        return aes.encrypt(Crypto.PadPkcs7(text))

    @staticmethod
    def IsAesEcbCipher(cipher):
        num_blocks = len(cipher) / 16
        blocks = map(lambda i: cipher[i*16:i*16+16], range(num_blocks))
        return Counter(blocks).most_common(1)[0][1] > 1

    @staticmethod
    def PadPkcs7(text, bs=16):
        pad_size = bs - len(text) % bs
        pad_char = chr(pad_size)
        return text + pad_char*pad_size

