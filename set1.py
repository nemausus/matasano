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

class Crypto(object):

    EN_MOST_FREQUENT = '. etaoinshrd'
    EN_AVG_LEN = 4.56
    EN_FREQUENCY = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074]                    # V-Z ]

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
    def DetectSingleByteXorCipher(ciphers):
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
    def DecryptAes(cipher, key, mode):
        iv = Random.new().read(16)
        mode = AES.MODE_ECB if mode == "ecb" else AES.MODE_CFB
        aes = AES.new(key, mode, iv)
        unpad = lambda s : s[:-ord(s[len(s)-1:])]
        return unpad(aes.decrypt(cipher))

    @staticmethod
    def IsAesEcbCipher(cipher):
        num_blocks = len(cipher) / 16
        blocks = map(lambda i: cipher[i*16:i*16+16], range(num_blocks))
        return Counter(blocks).most_common(1)[0][1] > 1


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
        _, key = Crypto.BreakRepeatingXor(cipher)
        self.assertEqual("Terminator X: Bring the noise", key)

    @Logger
    def testAesEcbMode(self):
        cipher = base64.b64decode(open("7.txt").read())
        key = 'YELLOW SUBMARINE'
        text = Crypto.DecryptAes(cipher, key, "ecb")
        expected = Crypto.GetRepeatingXor(
            base64.b64decode(open("6.txt").read()),
            "Terminator X: Bring the noise")
        self.assertEqual(expected, text)

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
