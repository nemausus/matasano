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

    EN_MOST_FREQUENT = ' etaoin'
    EN_AVG_LEN = 4.56
    EN_FREQUENCY = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074]                    # V-Z ]

    @staticmethod
    def GenRandomKey(length=16):
        """Returns random key of given length using base64 character set.
           Default key length is 16."""
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
        return ''.join(map(
            lambda i: alphabet[random.randint(0,63)],
            range(length)
        ))

    @staticmethod
    def GetChiSquaredError(text):
        """Returns Chi-squared error for english text"""
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
        """Checks if given ascii text is valid English.
            check 1: all characters should be printable.
            check 2: top 2 most frequent characters shoule be in ' etaoin'
            check 3: at least 90% letters should be in [a-z ]
            check 4: average word length should be in EN_AVG_LEN +-2 range
        """
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
        """Sequentially apply xor of each byte of the key to text and repeat"""
        xor = []
        for i, char in enumerate(text):
            key_char = key[i%len(key)]
            xor.append(chr(ord(key_char) ^ ord(char)))
        return ''.join(xor)

    @staticmethod
    def GetHammingDistance(text1, text2):
        """Returns hamming distance for two strings of same size."""
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
        """Detects single byte xor cipher from the list of ciphers."""
        for cipher in ciphers:
            text,_ = Crypto.BreakSingleByteXor(cipher)
            if text and Crypto.IsEnglish(text): return text
        return None

    @staticmethod
    def BreakKeyLength(cipher):
        """Returns most promising key length for repeating xor cipher."""
        def GetHammingDistanceAverage(text, key_len):
            # text_len = len(text)
            # num_blocks = int(text_len / (2*key_len))
            # TODO(naresh) : this is a hack
            num_blocks = 10
            left = map(lambda x : x*key_len, range(num_blocks))
            right = map(lambda x : x*key_len + key_len, range(num_blocks))
            block_indices = zip(left, right)

            block = lambda i : text[i:i+key_len]
            dist = lambda (i,j) : Crypto.GetHammingDistance(block(i), block(j))
            return (sum(map(dist, block_indices)) / float(key_len)), key_len

        key_lengths = map(
            lambda key_len : GetHammingDistanceAverage(cipher, key_len),
            range(2, 41))
        key_lengths.sort()
        return key_lengths[0][1]

    @staticmethod
    def BreakRepeatingXor(cipher):
        """Breaks repeating key xor cipher. Returns (plaintext, key)"""
        key_len = Crypto.BreakKeyLength(cipher)
        key = ''.join(map(
            lambda i: Crypto.BreakSingleByteXor(cipher[i::key_len])[1],
            range(0, key_len)))
        return Crypto.GetRepeatingXor(cipher, key), key

    @staticmethod
    def UnadPkcs7(text, bs=16):
        """Unpads text with pkcs7 and returns unpadded text."""
        if len(text) == 0 or len(text) % bs != 0:
            raise ValueError("Input text length is invalid %s" + len(text))
        pad_size = ord(text[-1:])
        if pad_size < bs and all(ord(c) == pad_size for c in text[-pad_size:]):
            return text[:-pad_size]
        return text

    @staticmethod
    def DecryptAes(cipher, key, mode, iv=None):
        """Decrypts AES cipher."""
        iv = iv if iv else Random.new().read(16)
        aes = AES.new(key, mode, iv)
        return Crypto.UnadPkcs7(aes.decrypt(cipher))

    @staticmethod
    def PadPkcs7(text, bs=16):
        """Pads text with pkcs7 and returns padded text."""
        mod = len(text) % bs
        pad_size = bs - mod if mod else 0
        pad_char = chr(pad_size)
        return text + pad_char*pad_size

    @staticmethod
    def EncryptAes(text, key, mode, iv=None):
        """Encrypts AES cipher."""
        iv = iv if iv else Random.new().read(16)
        aes = AES.new(key, mode, iv)
        return aes.encrypt(Crypto.PadPkcs7(text))

    @staticmethod
    def OracleEncryption(text):
        """1) Apply 5-10 random letters at beginning and end of text.
           2) Pick CBC or EBC mode randomly.
           4) Generate 16 byte key randomly.
           3) Apply AEC encryption using above inputs.
           Returns (cipher, mode) pair.
        """
        text = Crypto.GenRandomKey(random.randint(5,10)) + text + \
            Crypto.GenRandomKey(random.randint(5,10))
        mode = AES.MODE_ECB if random.randint(0,1) == 0 else AES.MODE_CBC
        key = Crypto.GenRandomKey(16)
        return Crypto.EncryptAes(text, key, mode), mode

    @staticmethod
    def IsAesEcbCipher(cipher):
        """Checks if given aes cipher is encrypted with ECB mode."""
        num_blocks = len(cipher) / 16
        blocks = map(lambda i: cipher[i*16:i*16+16], range(num_blocks))
        return Counter(blocks).most_common(1)[0][1] > 1

    @staticmethod
    def DecryptsAesEcbByteWise(aes_ecb):
        """Given a block box AES encryption function of this form:
        AES-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
        Finds and returns target-bytes.
        """
        # find length of key and plaintext (prefix + suffix)
        text_len = 0
        key_len = 0
        for i in range(0,64):
            cipher_len = len(aes_ecb('A' * i))
            if text_len and text_len != cipher_len:
                key_len = cipher_len - text_len
                text_len -= (i - 1)
                break
            text_len = cipher_len

        # find length of prefix
        c1 = aes_ecb('a')
        c2 = aes_ecb('b')
        # find which block is different in c1 and c2 which gives us some bound
        # for prefix length
        block_index = 0
        for i in range(0, len(c1)/key_len):
            start = i * key_len
            if c1[start:start+key_len] != c2[start:start+key_len]:
                block_index = i
                break

        # block_index*key_len <= prefix_len < (block_index+1)*key_len
        # Assuming secret text doesn't has '\x00' characters. TODO: fix this
        prefix_len = 0
        last_cipher = ''
        for i in range(1, key_len+2):
            start = block_index * key_len
            cipher = aes_ecb('\x00'*i)[start:start+key_len]
            if cipher == last_cipher:
                prefix_len = (block_index + 1) * key_len - i + 1
                break
            last_cipher = cipher

        # find if this is ECB mode
        text = 'A'*3*key_len
        if not Crypto.IsAesEcbCipher(aes_ecb(text)):
            return None

        suffix_len = text_len - prefix_len
        result = ''
        for i in range(1,suffix_len+1):
            mod = (i  + prefix_len) % key_len
            pad_size = key_len - mod if mod else 0
            known = 'A' * pad_size
            block_index = (prefix_len + pad_size + len(result)) / key_len
            start = block_index * key_len
            # create dictionary
            ciphers = {}
            for c in range(256):
                text = known + result + chr(c)
                ciphers[aes_ecb(text)[start:start+key_len]] = chr(c)
            # discover unknown one character at a time
            cipher = aes_ecb(known)[start:start+key_len]
            result += ciphers[cipher]
        return result

    @staticmethod
    def GetProfile(email):
        email = email.replace('&', '').replace('=', '')
        return "email=%s&uid=10&role=admin" % email

    @staticmethod
    def ParseUrlParams(params):
        """Parse url params to a dictionary."""
        return {k:v for k,v in map(lambda x: x.split('='), params.split('&'))}

