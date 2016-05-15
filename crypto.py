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
from mt19937 import MT19937
from mt19937_cipher import MT19937Cipher
from time import time

class Crypto(object):

    EN_MOST_FREQUENT = ' etaoin'
    EN_AVG_LEN = 4.56
    EN_FREQUENCY = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074]                    # V-Z ]

    EN_BIGRAMS = {'th':0.0356, 'he':0.0307, 'in':0.0243, 'er':0.0205,
            'an':0.0199, 're':0.0185, 'on':0.0176, 'at':0.0149, 'en':0.0145,
            'nd':0.0135, 'ti':0.0134, 'es':0.0134, 'or':0.0128, 'te':0.0120,
            'of':0.0117, 'ed':0.0117, 'is':0.0113, 'it':0.0112, 'al':0.0109,
            'ar':0.0107, 'st':0.0105, 'to':0.0104, 'nt':0.0104, 'ng':0.0095,
            'se':0.0093, 'ha':0.0093, 'as':0.0087, 'ou':0.0087, 'io':0.0083,
            'le':0.0083, 've':0.0083, 'co':0.0079, 'me':0.0079, 'de':0.0076,
            'hi':0.0076, 'ri':0.0073, 'ro':0.0073, 'ic':0.0070, 'ne':0.0069,
            'ea':0.0069, 'ra':0.0069, 'ce':0.0065, 'li':0.0062, 'ch':0.0060,
            'll':0.0058, 'be':0.0058, 'ma':0.0057, 'si':0.0055, 'om':0.0055,
            'ur':0.0054}


    @staticmethod
    def GetLines(filename):
        """Read lines from from the file. Removed newline character at the end
        before returning them."""
        return map(lambda l: l.replace('\n', ''), open(filename).readlines())

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
    def GetBigramSquaredError(bigrams):
        """Returns bigram squared error."""
        bigrams = map(lambda b : b.lower(), bigrams)
        frequency = Counter(bigrams)
        error = 0.0
        for bi in Crypto.EN_BIGRAMS:
            expected = Crypto.EN_BIGRAMS[bi] if bi in Crypto.EN_BIGRAMS else 0.0
            observed = frequency[bi] / float(len(bigrams))
            error += (expected - observed)**2 / expected
        return error;


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
    def HexToBase64(hex_str):
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
        for key in range(256):
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
            blocks = Crypto.GetBlocks(text, key_len)
            dist = lambda i : Crypto.GetHammingDistance(blocks[i], blocks[i+1])
            return sum(map(dist, range(0, 12, 2))) / float(key_len), key_len

        key_lengths = map(
            lambda key_len : GetHammingDistanceAverage(cipher, key_len),
            range(2, 41))
        key_lengths.sort()
        return key_lengths[0][1]

    @staticmethod
    def BreakRepeatingXor(cipher, key_len=0):
        """Breaks repeating key xor cipher. Returns (plaintext, key)"""
        key_len = key_len if key_len > 0 else Crypto.BreakKeyLength(cipher)
        key = ''.join(map(
            lambda i: Crypto.BreakSingleByteXor(cipher[i::key_len])[1],
            range(0, key_len)))
        return Crypto.GetRepeatingXor(cipher, key), key

    @staticmethod
    def PadPkcs7(text, bs=16):
        """Pads text with pkcs7 and returns padded text."""
        pad_size = bs - len(text) % bs
        pad_char = chr(pad_size)
        return text + pad_char*pad_size

    @staticmethod
    def UnadPkcs7(text, bs=16):
        """Unpads text with pkcs7 and returns unpadded text."""
        if len(text) == 0 or len(text) % bs != 0:
            raise ValueError("Input text length is invalid %s" % len(text))
        pad_size = ord(text[-1:])
        padding = chr(pad_size)*pad_size
        if padding != text[-pad_size:]:
            raise ValueError("Invalid Padding.")
        return text[:-pad_size]

    @staticmethod
    def DecryptAes(cipher, key, mode, IV=None, counter=None):
        """Decrypts AES cipher."""
        IV = IV if IV else Random.new().read(len(key))
        if mode == AES.MODE_ECB or mode == AES.MODE_CBC:
            aes = AES.new(key, mode, IV=IV)
            return Crypto.UnadPkcs7(aes.decrypt(cipher))
        elif mode == AES.MODE_CTR:
            aes = AES.new(key, mode, counter=counter)
            return aes.decrypt(cipher)

    @staticmethod
    def EncryptAes(text, key, mode, IV=None, counter=None):
        """Encrypts AES cipher."""
        IV = IV if IV else Random.new().read(len(key))
        if mode == AES.MODE_ECB or mode == AES.MODE_CBC:
            aes = AES.new(key, mode, IV=IV)
            return aes.encrypt(Crypto.PadPkcs7(text))
        elif mode == AES.MODE_CTR:
            aes = AES.new(key, mode, counter=counter)
            return aes.encrypt(text)


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
    def GetBlocks(text, bs=16):
        num_blocks = len(text) / bs
        return map(lambda i: text[i*bs:i*bs+bs], range(num_blocks))

    @staticmethod
    def IsAesEcbCipher(cipher):
        """Checks if given aes cipher is encrypted with ECB mode."""
        blocks = Crypto.GetBlocks(cipher)
        unique_blocks = set(blocks)
        return len(blocks) > len(unique_blocks) # has duplicate blocks

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
                text_len -= i
                break
            text_len = cipher_len

        get_block = lambda text, index : text[key_len*index:key_len*(index+1)]

        # find length of prefix
        c1 = aes_ecb('a')
        c2 = aes_ecb('b')
        # find which block is different in c1 and c2 which gives us some bound
        # for prefix length
        block_index = 0
        for i in range(0, len(c1)/key_len):
            block_index = i
            if get_block(c1, i) != get_block(c2, i): break

        # block_index*key_len <= prefix_len < (block_index+1)*key_len
        # Assuming secret text doesn't has '\x00' characters. TODO: fix this
        prefix_len = 0
        last_cipher = ''
        for i in range(1, key_len+2):
            cipher = get_block(aes_ecb('\x00'*i), block_index)
            prefix_len = (block_index + 1) * key_len - i + 1
            if cipher == last_cipher: break
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
            # create dictionary
            ciphers = {}
            for c in range(256):
                text = known + result + chr(c)
                ciphers[get_block(aes_ecb(text), block_index)] = chr(c)
            # discover unknown one character at a time
            cipher = get_block(aes_ecb(known), block_index)
            result += ciphers[cipher]
        return result

    @staticmethod
    def GenerateAesOracle(prefix, suffix, mode, quote, bs=16, counter=None):
        """Returns a AES encrypt function which encrypts text as following
        1. quote text using quote function.
        1. Add prefix to text
        2. Add suffix to text
        3. key and intialization vector are generated randomly but consistent
           across all runs.
        """
        key = Crypto.GenRandomKey(bs)
        iv =  Crypto.GenRandomKey(bs)
        if mode == AES.MODE_CTR:
            return (lambda text: Crypto.EncryptAes(
                prefix + quote(text) + suffix, key, mode, counter=counter), key)
        oracle = lambda text: Crypto.EncryptAes(
            prefix + quote(text) + suffix, key, mode, iv)
        return (oracle, key, iv)

    @staticmethod
    def FlipCipherToAddAdmin(aes_cbc, has_admin):
        # this ensures at least one block has all X's
        bs = 16
        cipher = aes_cbc('x'*2*bs)
        flipper = Crypto.GetRepeatingXor('x'*bs, ';admin=true;')
        for i, block in enumerate(Crypto.GetBlocks(cipher, bs)):
            flipped_cipher = cipher[:i*bs] + \
                Crypto.GetRepeatingXor(flipper, block) + cipher[(i+1)*bs:]
            if has_admin(flipped_cipher):
                return True
        return False

    @staticmethod
    def BreakAesUsingPaddingLeak(cipher, iv, has_valid_padding):
        """Decrypts cipher given has_valid_padding function which decrypts
        and return true if result has valid padding, false otherwise. We will
        use this leak to break the cipher and return plaintext"""
        bs = 16
        mutate = lambda text, i, c: text[:i] + c +  text[i+1:]
        # get padding size
        pad_size = 0
        # second_last block index
        sl_block = len(cipher) - bs*2
        for i in range(bs):
            # check if pad_size is bs - i
            change = 'b' if cipher[sl_block+i] == 'a' else 'a'
            if not has_valid_padding(mutate(cipher, sl_block+i, change), iv):
                pad_size = bs - i
                break

        # we know pad size which means we know last pad_size bytes of result.
        prexor = Crypto.GetRepeatingXor(
            chr(pad_size)*pad_size, cipher[-pad_size-bs:-bs])
        iv_and_cipher = iv + cipher
        for i in range(len(prexor), len(cipher)):
            pad_size = (len(prexor) % bs) + 1
            # decrypt byte at target_index in this iteration.
            target_index = len(cipher) - len(prexor) - 1
            for c in range(256):
                # temper iv_and_cipher
                attack = mutate(iv_and_cipher, target_index, chr(c))
                xor = Crypto.GetRepeatingXor(
                    chr(pad_size)*(pad_size-1), prexor[:pad_size-1])
                attack = attack[:target_index+1] + xor
                # add next block
                attack = attack + iv_and_cipher[len(attack):len(attack)+bs]
                flipped_iv = attack[:bs]
                flipped_cipher = attack[bs:]
                if has_valid_padding(flipped_cipher, flipped_iv):
                    prexor = chr(pad_size^c) + prexor
                    break
        blocks = zip(Crypto.GetBlocks(iv_and_cipher), Crypto.GetBlocks(prexor))
        return Crypto.UnadPkcs7(
            ''.join(map(lambda (a,b) : Crypto.GetRepeatingXor(a,b), blocks)))


    @staticmethod
    def GenAesStreamCounterSimple():
        """Returns a simple stream couner limited to 256 characters."""
        def GenCounter():
            count = 0
            while True:
                yield chr(0)*8 + chr(count) + chr(0)*7
                count += 1
        counter = GenCounter()
        return lambda : counter.next()

    @staticmethod
    def GenAesStreamCounterRng(seed=None):
        """Returns a RNG based stream couner."""
        seed = seed if seed else int(time())
        rng = MT19937(seed)
        def next():
            num = rng.next()
            return ''.join([chr(num >> i & 0xff) for i in (24,16,8,0)])
        return lambda : next() + next() + next() + next()

    @staticmethod
    def EncryptUsingMT19937():
        pass

    @staticmethod
    def GetBigrams(text):
        words = text.split()
        bigrams = []
        for word in words:
            bigrams.extend([word[i:i+2] for i in range(0, len(word), 2)])
            bigrams.extend([word[i:i+2] for i in range(1, len(word), 2)])
        return filter(lambda bi: len(bi) == 2, bigrams)

    @staticmethod
    def BreakAesCtrWithFixedNonce(ciphers, bs=16):
        full_cipher = ''
        for cipher in ciphers:
            extra = len(cipher) % bs
            if extra > 0:
                cipher = cipher[:-extra]
            full_cipher += cipher
        text, key = Crypto.BreakRepeatingXor(full_cipher, bs)
        return key

    @staticmethod
    def GenRandomNumber():
        """Wait for 40 to 1000 seconds and then generate random number using
        mt19937 randome generator"""
        delay = random.randint(40,1000)
        # substract delay to simulate sleep time
        seed = int(time()) - delay
        rng = MT19937(seed)
        return rng.next()

    @staticmethod
    def CloneMt19937Rng(rng):
        """Returns clone of random number generator."""
        clone = MT19937(0)
        for i in range(624):
            y = rng.next()
            # Inverse of y = y ^ y >> 18
            y = y ^ y >> 18

            # Inverse of y = y ^ y << 15 & 4022730752
            y = y ^ y << 15 & 4022730752

            # Inverse of y = y ^ y << 7 & 2636928640
            # We have 7 correct bits and in each iteration we get 7 more bits.
            x = y ^ y << 7 & 2636928640
            x = y ^ x << 7 & 2636928640
            x = y ^ x << 7 & 2636928640
            y = y ^ x << 7 & 2636928640

            # Inverse of y = y ^ y >> 11
            # We have 11 correct bits and in each iteration we get 11 more bits.
            x = y ^ y >> 11
            y = y ^ x >> 11
            clone.mt[i] = y
        return clone

    @staticmethod
    def BreakRngStreamCipher(cipher, text_suffix):
        """Breaks rng stream cipher and returns seed of rng."""
        for i in range(1<<16):
            mt_cipher = MT19937Cipher(i)
            text = mt_cipher.decrypt(cipher)
            if text.endswith(text_suffix):
                return i
        return -1

