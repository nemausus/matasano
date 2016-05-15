# author : Naresh Kumar
"""Collection of crypto utilities."""

import random
from time import time
from Crypto.Cipher import AES
from Crypto import Random
from mt19937 import MT19937RNG
from mt19937 import MT19937Cipher
from frequency_analyzer import FrequencyAnalyzer

def logger(test):
    """Decorator to print test name."""
    def func(*args):
        """Prints test name and runs it."""
        print "Running %s" % test.func_name
        test(*args)
    return func

class Crypto(object):
    """Collection of crypto utilities."""

    @staticmethod
    def get_lines(filename):
        """Read lines from from the file. Removed newline character at the end
        before returning them."""
        return [l.replace('\n', '') for l in open(filename).readlines()]


    @staticmethod
    def gen_random_key(length=16):
        """Returns random key of given length using base64 character set.
           Default key length is 16."""
        alphabet = ('abcdefghijklmnopqrstuvwxyz'
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                    '0123456789+/')
        return ''.join([alphabet[random.randint(0, 63)] for _ in range(length)])


    @staticmethod
    def get_hamming_distance(text1, text2):
        """Returns hamming distance for two strings of same size."""
        xor = [bin(ord(a) ^ ord(b)).count("1") for a, b in zip(text1, text2)]
        return sum(xor)


    @staticmethod
    def detect_single_byte_xor(ciphers):
        """Detects single byte xor cipher from the list of ciphers."""
        for cipher in ciphers:
            text, _ = FrequencyAnalyzer.break_single_byte_xor(cipher)
            if text and FrequencyAnalyzer.is_english(text):
                return text
        return None


    @staticmethod
    def break_key_length(cipher):
        """Returns most promising key length for repeating xor cipher."""
        def get_hamming_distance_average(text, key_len):
            """Returns hamming distance average."""
            blocks = Crypto.get_blocks(text, key_len)
            dist = lambda i: Crypto.get_hamming_distance(blocks[i], blocks[i+1])
            average = sum([dist(i) for i in range(0, 12, 2)]) / float(key_len)
            return average, key_len

        key_lengths = [get_hamming_distance_average(cipher, key_len)
                       for key_len in range(2, 41)]
        key_lengths.sort()
        return key_lengths[0][1]

    @staticmethod
    def break_repeating_xor(cipher, key_len=0):
        """Breaks repeating key xor cipher. Returns (plaintext, key)"""
        key_len = key_len if key_len > 0 else Crypto.break_key_length(cipher)
        key = ''.join([FrequencyAnalyzer.break_single_byte_xor(
            cipher[i::key_len])[1] for i in range(0, key_len)])
        return FrequencyAnalyzer.get_repeating_xor(cipher, key), key

    @staticmethod
    def pad_pkcs7(text, block_size=16):
        """Pads text with pkcs7 and returns padded text."""
        pad_size = block_size - len(text) % block_size
        pad_char = chr(pad_size)
        return text + pad_char*pad_size

    @staticmethod
    def unad_pkcs7(text, block_size=16):
        """Unpads text with pkcs7 and returns unpadded text."""
        if len(text) == 0 or len(text) % block_size != 0:
            raise ValueError("Input text length is invalid %s" % len(text))
        pad_size = ord(text[-1:])
        padding = chr(pad_size)*pad_size
        if padding != text[-pad_size:]:
            raise ValueError("Invalid Padding.")
        return text[:-pad_size]

    @staticmethod
    def decrypt_aes(cipher, key, mode, init_vector=None, counter=None):
        """Decrypts AES cipher."""
        if not init_vector:
            init_vector = Random.new().read(len(key))
        if mode == AES.MODE_ECB or mode == AES.MODE_CBC:
            aes = AES.new(key, mode, IV=init_vector)
            return Crypto.unad_pkcs7(aes.decrypt(cipher))
        elif mode == AES.MODE_CTR:
            aes = AES.new(key, mode, counter=counter)
            return aes.decrypt(cipher)

    @staticmethod
    def encrypt_aes(text, key, mode, init_vector=None, counter=None):
        """Encrypts AES cipher."""
        if not init_vector:
            init_vector = Random.new().read(len(key))
        if mode == AES.MODE_ECB or mode == AES.MODE_CBC:
            aes = AES.new(key, mode, IV=init_vector)
            return aes.encrypt(Crypto.pad_pkcs7(text))
        elif mode == AES.MODE_CTR:
            aes = AES.new(key, mode, counter=counter)
            return aes.encrypt(text)


    @staticmethod
    def oracle_encryption(text):
        """1) Apply 5-10 random letters at beginning and end of text.
           2) Pick CBC or EBC mode randomly.
           4) Generate 16 byte key randomly.
           3) Apply AEC encryption using above inputs.
           Returns (cipher, mode) pair.
        """
        text = Crypto.gen_random_key(random.randint(5, 10)) + text + \
            Crypto.gen_random_key(random.randint(5, 10))
        mode = AES.MODE_ECB if random.randint(0, 1) == 0 else AES.MODE_CBC
        key = Crypto.gen_random_key(16)
        return Crypto.encrypt_aes(text, key, mode), mode

    @staticmethod
    def get_blocks(text, block_size=16):
        """Breaks @text in to blocks fo size @block_size."""
        num_blocks = len(text) / block_size
        return [text[i*block_size:i*block_size+block_size]
                for i in range(num_blocks)]

    @staticmethod
    def is_aes_ecb_cipher(cipher):
        """Checks if given aes cipher is encrypted with ECB mode."""
        blocks = Crypto.get_blocks(cipher)
        unique_blocks = set(blocks)
        return len(blocks) > len(unique_blocks) # has duplicate blocks

    @staticmethod
    def decrypts_aes_ecb_byte_wise(aes_ecb):
        """Given a block box AES encryption function of this form:
        AES-ECB(random-prefix || attacker-controlled || target-bytes,random-key)
        Finds and returns target-bytes.
        """
        # find length of key and plaintext (prefix + suffix)
        text_len = 0
        key_len = 0
        for i in range(0, 64):
            cipher_len = len(aes_ecb('A' * i))
            if text_len and text_len != cipher_len:
                key_len = cipher_len - text_len
                text_len -= i
                break
            text_len = cipher_len

        get_block = lambda text, index: text[key_len*index:key_len*(index+1)]

        # find length of prefix
        cipher1 = aes_ecb('a')
        cipher2 = aes_ecb('b')
        # find which block is different in cipher1 and cipher2 which gives us
        # some bound
        # for prefix length
        block_index = 0
        for i in range(0, len(cipher1)/key_len):
            block_index = i
            if get_block(cipher1, i) != get_block(cipher2, i):
                break

        # block_index*key_len <= prefix_len < (block_index+1)*key_len
        # Assuming secret text doesn't has '\x00' characters. TODO: fix this
        prefix_len = 0
        last_cipher = ''
        for i in range(1, key_len+2):
            cipher = get_block(aes_ecb('\x00'*i), block_index)
            prefix_len = (block_index + 1) * key_len - i + 1
            if cipher == last_cipher:
                break
            last_cipher = cipher

        # find if this is ECB mode
        text = 'A'*3*key_len
        if not Crypto.is_aes_ecb_cipher(aes_ecb(text)):
            return None

        suffix_len = text_len - prefix_len
        result = ''
        for i in range(1, suffix_len+1):
            mod = (i  + prefix_len) % key_len
            pad_size = key_len - mod if mod else 0
            known = 'A' * pad_size
            block_index = (prefix_len + pad_size + len(result)) / key_len
            # create dictionary
            ciphers = {}
            for char in range(256):
                text = known + result + chr(char)
                ciphers[get_block(aes_ecb(text), block_index)] = chr(char)
            # discover unknown one character at a time
            cipher = get_block(aes_ecb(known), block_index)
            result += ciphers[cipher]
        return result

    @staticmethod
    def generate_aes_oracle(
            prefix, suffix, mode, quote, block_size=16, counter=None):
        """Returns a AES encrypt function which encrypts text as following
        1. quote text using quote function.
        1. Add prefix to text
        2. Add suffix to text
        3. key and intialization vector are generated randomly but consistent
           across all runs.
        """
        key = Crypto.gen_random_key(block_size)
        init_vector = Crypto.gen_random_key(block_size)
        if mode == AES.MODE_CTR:
            return (lambda text: Crypto.encrypt_aes(
                prefix + quote(text) + suffix, key, mode, counter=counter), key)
        oracle = lambda text: Crypto.encrypt_aes(
            prefix + quote(text) + suffix, key, mode, init_vector)
        return (oracle, key, init_vector)

    @staticmethod
    def flip_cipher_to_add_admin(aes_cbc, has_admin):
        """Flip bits in text until we get admin in cipher."""
        # this ensures at least one block has all X's
        block_size = 16
        cipher = aes_cbc('x'*2*block_size)
        flipper = FrequencyAnalyzer.get_repeating_xor(
            'x'*block_size, ';admin=true;')
        for i, block in enumerate(Crypto.get_blocks(cipher, block_size)):
            flipped_block = FrequencyAnalyzer.get_repeating_xor(flipper, block)
            flipped_cipher = (cipher[:i*block_size] +
                              flipped_block +
                              cipher[(i+1)*block_size:])
            if has_admin(flipped_cipher):
                return True
        return False

    @staticmethod
    def break_aes_using_padding_leak(cipher, init_vector, has_valid_padding):
        """Decrypts cipher given has_valid_padding function which decrypts
        and return true if result has valid padding, false otherwise. We will
        use this leak to break the cipher and return plaintext"""
        block_size = 16
        mutate = lambda text, i, c: text[:i] + c +  text[i+1:]
        # get padding size
        pad_size = 0
        # second_last block index
        sl_block = len(cipher) - block_size*2
        for i in range(block_size):
            # check if pad_size is block_size - i
            change = 'b' if cipher[sl_block+i] == 'a' else 'a'
            if not has_valid_padding(
                    mutate(cipher, sl_block+i, change), init_vector):
                pad_size = block_size - i
                break

        # we know pad size which means we know last pad_size bytes of result.
        prexor = FrequencyAnalyzer.get_repeating_xor(
            chr(pad_size)*pad_size, cipher[-pad_size-block_size:-block_size])
        iv_and_cipher = init_vector + cipher
        for i in range(len(prexor), len(cipher)):
            pad_size = (len(prexor) % block_size) + 1
            # decrypt byte at target_index in this iteration.
            target_index = len(cipher) - len(prexor) - 1
            for char in range(256):
                # temper iv_and_cipher
                attack = mutate(iv_and_cipher, target_index, chr(char))
                xor = FrequencyAnalyzer.get_repeating_xor(
                    chr(pad_size)*(pad_size-1), prexor[:pad_size-1])
                attack = attack[:target_index+1] + xor
                # add next block
                attack = (attack +
                          iv_and_cipher[len(attack):len(attack)+block_size])
                flipped_iv = attack[:block_size]
                flipped_cipher = attack[block_size:]
                if has_valid_padding(flipped_cipher, flipped_iv):
                    prexor = chr(pad_size^char) + prexor
                    break
        blocks = zip(
            Crypto.get_blocks(iv_and_cipher), Crypto.get_blocks(prexor))
        return Crypto.unad_pkcs7(''.join(
            [FrequencyAnalyzer.get_repeating_xor(a, b) for a, b in blocks]))


    @staticmethod
    def gen_aes_stream_counter_simple():
        """Returns a simple stream couner limited to 256 characters."""
        def gen_counter():
            """counter generator."""
            count = 0
            while True:
                yield chr(0)*8 + chr(count) + chr(0)*7
                count += 1
        counter = gen_counter()
        return lambda: counter.next()

    @staticmethod
    def break_aes_ctr_with_fixed_nonce(ciphers, block_size=16):
        """Breaks AES CTR with fixed nonce."""
        full_cipher = ''
        for cipher in ciphers:
            extra = len(cipher) % block_size
            if extra > 0:
                cipher = cipher[:-extra]
            full_cipher += cipher
        _, key = Crypto.break_repeating_xor(full_cipher, block_size)
        return key

    @staticmethod
    def gen_random_number():
        """Wait for 40 to 1000 seconds and then generate random number using
        mt19937 randome generator"""
        delay = random.randint(40, 1000)
        # substract delay to simulate sleep time
        seed = int(time()) - delay
        rng = MT19937RNG(seed)
        return rng.next()

    @staticmethod
    def break_rng_stream_cipher(cipher, text_suffix):
        """Breaks rng stream cipher and returns seed of rng."""
        for i in range(1<<16):
            mt_cipher = MT19937Cipher(i)
            text = mt_cipher.decrypt(cipher)
            if text.endswith(text_suffix):
                return i
        return -1
