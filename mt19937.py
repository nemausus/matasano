# author : Naresh Kumar
"""MT19937 random number generator utils."""

def _int32(num):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & num)

class MT19937RNG(object):
    """MT19937 random number generator."""

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.seq = [0] * 624
        self.seq[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.seq[i] = _int32(
                1812433253 * (self.seq[i - 1] ^ self.seq[i - 1] >> 30) + i)


    def next(self):
        """Returns next random number."""
        if self.index >= 624:
            self.twist()

        num = self.seq[self.index]

        # Right shift bnum 11 bits
        # operator precedence << -> & -> ^
        num = num ^ num >> 11
        # Shift num left bnum 7 and take the bitwise and of 2636928640
        num = num ^ num << 7 & 2636928640
        # Shift num left bnum 15 and take the bitwise and of num and 4022730752
        num = num ^ num << 15 & 4022730752
        # Right shift bnum 18 bits
        num = num ^ num >> 18

        self.index = self.index + 1

        return _int32(num)


    def twist(self):
        """Generates next set of 624 numbers."""
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            num = _int32((self.seq[i] & 0x80000000) +
                         (self.seq[(i + 1) % 624] & 0x7fffffff))
            self.seq[i] = self.seq[(i + 397) % 624] ^ num >> 1

            if num % 2 != 0:
                self.seq[i] = self.seq[i] ^ 0x9908b0df
        self.index = 0

    @staticmethod
    def clone(rng):
        """Returns clone of random number generator."""
        clone = MT19937RNG(0)
        for i in range(624):
            num = rng.next()
            # Inverse of num = num ^ num >> 18
            num = num ^ num >> 18

            # Inverse of num = num ^ num << 15 & 4022730752
            num = num ^ num << 15 & 4022730752

            # Inverse of num = num ^ num << 7 & 2636928640
            # We have 7 correct bits and in each iteration we get 7 more bits.
            temp = num ^ num << 7 & 2636928640
            temp = num ^ temp << 7 & 2636928640
            temp = num ^ temp << 7 & 2636928640
            num = num ^ temp << 7 & 2636928640

            # Inverse of num = num ^ num >> 11
            # We have 11 correct bits and in each iteration we get 11 more bits.
            temp = num ^ num >> 11
            num = num ^ temp >> 11
            clone.seq[i] = num
        return clone


class MT19937Cipher(object):
    """A simple stream cipher based on MT19937 random number generator."""

    def __init__(self, seed):
        self.seed = seed
        self.num = 0
        self.left = 0
        self.reset()

    def encrypt(self, text):
        """Returns encrypted text."""
        return ''.join([chr(self._next() ^ ord(c)) for c in text])

    def decrypt(self, text):
        """Returns dencrypted text."""
        return self.encrypt(text)

    def reset(self):
        """Reset stream of random number generator."""
        self.rng = MT19937RNG(self.seed)
        self.num = 0
        self.left = 0

    def _next(self):
        """Returns next byte of stream."""
        if not self.left:
            self.num = self.rng.next()
            self.left = 4
        shift = 8*(self.left-1)
        self.left -= 1
        return self.num >> shift & 0xff
