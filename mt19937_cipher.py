# author : Naresh Kumar

from mt19937 import MT19937

class MT19937Cipher:
    def __init__(self, seed):
        self.seed = seed
        self.reset()

    def encrypt(self, text):
        num = self.rng.next()
        cipher = ''
        return ''.join([chr(self._next() ^ ord(c)) for c in text])

    def decrypt(self, text):
        return self.encrypt(text)

    def reset(self):
        self.rng = MT19937(self.seed)
        self.num = 0
        self.left = 0

    def _next(self):
        if not self.left:
            self.num = self.rng.next()
            self.left = 4
        shift = 8*(self.left-1)
        self.left -= 1
        return self.num >> shift & 0xff

