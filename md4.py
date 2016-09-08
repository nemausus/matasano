#!/usr/bin/python

# Copyright: ThoughtSpot Inc 2016
# Author: Naresh Kumar (naresh.kumar@thoughtspot.com)

import struct

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4Hash(object):
    def __init__(self, h=None, count=0):
        self.remainder = ""
        self.count = count
        if h:
            self.h = h
        else:
            self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    def _add_chunk(self, chunk):
        self.count += 1
        X = list(struct.unpack("<16I", chunk) + (None,) * (80-16))
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate((h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4])
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4
            k = 4*(r%4) + r//4
            h[i] = leftrotate((h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4])
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4
            h[i] = leftrotate((h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4])

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def update(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk(message[chunk:chunk+64])
        return self

    def digest(self):
        l = len(self.remainder) + 64 * self.count
        self.update("\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))
        out = struct.pack("<4I", *self.h)
        self.__init__()
        return out

    @staticmethod
    def pad(message):
        message_byte_length = len(message)
        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length
        # (in bytes) is congruent to 56 (mod 64)
        message += b'\x00' * ((55 - message_byte_length) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit
        # little-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'<Q', message_bit_length)
        return message

def md4(message):
    """MD4 Hashing Function"""
    return MD4Hash().update(message).digest()


def extend_md4(md4, msg, suffix, validate):
    """Extends md4 to generated forged md4 hash ending with given suffix."""
    # Message is known but we don't know length of key.  We will try all values
    # multiple of multiple of 64
    msg_len = len(msg)
    msg_len = msg_len + (64 - msg_len % 64)
    h = list(struct.unpack('<4I', md4))
    while(msg_len < 1024):
        count = len(MD4Hash.pad('x'*msg_len)) / 64
        if validate(MD4Hash(h, count).update(suffix).digest()):
            return True
        msg_len += 64
    return False
