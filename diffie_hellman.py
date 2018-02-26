#!/usr/bin/python

# Copyright: ThoughtSpot Inc 2017
# Author: Naresh Kumar (naresh.kumar@thoughtspot.com)

import random

def modexp(base, power, mod):
    result = 1
    while power:
        if power & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        power = power >> 1
    return result

class DiffieHellman(object):
    p = 37
    g = 5
    a = random.randint(0, p-1)
    A = modexp(g, a, p)
    b = random.randint(0, p-1)
    B = modexp(g, a, p)
    s = modexp(B, a, p)
