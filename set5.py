#! /usr/bin/env python
# author : Naresh Kumar
"""Diffie Hellman and friends."""

import unittest

from crypto import logger
from diffie_hellman import modexp

class TestSet5(unittest.TestCase):
    """Tests for set 5 solutions."""

    @logger
    def test_modexp(self):
        """Challenge 33"""
        self.assertEqual(1, modexp(45, 0, 37))
        self.assertEqual(8, modexp(45, 1, 37))

if __name__ == '__main__':
    unittest.main(verbosity=0)
