#!/usr/bin/env python3
"""
Unit Tests for Hybrid LFSR-ARX Stream Cipher
"""

import unittest
from cipher import HybridStreamCipher, cross_feedback_mixing, butterfly_diffusion


class TestHybridStreamCipher(unittest.TestCase):

    def test_encryption_decryption_roundtrip(self):
        """Ensure ciphertext can be decrypted back to the exact plaintext."""
        key = 0xDEADBEEFCAFEBABEDEADBEEFCAFEBABE
        iv = 0x123456789ABCDEF0123456789ABCDEF0
        cipher_enc = HybridStreamCipher(key=key, iv=iv)
        cipher_dec = HybridStreamCipher(key=key, iv=iv)

        plaintext = b"Test message with standard ASCII, symbols !@#$%^&*(), and numbers 123456."
        ciphertext = cipher_enc.encrypt(plaintext)
        decrypted = cipher_dec.decrypt(ciphertext)

        self.assertNotEqual(plaintext, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_long_stream_refresh(self):
        """Ensure continuous keystream generation across multiple 4 KB block refreshes."""
        key = 0xAA55AA55AA55AA55AA55AA55AA55AA55
        iv = 1
        cipher = HybridStreamCipher(key=key, iv=iv)

        # Request 10 KB of keystream (triggers state refresh > 2 times)
        data = cipher.get_keystream_bytes(10240)
        self.assertEqual(len(data), 10240)
        # Ensure high byte diversity across output
        self.assertGreater(len(set(data)), 200)

    def test_cross_feedback_avalanche_effect(self):
        """A single bit flip in the key should flip ~50% of the 258 bits after 550 rounds."""
        iv = 1
        key1 = 0x1234567890ABCDEF1234567890ABCDEF
        key2 = key1 ^ 1  # Flip 1 bit

        m1 = cross_feedback_mixing(iv, key1)
        m2 = cross_feedback_mixing(iv, key2)

        flipped_bits = bin(m1 ^ m2).count("1")
        # In ideal confusion/diffusion, flipping 1 bit should change ~40-60% of bits (>= 100 out of 258)
        self.assertGreaterEqual(flipped_bits, 100, f"Avalanche insufficient: {flipped_bits}/258 bits flipped")

    def test_key_sensitivity(self):
        """Two keys differing by 1 bit must produce uncorrelated keystreams."""
        key1 = 0x11112222333344445555666677778888
        key2 = key1 ^ 1
        iv = 0x9999AAAA

        c1 = HybridStreamCipher(key=key1, iv=iv).get_keystream_bytes(128)
        c2 = HybridStreamCipher(key=key2, iv=iv).get_keystream_bytes(128)

        matching_bytes = sum(b1 == b2 for b1, b2 in zip(c1, c2))
        # For 128 bytes, random match expectation is ~ 128/256 = 0.5 bytes
        self.assertLess(matching_bytes, 10, "Keystreams between adjacent keys are too correlated!")


if __name__ == "__main__":
    unittest.main()
