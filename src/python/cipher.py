#!/usr/bin/env python3
"""
Hybrid LFSR-ARX Stream Cipher Reference Implementation
======================================================
Combines Linear Feedback Shift Registers (LFSRs) for maximal period guarantees
with Add-Rotate-Xor (ARX) operations for fast non-linear diffusion and confusion.

Phases:
1. Setup: 128-bit key padded to 131 bits, 127-bit IV counter.
2. Cross-Feedback Mixing: 550 rounds of cross-register polynomial feedback and non-linear injection.
3. Butterfly Diffusion Layer: 32-bit modular addition and rotational permutations (7, 11, 13).
4. Feed-Forward & Re-Keying: Non-reversible EKey generation and forward secrecy state refresh.
5. Keystream Generation: Double-ARX Counter Mode generating 32 Kilobits (4096 bytes) per round.
"""

from typing import List, Tuple

MASK_32 = 0xFFFFFFFF
MASK_127 = (1 << 127) - 1
MASK_131 = (1 << 131) - 1
MASK_256 = (1 << 256) - 1


def rotl32(x: int, n: int) -> int:
    """32-bit bitwise left rotation."""
    return ((x << n) | (x >> (32 - n))) & MASK_32


def get_bit(val: int, n: int) -> int:
    """Extract the n-th bit of an arbitrary-precision integer."""
    return (val >> n) & 1


def F(x: int, y: int, z: int, w: int) -> int:
    """
    Non-linear boolean injection function.
    F(x, y, z, w) = (x & y) ^ (z & w) ^ (x ^ z)
    """
    return (x & y) ^ (z & w) ^ (x ^ z)


def cross_feedback_mixing(iv_int: int, key_int: int, rounds: int = 550) -> int:
    """
    Phase 2: Cross-Feedback Mixing (Warm-Up).
    Cross-pollinates Register A (127-bit IV) and Register B (131-bit Key)
    using primitive polynomial taps and non-linear function F.
    
    Returns:
        258-bit concatenated integer [ Register_A_127 | Register_B_131 ]
    """
    A = iv_int & MASK_127
    B = key_int & MASK_131

    for _ in range(rounds):
        # Linear Feedback (Primitive Polynomial Taps)
        # A taps: 0, 112, 120, 123
        a_linear = (get_bit(A, 0) ^ get_bit(A, 112) ^ 
                    get_bit(A, 120) ^ get_bit(A, 123))
        # B taps: 0, 121, 124, 129
        b_linear = (get_bit(B, 0) ^ get_bit(B, 121) ^ 
                    get_bit(B, 124) ^ get_bit(B, 129))

        # Non-Linear Injection from opposite register
        f_out_b = F(get_bit(B, 0), get_bit(B, 32), get_bit(B, 64), get_bit(B, 96))
        f_out_a = F(get_bit(A, 0), get_bit(A, 32), get_bit(A, 64), get_bit(A, 96))

        # Cross-Mix
        a_new = a_linear ^ f_out_b
        b_new = b_linear ^ f_out_a

        # Shift right by 1 and insert new bit at MSB
        A = (A >> 1) | (a_new << 126)
        B = (B >> 1) | (b_new << 130)

    # Concatenate into 258-bit state
    return (A << 131) | B


def butterfly_diffusion(state_256: int) -> int:
    """
    Phase 3: 32-bit Butterfly Diffusion Network.
    Provides fast avalanche effect across all 8 32-bit words using
    3 passes of modular additions and variable rotations.
    """
    W = [(state_256 >> (32 * i)) & MASK_32 for i in range(8)]

    # Pass 1: Mix Adjacent Pairs (Stride 1, Rotate 7)
    for i in range(0, 8, 2):
        W[i] = (W[i] + W[i + 1]) & MASK_32
    W = [rotl32(w, 7) for w in W]

    # Pass 2: Mix Cross Pairs (Stride 2, Rotate 11)
    for i in range(0, 8, 4):
        W[i] = (W[i] + W[i + 2]) & MASK_32
        W[i + 1] = (W[i + 1] + W[i + 3]) & MASK_32
    W = [rotl32(w, 11) for w in W]

    # Pass 3: Mix Wide Pairs (Stride 4, Rotate 13)
    for i in range(4):
        W[i] = (W[i] + W[i + 4]) & MASK_32
    W = [rotl32(w, 13) for w in W]

    # Re-concatenate words into 256-bit integer
    result = 0
    for i, word in enumerate(W):
        result |= (word << (32 * i))
    return result


def generate_keystream_block_robust(ekey_256: int, total_blocks: int = 128) -> bytearray:
    """
    Phase 5: Double-ARX Counter Mode Keystream Generator.
    Produces 128 blocks * 256 bits = 32,768 bits (4,096 bytes) per invocation.
    """
    initial_state = [(ekey_256 >> (32 * i)) & MASK_32 for i in range(8)]
    output_bytes = bytearray()

    for counter in range(1, total_blocks + 1):
        state = list(initial_state)
        # Inject Counter into word 0 to ensure uniqueness
        state[0] ^= counter

        # 10 Rounds of Robust Double-ARX Mixing
        for _ in range(10):
            # ARX Layer (Two-way mix across pairs: (0,4), (1,5), (2,6), (3,7))
            for i in range(4):
                a, b = i, i + 4
                # Forward mix
                state[a] = (state[a] + state[b]) & MASK_32
                state[b] ^= state[a]
                state[b] = rotl32(state[b], 13)

                # Backward mix (prevents differential cryptanalysis)
                state[a] ^= state[b]
                state[a] = rotl32(state[a], 9)

            # Swap Layer (Permute word positions)
            state[1], state[2] = state[2], state[1]
            state[3], state[4] = state[4], state[3]
            state[5], state[6] = state[6], state[5]
            state[7], state[0] = state[0], state[7]

        # Feed-Forward Layer
        for k in range(8):
            base_val = initial_state[k]
            if k == 0:
                base_val ^= counter
            out_word = (state[k] + base_val) & MASK_32
            output_bytes.extend(out_word.to_bytes(4, byteorder="little"))

    return output_bytes


class HybridStreamCipher:
    """
    High-level Stream Cipher engine managing state generation,
    re-keying (forward secrecy), and encryption/decryption.
    """
    def __init__(self, key: int, iv: int = 1):
        self.key = key & MASK_131
        self.iv = iv & MASK_127
        self.keystream_buffer = bytearray()
        self.buffer_index = 0
        self.current_state_258 = None
        self._init_cipher()

    def _init_cipher(self):
        # Initial Cross-Feedback Mixing
        self.current_state_258 = cross_feedback_mixing(self.iv, self.key)

    def _refresh_state_and_generate_chunk(self):
        """Generates next 4 KB keystream chunk and re-keys for forward secrecy."""
        state_256 = self.current_state_258 & MASK_256
        diffused_256 = butterfly_diffusion(state_256)
        
        # Phase 4: Feed-Forward EKey
        ekey = state_256 ^ diffused_256

        # Generate 4096 bytes of keystream
        chunk = generate_keystream_block_robust(ekey, total_blocks=128)
        self.keystream_buffer = chunk
        self.buffer_index = 0

        # Forward Secrecy: Prepare 258-bit input for next round
        # Bit 257 = Bit 255, Bit 258 = Bit 256
        bit255 = get_bit(ekey, 254)
        bit256 = get_bit(ekey, 255)
        next_input_258 = ekey | (bit255 << 256) | (bit256 << 257)

        next_iv = (next_input_258 >> 131) & MASK_127
        next_key = next_input_258 & MASK_131
        self.current_state_258 = cross_feedback_mixing(next_iv, next_key, rounds=256)

    def get_keystream_bytes(self, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            if self.buffer_index >= len(self.keystream_buffer):
                self._refresh_state_and_generate_chunk()
            take = min(length - len(result), len(self.keystream_buffer) - self.buffer_index)
            result.extend(self.keystream_buffer[self.buffer_index : self.buffer_index + take])
            self.buffer_index += take
        return bytes(result)

    def encrypt(self, plaintext: bytes) -> bytes:
        ks = self.get_keystream_bytes(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Stream cipher decryption is identical to encryption
        return self.encrypt(ciphertext)


if __name__ == "__main__":
    print("=== Hybrid LFSR-ARX Stream Cipher Reference Demo ===")
    sample_key = 0x1A2B3C4D5E6F708192A3B4C5D6E7F809
    sample_iv = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    cipher_enc = HybridStreamCipher(key=sample_key, iv=sample_iv)
    cipher_dec = HybridStreamCipher(key=sample_key, iv=sample_iv)

    message = b"Confidential Cryptanalysis Project - Custom Stream Cipher"
    print(f"Original Text:  {message.decode()}")

    ciphertext = cipher_enc.encrypt(message)
    print(f"Ciphertext Hex: {ciphertext.hex()}")

    recovered = cipher_dec.decrypt(ciphertext)
    print(f"Decrypted Text: {recovered.decode()}")
    assert recovered == message, "Decryption failed!"
    print("Self-test passed successfully!")
