#!/usr/bin/env python3
"""
Empirical Security Evaluation Script
====================================
Tests the Confusion, Diffusion, and Statistical Randomness properties
of the Hybrid LFSR-ARX Stream Cipher.

Metrics evaluated:
1. Strict Avalanche Criterion (SAC) / Diffusion: 1-bit flip in Key and IV
2. Cross-Feedback Mixing Avalanche (550 rounds)
3. Confusion / Key Sensitivity: Hamming distance across random 1-bit key deltas
4. Shannon Byte Entropy
5. Monobit Frequency Test (NIST SP 800-22 inspired)
"""

import math
import random
from cipher import HybridStreamCipher, cross_feedback_mixing


def run_avalanche_diffusion_test(trials: int = 128):
    print("=" * 65)
    print("1. STRICT AVALANCHE CRITERION (SAC) & DIFFUSION TEST")
    print("=" * 65)
    print(f"[*] Testing 1-bit flips across {trials} key bit positions...")

    base_key = 0x6A09E667F3BCC908B5C0FBCEE94B3439
    base_iv = 0x1F83D9AB55E4C2A109876543210FEDCB

    base_cipher = HybridStreamCipher(key=base_key, iv=base_iv)
    base_ks = base_cipher.get_keystream_bytes(512)  # 4096 bits
    base_bits = "".join(f"{b:08b}" for b in base_ks)

    key_flips = []
    for bit_idx in range(trials):
        flipped_key = base_key ^ (1 << bit_idx)
        c = HybridStreamCipher(key=flipped_key, iv=base_iv)
        ks = c.get_keystream_bytes(512)
        bits = "".join(f"{b:08b}" for b in ks)
        hd = sum(b1 != b2 for b1, b2 in zip(base_bits, bits))
        key_flips.append((hd / len(base_bits)) * 100)

    mean_key_flips = sum(key_flips) / len(key_flips)
    std_key_flips = math.sqrt(sum((x - mean_key_flips) ** 2 for x in key_flips) / len(key_flips))

    print(f"  -> Key-Flip Diffusion (SAC):   Mean = {mean_key_flips:.2f}% (Ideal: 50.0%)")
    print(f"                                 StdDev = {std_key_flips:.2f}%")
    print(f"                                 Range  = [{min(key_flips):.2f}%, {max(key_flips):.2f}%]")

    # IV Flip
    iv_trials = 127
    print(f"\n[*] Testing 1-bit flips across {iv_trials} IV bit positions...")
    iv_flips = []
    for bit_idx in range(iv_trials):
        flipped_iv = base_iv ^ (1 << bit_idx)
        c = HybridStreamCipher(key=base_key, iv=flipped_iv)
        ks = c.get_keystream_bytes(512)
        bits = "".join(f"{b:08b}" for b in ks)
        hd = sum(b1 != b2 for b1, b2 in zip(base_bits, bits))
        iv_flips.append((hd / len(base_bits)) * 100)

    mean_iv_flips = sum(iv_flips) / len(iv_flips)
    std_iv_flips = math.sqrt(sum((x - mean_iv_flips) ** 2 for x in iv_flips) / len(iv_flips))

    print(f"  -> IV-Flip Diffusion (SAC):    Mean = {mean_iv_flips:.2f}% (Ideal: 50.0%)")
    print(f"                                 StdDev = {std_iv_flips:.2f}%")
    print(f"                                 Range  = [{min(iv_flips):.2f}%, {max(iv_flips):.2f}%]")


def run_cross_feedback_avalanche_test(trials: int = 200):
    print("\n" + "=" * 65)
    print("2. CROSS-FEEDBACK MIXING (550 ROUNDS) AVALANCHE TEST")
    print("=" * 65)
    print(f"[*] Running {trials} randomized trials flipping 1 bit in Key and IV...")

    flips_k = []
    flips_iv = []

    for _ in range(trials):
        k = random.getrandbits(128)
        iv = random.getrandbits(127)

        # 1 bit flip in key
        k_flipped = k ^ (1 << random.randint(0, 127))
        m1 = cross_feedback_mixing(iv, k)
        m2 = cross_feedback_mixing(iv, k_flipped)
        flips_k.append((bin(m1 ^ m2).count("1") / 258.0) * 100)

        # 1 bit flip in IV
        iv_flipped = iv ^ (1 << random.randint(0, 126))
        m3 = cross_feedback_mixing(iv_flipped, k)
        flips_iv.append((bin(m1 ^ m3).count("1") / 258.0) * 100)

    print(f"  -> State Avalanche (Key Delta): Mean = {sum(flips_k)/len(flips_k):.2f}% (Ideal: 50.0%)")
    print(f"  -> State Avalanche (IV Delta):  Mean = {sum(flips_iv)/len(flips_iv):.2f}% (Ideal: 50.0%)")


def run_confusion_key_sensitivity_test(trials: int = 200):
    print("\n" + "=" * 65)
    print("3. CONFUSION & KEY SENSITIVITY TEST (RANDOMIZED PAIRS)")
    print("=" * 65)
    print(f"[*] Comparing keystream outputs across {trials} random adjacent key pairs...")

    hd_pcts = []
    for _ in range(trials):
        k1 = random.getrandbits(128)
        k2 = k1 ^ (1 << random.randint(0, 127))
        iv = random.getrandbits(127)

        c1 = HybridStreamCipher(key=k1, iv=iv).get_keystream_bytes(256)
        c2 = HybridStreamCipher(key=k2, iv=iv).get_keystream_bytes(256)

        flips = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(c1, c2))
        hd_pcts.append((flips / (256 * 8)) * 100)

    mean_hd = sum(hd_pcts) / len(hd_pcts)
    std_hd = math.sqrt(sum((x - mean_hd) ** 2 for x in hd_pcts) / len(hd_pcts))

    print(f"  -> Keystream Non-Correlation:  Mean = {mean_hd:.2f}% (Ideal: 50.0%)")
    print(f"                                 StdDev = {std_hd:.2f}%")
    print(f"                                 Range  = [{min(hd_pcts):.2f}%, {max(hd_pcts):.2f}%]")


def run_statistical_randomness_test():
    print("\n" + "=" * 65)
    print("4. STATISTICAL RANDOMNESS & FREQUENCY ANALYSIS")
    print("=" * 65)
    print("[*] Generating keystream sample...")

    cipher = HybridStreamCipher(key=0x1234567890ABCDEF1234567890ABCDEF, iv=0x55555555555555555555555555555555)
    sample = cipher.get_keystream_bytes(1024 * 1024)  # 1 MB

    # Shannon Entropy
    byte_counts = [0] * 256
    for b in sample:
        byte_counts[b] += 1
    entropy = -sum((cnt / len(sample)) * math.log2(cnt / len(sample)) for cnt in byte_counts if cnt > 0)

    # Monobit Frequency Test
    total_bits = len(sample) * 8
    ones = sum(bin(b).count("1") for b in sample)
    ones_ratio = ones / total_bits
    s_obs = abs(ones - (total_bits - ones)) / math.sqrt(total_bits)
    p_val = math.erfc(s_obs / math.sqrt(2))

    print(f"  -> Shannon Byte Entropy:       {entropy:.6f} bits/byte (Max: 8.000000)")
    print(f"  -> Monobit Proportion (Ones):  {ones_ratio:.6f} (Ideal: 0.500000)")
    print(f"  -> NIST Monobit Test Statistic: S_obs = {s_obs:.4f}, p-value = {p_val:.4f}")
    print("=" * 65)


if __name__ == "__main__":
    run_avalanche_diffusion_test()
    run_cross_feedback_avalanche_test()
    run_confusion_key_sensitivity_test()
    run_statistical_randomness_test()
