#!/usr/bin/env python3
"""
Throughput Benchmark for Hybrid LFSR-ARX Stream Cipher (Python)
"""

import time
from cipher import HybridStreamCipher


def run_benchmark(megabytes: int = 4):
    print(f"--- Running Python Throughput Benchmark ({megabytes} MB) ---")
    key = 0x0123456789ABCDEF0123456789ABCDEF
    iv = 0x112233445566778899AABBCCDDEEFF00
    
    cipher = HybridStreamCipher(key=key, iv=iv)
    total_bytes = megabytes * 1024 * 1024

    start_time = time.perf_counter()
    _ = cipher.get_keystream_bytes(total_bytes)
    elapsed = time.perf_counter() - start_time

    throughput_mb_s = megabytes / elapsed
    print(f"Generated: {megabytes} MB ({total_bytes:,} bytes)")
    print(f"Elapsed Time: {elapsed:.4f} seconds")
    print(f"Throughput:   {throughput_mb_s:.2f} MB/s (Python interpreter)")


if __name__ == "__main__":
    run_benchmark(4)
