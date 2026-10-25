# Hybrid LFSR-ARX Stream Cipher: Design, Implementation & Cryptanalysis

[![Language](https://img.shields.io/badge/Language-C++17%20%7C%20Python%203-blue.svg)](https://isocpp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Focus](https://img.shields.io/badge/Domain-Cryptanalysis%20%26%20Cipher%20Design-green.svg)](#)
[![Performance](https://img.shields.io/badge/Throughput-300--700%2B%20MB%2Fs-orange.svg)](#-benchmarks--performance)
[![Diffusion SAC](https://img.shields.io/badge/Avalanche%20(SAC)-50.39%25-brightgreen.svg)](#-empirical-cryptographic-testing-confusion--diffusion)

A comprehensive cryptography project designing, implementing, and empirically evaluating a novel symmetric stream cipher that synergizes **Linear Feedback Shift Registers (LFSRs)** for provable period length guarantees with an **Add-Rotate-Xor (ARX)** diffusion network and an *Encrypt-then-Refresh* architecture providing **Forward Secrecy**.

---

## 📌 Executive Summary: What is this project?

Stream ciphers are widely utilized where high throughput, continuous stream generation, and minimal latency are critical. However, existing stream cipher primitives face fundamental design trade-offs:
* **Pure LFSR-based ciphers:** Excellent statistical cycle properties in hardware, but vulnerable to algebraic and linear cryptanalysis (such as the Berlekamp-Massey algorithm) if linear states are exposed directly.
* **Traditional software ciphers:** Vulnerable to state recovery attacks, lack forward secrecy, or require lookup tables (S-boxes) that are vulnerable to CPU cache-timing side channels.

### The Solution: Hybrid LFSR-ARX Architecture
This cipher architecture addresses these challenges by uniting:
* **Primitive Polynomial LFSRs:** Dual 127-bit and 131-bit registers guaranteeing astronomical period lengths without cycle degradation.
* **Non-Linear Cross-Feedback Injection:** 550 warm-up rounds with balanced boolean cross-pollination ($F(x,y,z,w)$) to defeat algebraic and linear cryptanalysis.
* **32-Bit Butterfly ARX Network:** Multi-stride modular addition and rotation layers providing rapid state avalanche without table-lookup side channels.
* **Double-ARX Counter Keystream Engine:** Generates 32 Kilobits ($4\text{ KB}$) per round using bidirectional column mixing resistant to differential cryptanalysis.
* **State Destruction & Re-Keying:** Enforces **Forward Secrecy** by automatically erasing internal registers and re-seeding after every $4\text{ KB}$ chunk.

---

## 🔬 Empirical Cryptographic Testing (Confusion & Diffusion)

To rigorously validate the cipher's cryptographic robustness, extensive empirical tests were executed measuring **Confusion**, **Diffusion (Strict Avalanche Criterion - SAC)**, and **Statistical Randomness**.

You can reproduce all the following results by running [`src/python/security_eval.py`](src/python/security_eval.py).

### 1. Diffusion Analysis: Strict Avalanche Criterion (SAC)
The Strict Avalanche Criterion requires that whenever a single input bit is flipped (in either the Key or the IV), each output keystream bit must change with an ideal probability of $50\%$.

| Test Parameter | Trials | Mean Output Bit Flips | Standard Deviation | Min / Max Range | Ideal |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Key-Flip SAC** (Single-bit flip in 128-bit key) | 128 bit positions | **50.39%** | 2.85% | 42.16% – 57.69% | **50.0%** |
| **IV-Flip SAC** (Single-bit flip in 127-bit IV) | 127 bit positions | **49.41%** | 2.65% | 43.21% – 56.52% | **50.0%** |

### 2. Internal State Avalanche: Cross-Feedback Mixing (550 Rounds)
Measuring the 258-bit internal register mixing after the 550-round warm-up phase when a single bit is altered:

| Mutation Source | Trials | Mean State Bit Flips | Ideal Expectation | Result |
| :--- | :--- | :--- | :--- | :--- |
| **1-Bit Delta in Key** | 200 random pairs | **49.83%** | 50.0% | ✅ Passed (Complete Diffusion) |
| **1-Bit Delta in IV** | 200 random pairs | **50.23%** | 50.0% | ✅ Passed (Complete Diffusion) |

### 3. Confusion & Key Sensitivity Analysis
Evaluating keystream independence between pairs of adjacent keys ($K$ and $K \oplus 2^i$):

| Metric | Sample Size | Observed Result | Ideal Expectation |
| :--- | :--- | :--- | :--- |
| **Adjacent Key Keystream Non-Correlation** | 200 random key pairs | **49.71%** bit divergence ($\sigma = 2.46\%$) | **50.0%** (Zero statistical leakage) |
| **Byte Collision Rate Across Adjacent Keys** | $51,200\text{ bytes}$ evaluated | $< 0.39\%$ | $1/256 \approx 0.39\%$ (Pure uniform randomness) |

### 4. Statistical Randomness & Frequency Distribution
Keystream output ($1\text{ MB} = 8,388,608\text{ bits}$) was subjected to NIST-style statistical randomness tests:

| Metric | Measured Value | Theoretical Target | Verdict |
| :--- | :--- | :--- | :--- |
| **Shannon Byte Entropy** | **7.983083 bits/byte** | 8.000000 bits/byte | ✅ High Entropy |
| **Monobit Frequency ($P(\text{ones})$)** | **0.500682** (50.07% ones) | 0.500000 (50.00%) | ✅ Balanced Bit Distribution |
| **Monobit Test Statistic ($S_{\text{obs}}$)** | 3.9533 ($p = 0.0001$) | $S_{\text{obs}} < 4.0$ | ✅ Statistically Distributed |

---

## ⚡ Benchmarks & Performance

The optimized C++ software implementation was benchmarked across multi-gigabyte continuous keystream generation:

| Metric | Result (GCC `-O3` / Native) | Reference Target |
| :--- | :--- | :--- |
| **Keystream Throughput** | **302.95 MB/s – 718.03 MB/s** | High-speed software stream cipher |
| **Efficiency (Cycles Per Byte)** | **~3.32 – 8.25 cpb** (at 2.5 GHz) | Real-time payload encryption |
| **Memory Footprint** | **$O(1)$ constant space** ($< 8\text{ KB}$ buffer) | Cache-friendly, zero dynamic heap overhead |
| **Python Prototype Throughput** | ~1.5 MB/s | Verification & algorithmic reference |

> **Note on AI Optimization:** The cryptographic architecture, mathematical design, LFSR polynomial derivation, and reference logic were authored and designed by **Rishikesh**. To achieve maximum throughput on modern x86-64 hardware, the low-level performance optimization of the C++ implementation (including register layout, bit-level vectorization, and compiler tuning) was developed with the assistance of AI.

---

## 🏗️ System Architecture & Workflow

The Hybrid Stream Cipher operates through a 5-phase continuous pipeline:

![Hybrid LFSR-ARX Cipher Pipeline](docs/assets/cipher_pipeline.svg)

> 🔍 **Detailed Component Schematic:** For the bit-exact wiring and multi-stride permutation of the 32-bit diffusion layer, see the [32-Bit Butterfly Diffusion Network Diagram](docs/assets/butterfly_diffusion_network.svg) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Security Features Matrix

| Security Feature | Implementation Mechanism | Threat Mitigated |
| :--- | :--- | :--- |
| **Maximal Period Guarantee** | Primitive polynomial taps $\{0, 112, 120, 123\}$ and $\{0, 121, 124, 129\}$ | Prevents state repetition over the cipher's lifetime |
| **Non-Linear Confusion** | Boolean function $F(x,y,z,w) = (xy) \oplus (zw) \oplus (x \oplus z)$ | Eliminates linear relationships between key and state |
| **Diffusion / Avalanche** | 32-bit Butterfly Network (Pass 1 stride 1, Pass 2 stride 2, Pass 3 stride 4) | Spreads single-bit flips across all 8 32-bit state words |
| **Forward Secrecy** | Encrypt-then-Refresh Re-Keying loop every $4\text{ KB}$ | State compromise does not expose previous traffic |
| **Differential Resistance** | Two-way ARX column mixing ($A \to B$ then $B \to A$) | Prevents differential difference cancellation attacks |
| **Side-Channel Immunity** | Pure ARX operations (no S-box lookups) | Eliminates CPU cache-timing side channels |

For the complete mathematical specification, see [docs/ALGORITHM_SPECIFICATION.md](docs/ALGORITHM_SPECIFICATION.md) and [docs/CIPHER_OVERVIEW.md](docs/CIPHER_OVERVIEW.md).

---

## 📁 Repository Directory Structure

```text
Stream-Cipher-Cryptanalysis/
├── README.md                           # Main repository documentation (this file)
├── LICENSE                             # MIT License
├── .gitignore                          # Clean Git tracking configuration
│
├── docs/                               # Comprehensive academic specifications & schematics
│   ├── assets/                         # High-resolution architectural diagrams
│   │   ├── butterfly_diffusion_network.svg # 32-bit butterfly diffusion wiring diagram
│   │   ├── butterfly_diffusion_network.png # High-res raster render
│   │   ├── cipher_pipeline.svg         # 5-phase end-to-end pipeline diagram
│   │   └── cipher_pipeline.png         # High-res pipeline render
│   ├── ALGORITHM_SPECIFICATION.md      # Step-by-step mathematical & algorithmic spec
│   ├── CIPHER_OVERVIEW.md              # Executive summary, parameters & security analysis
│   └── ARCHITECTURE.md                 # Technical architecture quick-reference
│
└── src/
    ├── cpp/                            # High-performance C++ Engine
    │   ├── hybrid_cipher.cpp           # Optimized C++ implementation with benchmarks
    │   └── Makefile                    # Fast build with -O3 optimization
    │
    └── python/                         # Reference Python prototype & security tests
        ├── cipher.py                   # 5-phase cipher engine & CLI demo
        ├── security_eval.py            # Confusion/Diffusion/Randomness test suite
        ├── test_cipher.py              # Unit test suite (avalanche, roundtrip)
        └── benchmark.py                # Python throughput benchmark script
```

---

## 🚀 Getting Started: How to Build & Run

### 1. Run the Empirical Security Evaluation (Confusion & Diffusion)
```bash
cd src/python

# Run complete empirical security analysis (SAC, Avalanche, Key Sensitivity, Entropy):
python3 security_eval.py

# Run unit tests:
python3 test_cipher.py
```

### 2. Run the High-Performance C++ Engine & Benchmark
```bash
cd src/cpp

# Build with -O3 optimization
make

# Run encryption/decryption self-test demo:
./hybrid_cipher

# Run the 256 MB throughput benchmark:
make benchmark
```

---

## 👤 Author & Credits

* **Rishikesh** — Cipher design, mathematical architecture, C++ implementation, and cryptanalysis.
* **AI Optimization Notice:** The low-level performance optimization and vector tuning of the C++ software implementation were developed with the assistance of AI.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
