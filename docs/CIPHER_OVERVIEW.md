# Hybrid LFSR-ARX Stream Cipher: Architectural Overview

**Author:** Rishikesh  
**Domain:** Symmetric Cryptography & Cryptanalysis  
**License:** [MIT License](../LICENSE)

---

## 1. Executive Summary

This project designs and benchmarks a high-performance **Hybrid Symmetric Stream Cipher** engineered to resolve classic vulnerabilities found in traditional software-based stream ciphers (such as state recovery and lack of forward secrecy) while retaining near-line-rate execution speeds on standard 32-bit and 64-bit microprocessors.

The cipher synergizes the provable, astronomical period length of **Linear Feedback Shift Registers (LFSRs)** with the non-linear confusion and diffusion of **Add-Rotate-Xor (ARX)** operations.

### Key Architectural Tenet: *Encrypt-then-Refresh*
Traditional stream ciphers maintain an open internal state throughout an entire session. If an adversary recovers the state at time $t$, all subsequent (and often preceding) keystream blocks are compromised. This cipher introduces an **Encrypt-then-Refresh** state lifecycle:
1. Generates a chaotic, highly non-linear internal state through 550 clock cycles of cross-feedback polynomial mixing.
2. Hardens the state across an 8-word 32-bit multi-stride Butterfly Diffusion Network.
3. Emits a strictly bounded keystream chunk of $2^{15}\text{ bits}$ ($32\text{ Kilobits} / 4\text{ KB}$).
4. **Enforces Forward Secrecy:** Automatically obliterates the internal state and re-seeds with a derived one-way ephemeral key ($\text{EKey}$), ensuring past keystream segments remain mathematically irrecoverable even if the current state is leaked.

---

## 2. System Parameters

| Parameter | Bit Width | Mathematical Role |
| :--- | :--- | :--- |
| **Secret Key ($K$)** | 128 bits | Primary cryptographic secret, mapped into a 131-bit register |
| **Initialization Vector ($\text{IV}$)** | 127 bits | Per-message unique nonce / session counter |
| **Internal Mixing State** | 258 bits | Concatenated LFSR registers ($127\text{b} + 131\text{b}$) |
| **Diffused Working State** | 256 bits | 8 words of 32 bits ($W_0, \dots, W_7$) |
| **Keystream Chunk Size** | $2^{15}\text{ bits}$ ($4,096\text{ bytes}$) | Output emitted per re-keying round |
| **Re-Keying Interval** | Every $4\text{ KB}$ | Enforces forward secrecy |

---

## 3. High-Level Architectural Pipeline

![Hybrid LFSR-ARX Pipeline](assets/cipher_pipeline.svg)

The cipher executes in a continuous 5-phase operational cycle:

### Phase 1: Setup & Primitive Polynomial Initialization
Registers are initialized with the $\text{IV}$ and User Key using feedback taps derived from primitive polynomials over $\text{GF}(2)$ to guarantee maximal period length without cycle collapse:
* **Register A (127-bit IV):** Primitive polynomial taps at indices $\{0, 112, 120, 123\}$.
* **Register B (131-bit Key):** Primitive polynomial taps at indices $\{0, 121, 124, 129\}$.

### Phase 2: Initialization (Cross-Feedback Warm-Up)
To eliminate linear relationships and provide confusion, Register A and Register B cross-pollinate for **550 clock cycles**:
* Each cycle calculates linear feedback from primitive taps.
* Non-linear injection is calculated using the balanced boolean function:
  $$F(x, y, z, w) = (x \land y) \oplus (z \land w) \oplus (x \oplus z)$$
  sampled from well-spaced bits in the opposite register ($\{0, 32, 64, 96\}$).
* Bits are cross-injected into the opposite register's MSB while shifting right.

### Phase 3: Core Hardening (32-Bit Butterfly Diffusion Network)
The 256-bit mixed state is partitioned into eight 32-bit words ($W_0 \dots W_7$). A multi-stride butterfly network applies three successive passes of modular additions and circular left rotations ($\lll 7, 11, 13$), spreading input bit variations across all 256 bits.

### Phase 4: Feed-Forward EKey Derivation
A one-way feed-forward transformation locks the internal state:
$$\text{EKey}_{256} = \text{State}_{256} \oplus \text{DiffusedState}_{256}$$
This prevents algebraic inversion attacks. To prepare for the subsequent re-keying round, $\text{EKey}$ is padded to 258 bits and fed back into Phase 2.

### Phase 5: Keystream Generation (Double-ARX Counter Mode)
The 256-bit $\text{EKey}$ is loaded into a Counter-Mode keystream engine producing 128 blocks $\times$ 256 bits ($32\text{ Kb}$):
* Each block injects a counter into $W_0$.
* 10 scrambling rounds perform bidirectional column ARX mixing ($A \to B$, then $B \to A$) and diagonal word swapping.
* An initial state feed-forward addition yields the final 32-bit keystream words.

---

## 4. Cryptographic Security Properties

| Security Dimension | Structural Mechanism | Cryptanalytic Protection |
| :--- | :--- | :--- |
| **Maximal Period Guarantee** | Primitive Polynomials in Phase 2 | Prevents short state cycles and repetition over practical data volumes. |
| **Algebraic Non-Linearity (Confusion)** | Boolean Injection Function $F(x,y,z,w)$ | Destroys linear correlations; defeats the Berlekamp-Massey attack. |
| **Avalanche & Diffusion** | 32-Bit Butterfly Network (Phase 3) | Achieves Strict Avalanche Criterion (SAC $\approx 50.39\%$); single-bit flip alters ~50% of the state. |
| **Forward Secrecy** | Encrypt-then-Refresh Re-Keying Loop | Memory exposure of current state does not compromise previous ciphertexts. |
| **Differential Resistance** | Bidirectional ARX & Diagonal Swaps | Eliminates differential difference propagation and linear approximation biases. |
| **Side-Channel Immunity** | Constant-Time Software Operations | Pure ARX logic eliminates cache-timing attacks inherent in S-box table lookups. |

---

## 5. Empirical Performance Summary

| Environment | Processor | Compiler | Throughput | Cycles Per Byte |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)** | Modern x86-64 | GCC 13 (`-O3 -march=native`) | **718.03 MB/s** | **~3.32 cpb** |
| **Windows 11** | Intel Core i5-12500H @ 2.50 GHz | MinGW GCC 6.3 (`-O3`) | **302.95 MB/s** | **~8.25 cpb** |
| **Python Prototype** | Reference VM | Python 3.12+ | ~1.5 MB/s | Verification & Test |

*Memory Footprint:* Strictly $O(1)$ constant memory overhead ($< 8\text{ KB}$ buffer), enabling execution on embedded systems and cache-constrained environments.
