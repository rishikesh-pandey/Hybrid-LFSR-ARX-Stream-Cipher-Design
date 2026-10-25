/*
 * Hybrid LFSR-ARX Stream Cipher Implementation (C++)
 * ===================================================
 * High-performance symmetric stream cipher combining Linear Feedback Shift Registers (LFSRs)
 * with Add-Rotate-Xor (ARX) operations.
 *
 * Architecture:
 * 1. Setup: 128-bit key, 127-bit IV
 * 2. Cross-Feedback Mixing: 550 rounds of cross-register polynomial feedback & non-linear injection
 * 3. Butterfly Diffusion Network: 3-pass 32-bit modular additions and rotations (7, 11, 13)
 * 4. Feed-Forward & Re-Keying: EKey generation and Encrypt-then-Refresh forward secrecy
 * 5. Double-ARX Keystream Generation: 128 counter blocks * 256 bits = 32 Kb per round
 */

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <cstdint>
#include <algorithm>

using namespace std;

// --- Bitwise & Rotation Helpers ---

static inline uint32_t rotl32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t nonLinearF(uint32_t x, uint32_t y, uint32_t z, uint32_t w) {
    return (x & y) ^ (z & w) ^ (x ^ z);
}

// Fixed-width registers for Phase 2 LFSR Cross-Mixing
struct Register127 {
    uint64_t words[2]; // 128 bits capacity, valid bits 0..126

    Register127() { words[0] = 0; words[1] = 0; }
    Register127(uint64_t low, uint64_t high) {
        words[0] = low;
        words[1] = high & 0x7FFFFFFFFFFFFFFFULL; // mask to 127 bits
    }

    inline int getBit(int n) const {
        return (words[n / 64] >> (n % 64)) & 1ULL;
    }

    inline void shiftRightInsertMSB(int newBit) {
        words[0] = (words[0] >> 1) | (words[1] << 63);
        words[1] = (words[1] >> 1) | (((uint64_t)newBit & 1ULL) << 62);
    }
};

struct Register131 {
    uint64_t words[3]; // valid bits 0..130

    Register131() { words[0] = 0; words[1] = 0; words[2] = 0; }
    Register131(uint64_t w0, uint64_t w1, uint64_t w2) {
        words[0] = w0;
        words[1] = w1;
        words[2] = w2 & 0x7ULL; // 131 bits total (64 + 64 + 3)
    }

    inline int getBit(int n) const {
        return (words[n / 64] >> (n % 64)) & 1ULL;
    }

    inline void shiftRightInsertMSB(int newBit) {
        words[0] = (words[0] >> 1) | (words[1] << 63);
        words[1] = (words[1] >> 1) | (words[2] << 63);
        words[2] = (words[2] >> 1) | (((uint64_t)newBit & 1ULL) << 2);
    }
};

// 256-bit word container
struct State256 {
    uint32_t words[8];

    State256() {
        memset(words, 0, sizeof(words));
    }
};

// --- Phase 2: Cross-Feedback Mixing ---
void crossFeedbackMixing(Register127& regA, Register131& regB, State256& outState, int rounds = 550) {
    for (int r = 0; r < rounds; ++r) {
        // Linear feedback (primitive polynomial taps)
        int a_linear = regA.getBit(0) ^ regA.getBit(112) ^ regA.getBit(120) ^ regA.getBit(123);
        int b_linear = regB.getBit(0) ^ regB.getBit(121) ^ regB.getBit(124) ^ regB.getBit(129);

        // Non-linear injection from opposite register
        int f_out_b = nonLinearF(regB.getBit(0), regB.getBit(32), regB.getBit(64), regB.getBit(96));
        int f_out_a = nonLinearF(regA.getBit(0), regA.getBit(32), regA.getBit(64), regA.getBit(96));

        int a_new = a_linear ^ f_out_b;
        int b_new = b_linear ^ f_out_a;

        regA.shiftRightInsertMSB(a_new);
        regB.shiftRightInsertMSB(b_new);
    }

    // Pack into 256-bit output state
    uint64_t raw[4];
    raw[0] = regB.words[0];
    raw[1] = regB.words[1];
    raw[2] = (regB.words[2] & 0x7ULL) | (regA.words[0] << 3);
    raw[3] = (regA.words[0] >> 61) | (regA.words[1] << 3);

    for (int i = 0; i < 8; ++i) {
        outState.words[i] = (uint32_t)((raw[i / 2] >> ((i % 2) * 32)) & 0xFFFFFFFF);
    }
}

// --- Phase 3: Butterfly Diffusion Layer ---
State256 butterflyDiffusion(const State256& in) {
    State256 out = in;

    // Pass 1: Stride 1 (Mix Pairs), Rotate 7
    for (int i = 0; i < 8; i += 2) {
        out.words[i] += out.words[i + 1];
    }
    for (int i = 0; i < 8; ++i) {
        out.words[i] = rotl32(out.words[i], 7);
    }

    // Pass 2: Stride 2 (Mix Cross), Rotate 11
    for (int i = 0; i < 8; i += 4) {
        out.words[i] += out.words[i + 2];
        out.words[i + 1] += out.words[i + 3];
    }
    for (int i = 0; i < 8; ++i) {
        out.words[i] = rotl32(out.words[i], 11);
    }

    // Pass 3: Stride 4 (Mix Wide), Rotate 13
    for (int i = 0; i < 4; ++i) {
        out.words[i] += out.words[i + 4];
    }
    for (int i = 0; i < 8; ++i) {
        out.words[i] = rotl32(out.words[i], 13);
    }

    return out;
}

// --- Phase 5: Double-ARX Counter Mode Keystream Generator ---
void generateKeystreamBlockRobust(const State256& ekey, uint8_t* outBuffer, int totalBlocks = 128) {
    uint32_t* outWords = reinterpret_cast<uint32_t*>(outBuffer);
    size_t wordOffset = 0;

    for (uint32_t counter = 1; counter <= (uint32_t)totalBlocks; ++counter) {
        uint32_t state[8];
        memcpy(state, ekey.words, sizeof(state));
        state[0] ^= counter;

        // 10 Scrambling rounds of two-way ARX
        for (int r = 0; r < 10; ++r) {
            // Column mix: (0,4), (1,5), (2,6), (3,7)
            for (int i = 0; i < 4; ++i) {
                int a = i, b = i + 4;
                // Forward mix
                state[a] += state[b];
                state[b] ^= state[a];
                state[b] = rotl32(state[b], 13);

                // Backward mix
                state[a] ^= state[b];
                state[a] = rotl32(state[a], 9);
            }

            // Swap layer
            swap(state[1], state[2]);
            swap(state[3], state[4]);
            swap(state[5], state[6]);
            swap(state[7], state[0]);
        }

        // Feed-Forward
        for (int k = 0; k < 8; ++k) {
            uint32_t baseVal = ekey.words[k];
            if (k == 0) baseVal ^= counter;
            outWords[wordOffset++] = state[k] + baseVal;
        }
    }
}

// --- High-Level Cipher Class ---
class HybridStreamCipher {
private:
    Register127 regA;
    Register131 regB;
    State256 currentState;
    vector<uint8_t> buffer;
    size_t bufferIndex;

    void refreshKeystreamChunk() {
        State256 diffused = butterflyDiffusion(currentState);
        State256 ekey;
        for (int i = 0; i < 8; ++i) {
            ekey.words[i] = currentState.words[i] ^ diffused.words[i];
        }

        buffer.resize(128 * 32); // 4096 bytes
        generateKeystreamBlockRobust(ekey, buffer.data(), 128);
        bufferIndex = 0;

        // Re-keying setup for Forward Secrecy
        regA = Register127(
            ((uint64_t)ekey.words[0]) | (((uint64_t)ekey.words[1]) << 32),
            ((uint64_t)ekey.words[2]) | (((uint64_t)ekey.words[3]) << 32)
        );
        regB = Register131(
            ((uint64_t)ekey.words[4]) | (((uint64_t)ekey.words[5]) << 32),
            ((uint64_t)ekey.words[6]) | (((uint64_t)ekey.words[7]) << 32),
            (uint64_t)(ekey.words[7] >> 29)
        );
        crossFeedbackMixing(regA, regB, currentState, 256);
    }

public:
    HybridStreamCipher(uint64_t keyLow, uint64_t keyHigh, uint64_t ivLow = 1, uint64_t ivHigh = 0)
        : regA(ivLow, ivHigh), regB(keyLow, keyHigh, 0), bufferIndex(0) {
        crossFeedbackMixing(regA, regB, currentState, 550);
    }

    void getKeystream(uint8_t* dest, size_t length) {
        size_t generated = 0;
        while (generated < length) {
            if (bufferIndex >= buffer.size()) {
                refreshKeystreamChunk();
            }
            size_t take = min(length - generated, buffer.size() - bufferIndex);
            memcpy(dest + generated, buffer.data() + bufferIndex, take);
            bufferIndex += take;
            generated += take;
        }
    }

    void process(const uint8_t* input, uint8_t* output, size_t length) {
        vector<uint8_t> ks(length);
        getKeystream(ks.data(), length);
        for (size_t i = 0; i < length; ++i) {
            output[i] = input[i] ^ ks[i];
        }
    }
};

static string toHex(const uint8_t* data, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << setw(2) << (int)data[i];
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    cout << "=========================================================\n";
    cout << "     Hybrid LFSR-ARX Stream Cipher (C++ Engine)          \n";
    cout << "=========================================================\n";

    bool benchmarkMode = (argc > 1 && string(argv[1]) == "--benchmark");

    if (benchmarkMode) {
        const size_t totalMB = 256;
        const size_t totalBytes = totalMB * 1024 * 1024;
        cout << "[*] Running High-Performance Throughput Benchmark (" << totalMB << " MB)...\n";

        HybridStreamCipher cipher(0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL);
        vector<uint8_t> chunk(64 * 1024); // 64 KB block
        size_t bytesProcessed = 0;

        auto start = chrono::high_resolution_clock::now();
        while (bytesProcessed < totalBytes) {
            cipher.getKeystream(chunk.data(), chunk.size());
            bytesProcessed += chunk.size();
        }
        auto end = chrono::high_resolution_clock::now();

        chrono::duration<double> elapsed = end - start;
        double throughput = (double)totalMB / elapsed.count();
        double cpb = (elapsed.count() * 2.5e9) / (double)totalBytes; // normalized to 2.5 GHz

        cout << "\n--- Benchmark Results ---\n";
        cout << "Data Generated: " << totalMB << " MB (" << totalBytes << " bytes)\n";
        cout << "Time Elapsed:   " << fixed << setprecision(3) << elapsed.count() << " seconds\n";
        cout << "Throughput:     " << fixed << setprecision(2) << throughput << " MB/s\n";
        cout << "Efficiency:     ~" << fixed << setprecision(2) << cpb << " Cycles Per Byte (at 2.5 GHz)\n";
        return 0;
    }

    // Demo Mode
    cout << "[*] Running Verification Demo...\n";
    uint64_t keyL = 0x1A2B3C4D5E6F7081ULL;
    uint64_t keyH = 0x92A3B4C5D6E7F809ULL;
    uint64_t ivL  = 0x0000000000000001ULL;

    HybridStreamCipher enc(keyL, keyH, ivL);
    HybridStreamCipher dec(keyL, keyH, ivL);

    string message = "Cryptanalysis Course Project: Robust Hybrid Stream Cipher!";
    vector<uint8_t> plaintext(message.begin(), message.end());
    vector<uint8_t> ciphertext(plaintext.size());
    vector<uint8_t> decrypted(plaintext.size());

    enc.process(plaintext.data(), ciphertext.data(), plaintext.size());
    dec.process(ciphertext.data(), decrypted.data(), ciphertext.size());

    string recovered(decrypted.begin(), decrypted.end());
    cout << "Original Text:  " << message << "\n";
    cout << "Ciphertext Hex: " << toHex(ciphertext.data(), ciphertext.size()) << "\n";
    cout << "Decrypted Text: " << recovered << "\n";

    if (recovered == message) {
        cout << "[+] Self-Test: PASSED (Encryption & Decryption match!)\n";
    } else {
        cout << "[-] Self-Test: FAILED!\n";
        return 1;
    }

    cout << "\nTip: Run with '--benchmark' to measure keystream throughput:\n";
    cout << "     ./hybrid_cipher --benchmark\n";

    return 0;
}
