#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <gmp.h>

#define KEYLEN 32

using u128 = __uint128_t;

static std::mutex print_mutex;
static std::condition_variable cv;
static std::atomic<bool> found{false};

// n and gap as little-endian 64-bit limbs (limb[0] = LSB, limb[7] = MSB)
static uint64_t g_n[8];
static uint64_t g_gap[8];

static const char* N_HEX   = "B3EFAF2E3A1FDF4C496EC1FEFEFC8C93603004CB36E0F24AEBC4E8A2E37D6F65407378FAA5288E67BB8567E530BA7DC58A9739D8B9700BA0965B736AB8E029B1";
static const char* GAP_HEX = "F2BC6E68B42E43CB19056EA8986F4816D346E7D12CCB66B2AD2C18D8EA1BEF001E0";

static void parse_hex_to_limbs(const char* hex, uint64_t limbs[8]) {
    char buf[129];
    memset(buf, '0', 128);
    size_t len = strlen(hex);
    memcpy(buf + (128 - len), hex, len);
    buf[128] = 0;
    for (int i = 0; i < 8; i++) {
        char chunk[17];
        memcpy(chunk, buf + i * 16, 16);
        chunk[16] = 0;
        limbs[7 - i] = strtoull(chunk, nullptr, 16);
    }
}

// LCG producing len bytes; returns final seed state
static inline int MakeRandom(uint8_t* out, int len, int rseed) {
    int seed = rseed;
    for (int j = 0; j < len; j++) {
        seed = seed * 0x8088405 + 1;
        uint64_t lval = (uint64_t)(uint32_t)seed * 0xDFULL;
        out[j] = (uint8_t)((lval >> 32) + 0x20);
    }
    return seed;
}

// bytes are big-endian (b[0] most significant) -> little-endian limbs
static inline void bytes_to_limbs_256(const uint8_t* b, uint64_t l[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | b[i * 8 + k];
        l[3 - i] = v;
    }
}

// 256-bit x 256-bit -> 512-bit schoolbook multiply
static inline void mul_256x256(const uint64_t a[4], const uint64_t b[4], uint64_t r[8]) {
    for (int i = 0; i < 8; i++) r[i] = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 prod = (u128)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        r[i + 4] = carry;
    }
}

// Returns true iff 0 <= n - prod <= gap
static inline bool in_range(const uint64_t n[8], const uint64_t prod[8], const uint64_t gap[8]) {
    uint64_t sub[8];
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        u128 x = (u128)n[i] - prod[i] - borrow;
        sub[i] = (uint64_t)x;
        borrow = (uint64_t)((x >> 64) & 1);
    }
    if (borrow) return false; // prod > n
    for (int i = 7; i >= 0; i--) {
        if (sub[i] != gap[i]) return sub[i] < gap[i];
    }
    return true;
}

static void handle_hit(int seed) {
    mpz_t mp, mq, mn, phi, d, e;
    mpz_inits(mp, mq, mn, phi, d, e, NULL);
    mpz_set_str(mn, N_HEX, 16);

    uint8_t buf[KEYLEN];
    int ns = MakeRandom(buf, KEYLEN, seed);
    mpz_import(mp, KEYLEN, 1, 1, 0, 0, buf);
    MakeRandom(buf, KEYLEN, ns);
    mpz_import(mq, KEYLEN, 1, 1, 0, 0, buf);

    mpz_nextprime(mp, mp);
    if (mpz_divisible_p(mn, mp)) {
        mpz_nextprime(mq, mq);
        std::lock_guard<std::mutex> lock(print_mutex);
        if (!found.exchange(true)) {
            gmp_printf("p:\n%ZX\n\nq:\n%ZX\n\nn (p * q):\n%ZX\n", mp, mq, mn);
            mpz_sub_ui(mp, mp, 1);
            mpz_sub_ui(mq, mq, 1);
            mpz_mul(phi, mp, mq);
            mpz_set_ui(e, 65537);
            mpz_invert(d, e, phi);
            gmp_printf("(d, phi): (%ZX, %ZX)\n", d, phi);
            std::cout << "Seed " << std::hex << seed << std::endl;
            cv.notify_all();
        }
    }
    mpz_clears(mp, mq, mn, phi, d, e, NULL);
}

static void searchRange(int start, int end) {
    uint64_t p_limbs[4], q_limbs[4], prod[8];
    uint8_t rbuf[KEYLEN];

    for (int seed = start; seed <= end; seed++) {
        if ((seed & 0xFFFF) == 0 && found.load(std::memory_order_relaxed)) break;

        int ns = MakeRandom(rbuf, KEYLEN, seed);
        bytes_to_limbs_256(rbuf, p_limbs);
        MakeRandom(rbuf, KEYLEN, ns);
        bytes_to_limbs_256(rbuf, q_limbs);

        mul_256x256(p_limbs, q_limbs, prod);
        if (!in_range(g_n, prod, g_gap)) continue;

        handle_hit(seed);
    }
}

int main() {
    parse_hex_to_limbs(N_HEX, g_n);
    parse_hex_to_limbs(GAP_HEX, g_gap);

    const unsigned int numThreads = std::thread::hardware_concurrency();
    std::cout << "Spawning " << std::dec << numThreads << " threads" << std::endl;

    std::vector<std::thread> threads;
    int range = 0xFFFFFFFF / numThreads;
    int start = 0;
    for (unsigned i = 0; i < numThreads; i++) {
        int end = (i == numThreads - 1) ? 0xFFFFFFFF : start + range;
        threads.emplace_back(searchRange, start, end);
        start = end + 1;
    }

    {
        std::unique_lock<std::mutex> lock(print_mutex);
        cv.wait(lock, [] { return found.load(); });
    }
    for (auto& t : threads) t.join();
    return 0;
}
