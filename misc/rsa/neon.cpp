#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <arm_neon.h>
#include <gmp.h>

#define KEYLEN 32

using u128 = __uint128_t;

static std::mutex print_mutex;
static std::condition_variable cv;
static std::atomic<bool> found{false};

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

static inline int MakeRandom(uint8_t* out, int len, int rseed) {
    int seed = rseed;
    for (int j = 0; j < len; j++) {
        seed = seed * 0x8088405 + 1;
        uint64_t lval = (uint64_t)(uint32_t)seed * 0xDFULL;
        out[j] = (uint8_t)((lval >> 32) + 0x20);
    }
    return seed;
}

static inline void bytes_to_limbs_256(const uint8_t* b, uint64_t l[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | b[i * 8 + k];
        l[3 - i] = v;
    }
}

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

static inline bool in_range(const uint64_t n[8], const uint64_t prod[8], const uint64_t gap[8]) {
    uint64_t sub[8];
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        u128 x = (u128)n[i] - prod[i] - borrow;
        sub[i] = (uint64_t)x;
        borrow = (uint64_t)((x >> 64) & 1);
    }
    if (borrow) return false;
    for (int i = 7; i >= 0; i--) {
        if (sub[i] != gap[i]) return sub[i] < gap[i];
    }
    return true;
}

// 4-wide NEON LCG: generate 32 p-bytes and 32 q-bytes for each of 4 consecutive seeds.
static inline void gen4_pq_bytes(uint32_t seed_base,
                                 uint8_t p[4][KEYLEN],
                                 uint8_t q[4][KEYLEN]) {
    uint32x4_t state = { seed_base, seed_base + 1, seed_base + 2, seed_base + 3 };
    const uint32x4_t mulc   = vdupq_n_u32(0x8088405);
    const uint32x4_t addone = vdupq_n_u32(1);
    const uint32x4_t add20  = vdupq_n_u32(0x20);

    for (int j = 0; j < KEYLEN; j++) {
        state = vmlaq_u32(addone, state, mulc);
        uint64x2_t lo_prod = vmull_n_u32(vget_low_u32(state),  0xDF);
        uint64x2_t hi_prod = vmull_n_u32(vget_high_u32(state), 0xDF);
        uint32x4_t high    = vcombine_u32(vshrn_n_u64(lo_prod, 32),
                                          vshrn_n_u64(hi_prod, 32));
        uint32x4_t bytes   = vaddq_u32(high, add20);
        p[0][j] = (uint8_t)vgetq_lane_u32(bytes, 0);
        p[1][j] = (uint8_t)vgetq_lane_u32(bytes, 1);
        p[2][j] = (uint8_t)vgetq_lane_u32(bytes, 2);
        p[3][j] = (uint8_t)vgetq_lane_u32(bytes, 3);
    }
    for (int j = 0; j < KEYLEN; j++) {
        state = vmlaq_u32(addone, state, mulc);
        uint64x2_t lo_prod = vmull_n_u32(vget_low_u32(state),  0xDF);
        uint64x2_t hi_prod = vmull_n_u32(vget_high_u32(state), 0xDF);
        uint32x4_t high    = vcombine_u32(vshrn_n_u64(lo_prod, 32),
                                          vshrn_n_u64(hi_prod, 32));
        uint32x4_t bytes   = vaddq_u32(high, add20);
        q[0][j] = (uint8_t)vgetq_lane_u32(bytes, 0);
        q[1][j] = (uint8_t)vgetq_lane_u32(bytes, 1);
        q[2][j] = (uint8_t)vgetq_lane_u32(bytes, 2);
        q[3][j] = (uint8_t)vgetq_lane_u32(bytes, 3);
    }
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
    uint8_t p_bytes[4][KEYLEN];
    uint8_t q_bytes[4][KEYLEN];
    uint64_t p_limbs[4], q_limbs[4], prod[8];

    // Use int64_t to avoid signed-int overflow in the comparison/increment
    int64_t s = start;
    int64_t e = end;

    while (s + 3 <= e) {
        if ((s & 0xFFFF) == 0 && found.load(std::memory_order_relaxed)) return;

        gen4_pq_bytes((uint32_t)(int32_t)s, p_bytes, q_bytes);
        for (int k = 0; k < 4; k++) {
            bytes_to_limbs_256(p_bytes[k], p_limbs);
            bytes_to_limbs_256(q_bytes[k], q_limbs);
            mul_256x256(p_limbs, q_limbs, prod);
            if (!in_range(g_n, prod, g_gap)) continue;
            handle_hit((int)(s + k));
        }
        s += 4;
    }
    // scalar tail
    for (; s <= e; s++) {
        if (found.load(std::memory_order_relaxed)) return;
        uint8_t rbuf[KEYLEN];
        int ns = MakeRandom(rbuf, KEYLEN, (int)s);
        bytes_to_limbs_256(rbuf, p_limbs);
        MakeRandom(rbuf, KEYLEN, ns);
        bytes_to_limbs_256(rbuf, q_limbs);
        mul_256x256(p_limbs, q_limbs, prod);
        if (!in_range(g_n, prod, g_gap)) continue;
        handle_hit((int)s);
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
