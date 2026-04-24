#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <chrono>
#include <gmp.h>

static const char* N_HEX   = "B3EFAF2E3A1FDF4C496EC1FEFEFC8C93603004CB36E0F24AEBC4E8A2E37D6F65407378FAA5288E67BB8567E530BA7DC58A9739D8B9700BA0965B736AB8E029B1";
static const char* GAP_HEX = "F2BC6E68B42E43CB19056EA8986F4816D346E7D12CCB66B2AD2C18D8EA1BEF001E0";

static const char* kMetalSrc = R"MSL(
#include <metal_stdlib>
using namespace metal;

kernel void search(
    device atomic_uint *found        [[buffer(0)]],
    constant uint      *n_limbs      [[buffer(1)]],   // 16 x uint32, little-endian
    constant uint      *gap_limbs    [[buffer(2)]],
    constant uint      &base_seed    [[buffer(3)]],
    uint                tid          [[thread_position_in_grid]])
{
    uint seed = base_seed + tid;

    uint s = seed;
    uchar pbytes[32], qbytes[32];
    for (int j = 0; j < 32; j++) {
        s = s * 0x8088405u + 1u;
        ulong lv = (ulong)s * 0xDFul;
        pbytes[j] = uchar((lv >> 32) + 0x20u);
    }
    for (int j = 0; j < 32; j++) {
        s = s * 0x8088405u + 1u;
        ulong lv = (ulong)s * 0xDFul;
        qbytes[j] = uchar((lv >> 32) + 0x20u);
    }

    // Pack bytes (big-endian within the number) into 8 x uint32 little-endian limbs
    uint p[8], q[8];
    for (int i = 0; i < 8; i++) {
        p[7 - i] = ((uint)pbytes[i*4]     << 24) |
                   ((uint)pbytes[i*4 + 1] << 16) |
                   ((uint)pbytes[i*4 + 2] <<  8) |
                    (uint)pbytes[i*4 + 3];
        q[7 - i] = ((uint)qbytes[i*4]     << 24) |
                   ((uint)qbytes[i*4 + 1] << 16) |
                   ((uint)qbytes[i*4 + 2] <<  8) |
                    (uint)qbytes[i*4 + 3];
    }

    // 256x256 -> 512 bit schoolbook multiply, 32-bit limbs with 64-bit intermediate
    uint prod[16];
    for (int i = 0; i < 16; i++) prod[i] = 0u;
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong pp = (ulong)p[i] * (ulong)q[j] + (ulong)prod[i + j] + carry;
            prod[i + j] = (uint)pp;
            carry = pp >> 32;
        }
        prod[i + 8] = (uint)carry;
    }

    // sub = n - prod, 32-bit limbs with borrow
    ulong borrow = 0;
    uint sub[16];
    for (int i = 0; i < 16; i++) {
        ulong x = (ulong)n_limbs[i] - (ulong)prod[i] - borrow;
        sub[i] = (uint)x;
        borrow = (x >> 32) & 1ul;
    }
    if (borrow) return;                 // prod > n

    // compare sub vs gap (both little-endian limbs)
    for (int i = 15; i >= 0; i--) {
        if (sub[i] > gap_limbs[i]) return;      // sub > gap
        if (sub[i] < gap_limbs[i]) break;       // sub < gap → hit
    }

    // Write seed+1 so that 0 means "not found"
    atomic_store_explicit(found, seed + 1u, memory_order_relaxed);
}
)MSL";

static void parse_hex_32limbs(const char* hex, uint32_t limbs[16]) {
    char buf[129];
    memset(buf, '0', 128);
    size_t len = strlen(hex);
    memcpy(buf + (128 - len), hex, len);
    buf[128] = 0;
    for (int i = 0; i < 16; i++) {
        char chunk[9];
        memcpy(chunk, buf + i * 8, 8);
        chunk[8] = 0;
        limbs[15 - i] = (uint32_t)strtoul(chunk, nullptr, 16);
    }
}

static int MakeRandom(uint8_t* out, int len, int rseed) {
    int seed = rseed;
    for (int j = 0; j < len; j++) {
        seed = seed * 0x8088405 + 1;
        uint64_t lval = (uint64_t)(uint32_t)seed * 0xDFULL;
        out[j] = (uint8_t)((lval >> 32) + 0x20);
    }
    return seed;
}

static bool handle_hit(int seed) {
    mpz_t mp, mq, mn, phi, d, e;
    mpz_inits(mp, mq, mn, phi, d, e, NULL);
    mpz_set_str(mn, N_HEX, 16);
    uint8_t buf[32];
    int ns = MakeRandom(buf, 32, seed);
    mpz_import(mp, 32, 1, 1, 0, 0, buf);
    MakeRandom(buf, 32, ns);
    mpz_import(mq, 32, 1, 1, 0, 0, buf);
    mpz_nextprime(mp, mp);
    bool ok = mpz_divisible_p(mn, mp) != 0;
    if (ok) {
        mpz_nextprime(mq, mq);
        gmp_printf("p:\n%ZX\n\nq:\n%ZX\n\nn (p * q):\n%ZX\n", mp, mq, mn);
        mpz_sub_ui(mp, mp, 1);
        mpz_sub_ui(mq, mq, 1);
        mpz_mul(phi, mp, mq);
        mpz_set_ui(e, 65537);
        mpz_invert(d, e, phi);
        gmp_printf("(d, phi): (%ZX, %ZX)\n", d, phi);
        std::cout << "Seed " << std::hex << seed << std::endl;
    }
    mpz_clears(mp, mq, mn, phi, d, e, NULL);
    return ok;
}

int main() {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) { std::cerr << "No Metal device\n"; return 1; }
        std::cout << "GPU: " << [device.name UTF8String] << std::endl;

        NSError* err = nil;
        id<MTLLibrary> lib = [device newLibraryWithSource:@(kMetalSrc) options:nil error:&err];
        if (!lib) {
            std::cerr << "Compile error: " << [err.localizedDescription UTF8String] << "\n";
            return 1;
        }
        id<MTLFunction> fn = [lib newFunctionWithName:@"search"];
        id<MTLComputePipelineState> pso =
            [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pso) {
            std::cerr << "PSO error: " << [err.localizedDescription UTF8String] << "\n";
            return 1;
        }
        id<MTLCommandQueue> queue = [device newCommandQueue];

        uint32_t n_limbs[16], gap_limbs[16];
        parse_hex_32limbs(N_HEX, n_limbs);
        parse_hex_32limbs(GAP_HEX, gap_limbs);

        id<MTLBuffer> n_buf   = [device newBufferWithBytes:n_limbs   length:sizeof(n_limbs)   options:MTLResourceStorageModeShared];
        id<MTLBuffer> gap_buf = [device newBufferWithBytes:gap_limbs length:sizeof(gap_limbs) options:MTLResourceStorageModeShared];
        id<MTLBuffer> found_buf = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        *((uint32_t*)found_buf.contents) = 0;

        const uint64_t TOTAL = 1ull << 32;
        const uint64_t BATCH = 1ull << 28;      // 256M threads per dispatch
        uint32_t found_raw = 0;

        NSUInteger tpg = pso.maxTotalThreadsPerThreadgroup;
        std::cout << "Threads per threadgroup: " << tpg
                  << ", batch size: " << BATCH
                  << ", batches: " << (TOTAL / BATCH) << std::endl;

        auto t0 = std::chrono::steady_clock::now();

        for (uint64_t base = 0; base < TOTAL; base += BATCH) {
            id<MTLCommandBuffer> cmd = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
            [enc setComputePipelineState:pso];
            [enc setBuffer:found_buf offset:0 atIndex:0];
            [enc setBuffer:n_buf     offset:0 atIndex:1];
            [enc setBuffer:gap_buf   offset:0 atIndex:2];
            uint32_t base_seed = (uint32_t)base;
            [enc setBytes:&base_seed length:sizeof(base_seed) atIndex:3];
            [enc dispatchThreads:MTLSizeMake((NSUInteger)BATCH, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(tpg, 1, 1)];
            [enc endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];

            found_raw = *((uint32_t*)found_buf.contents);
            if (found_raw) break;
        }

        auto t1 = std::chrono::steady_clock::now();
        double gpu_seconds = std::chrono::duration<double>(t1 - t0).count();
        std::cout << "GPU search time: " << gpu_seconds << "s" << std::endl;

        if (!found_raw) { std::cerr << "Not found\n"; return 2; }
        uint32_t seed = found_raw - 1;
        if (!handle_hit((int)seed)) {
            std::cerr << "False positive at seed " << std::hex << seed << "\n";
            return 3;
        }
    }
    return 0;
}
