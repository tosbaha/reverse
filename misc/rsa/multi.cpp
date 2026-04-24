#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <gmp.h>

std::mutex print_mutex;
std::condition_variable cv;
bool found = false;
#define KEYLEN 32


// Function to create a random number of given length using the provided seed
int MakeRandom(char *out, int len, int rseed) {
    int seed = rseed, j = 0;
    char *p = out;

    do {
        seed = seed * (int)0x8088405 + 1;
        u_int64_t lval = (unsigned)seed * 0xDFULL;
        p[j++] = (char)((lval >> 32) + 0x20);
    } while (--len);
    return seed;
}

void searchRange(int start, int end, const mpz_t& gap, const mpz_t& n) {
    mpz_t p, q, phi,d,e,fake, sub;
    mpz_inits(p, q, phi,d,e,fake, sub,NULL);

    for (int seed = start; seed <= end && !found; seed++) {
        // Generate random 32-byte numbers and initialize p and q
        char random_buffer[KEYLEN];
        int nextSeed = MakeRandom(random_buffer, KEYLEN, seed);
        //random_buffer[KEYLEN-1]|=1; // make it odd
        mpz_import(p, KEYLEN, 1, 1, 0, 0, random_buffer);
        MakeRandom(random_buffer, KEYLEN, nextSeed);
        mpz_import(q, KEYLEN, 1, 1, 0, 0, random_buffer);
        mpz_mul(fake, q, p);
        mpz_sub(sub, n, fake);

        if (mpz_sgn(sub) < 0) continue;
        if (mpz_cmp(sub, gap) > 0) continue;
        mpz_nextprime(p, p);

        if (mpz_divisible_p(n, p)) {

            mpz_nextprime(q, q);
            gmp_printf("p:\n%ZX\n\nq:\n%ZX\n\nn (p * q):\n%ZX\n", p, q, n);
            mpz_sub_ui(p, p, 1);
            mpz_sub_ui(q, q, 1);
            mpz_mul(phi, p, q);
            mpz_set_ui(e, 65537);  // Commonly used value for e
            mpz_invert(d, e, phi);
            gmp_printf("(d, phi): (%ZX, %ZX)\n", d, phi);

            
            std::unique_lock<std::mutex> lock(print_mutex);
            found = true;
            std::cout << "Seed " << std::hex << seed << std::endl;
            cv.notify_all();
            break;
        }
    }

   mpz_clears(p, q, fake, sub,NULL);
}

int main() {
    mpz_t gap, n;
    mpz_inits(gap, n, NULL);

    mpz_set_str(gap, "F2BC6E68B42E43CB19056EA8986F4816D346E7D12CCB66B2AD2C18D8EA1BEF001E0", 16);
    mpz_set_str(n, "B3EFAF2E3A1FDF4C496EC1FEFEFC8C93603004CB36E0F24AEBC4E8A2E37D6F65407378FAA5288E67BB8567E530BA7DC58A9739D8B9700BA0965B736AB8E029B1", 16); 
    const unsigned int numThreads = std::thread::hardware_concurrency();
    std::cout << "Spawning " << std::dec << numThreads << " threads" << std::endl;

    std::vector<std::thread> threads;

    int range = 0xFFFFFFFF / numThreads;
    int start = 0;

    for (int i = 0; i < numThreads; ++i) {
        int end = (i == numThreads - 1) ? 0xFFFFFFFF : start + range;
        threads.emplace_back(searchRange, start, end, std::ref(gap), std::ref(n));
        start = end + 1;
    }

    {
        std::unique_lock<std::mutex> lock(print_mutex);
        cv.wait(lock, [] { return found; });
    }

    for (auto &thread : threads) {
        thread.join();
    }

    mpz_clears(gap, n, NULL);

    return 0;
}
