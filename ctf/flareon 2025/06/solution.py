import json
import binascii
import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime, long_to_bytes
import pathlib

chat_log = [
  {
    "conversation_time": 0,
    "mode": "LCG-XOR",
    "plaintext": "Hello",
    "ciphertext": "e934b27119f12318fe16e8cd1c1678fd3b0a752eca163a7261a7e2510184bbe9"
  },
  {
    "conversation_time": 4,
    "mode": "LCG-XOR",
    "plaintext": "How are you?",
    "ciphertext": "25bf2fd1198392f4935dcace7d747c1e0715865b21358418e67f94163513eae4"
  },
  {
    "conversation_time": 11,
    "mode": "LCG-XOR",
    "plaintext": "Terrible...",
    "ciphertext": "c9f20e5561acf172305cf8f04c13e643c988aa5ab29b5499c93df112687c8c7c"
  },
  {
    "conversation_time": 13,
    "mode": "LCG-XOR",
    "plaintext": "Is this a secure channel?",
    "ciphertext": "3ab9c9f38e4f767a13b12569cdbf13db6bbb939e4c8a57287fb0c9def0288e46"
  },
  {
    "conversation_time": 16,
    "mode": "LCG-XOR",
    "plaintext": "Yes, it's on the blockchain.",
    "ciphertext": "3f6de0c2063d3e8e875737046fef079d73cc9b1b7a4b7b94da2d2867493f6fc5"
  },
  {
    "conversation_time": 24,
    "mode": "LCG-XOR",
    "plaintext": "Erm enable super safe mode",
    "ciphertext": "787cf6c0be39caa21b7908fcd1beca68031b7d11130005ba361c5d361b106b6d"
  },
  {
    "conversation_time": 30,
    "mode": "LCG-XOR",
    "plaintext": "Ok, activating now",
    "ciphertext": "632ab61849140655e0ee6f90ab00b879a3a3da241d4b50bab99f74f169d456db"
  },
  {
    "conversation_time": 242,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "680a65364a498aa87cf17c934ab308b2aee0014aee5b0b7d289b5108677c7ad1eb3bcfbcad7582f87cb3f242391bea7e70e8c01f3ad53ac69488713daea76bb3a524bd2a4bbbc2cfb487477e9d91783f103bd6729b15a4ae99cb93f0db22a467ce12f8d56acaef5d1652c54f495db7bc88aa423bc1c2b60a6ecaede2f4273f6dce265f6c664ec583d7bd75d2fb849d77fa11d05de891b5a706eb103b7dbdb4e5a4a2e72445b61b83fd931cae34e5eaab931037db72ba14e41a70de94472e949ca3cf2135c2ccef0e9b6fa7dd3aaf29a946d165f6ca452466168c32c43c91f159928efb3624e56430b14a0728c52f2668ab26f837120d7af36baf48192ceb3002"
  },
  {
    "conversation_time": 249,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "6f70034472ce115fc82a08560bd22f0e7f373e6ef27bca6e4c8f67fedf4031be23bf50311b4720fe74836b352b34c42db46341cac60298f2fa768f775a9c3da0c6705e0ce11d19b3cbdcf51309c22744e96a19576a8de0e1195f2dab21a3f1b0ef5086afcffa2e086e7738e5032cb5503df39e4bf4bdf620af7aa0f752dac942be50e7fec9a82b63f5c8faf07306e2a2e605bb93df09951c8ad46e5a2572e333484cae16be41929523c83c0d4ca317ef72ea9cde1d5630ebf6c244803d2dc1da0a1eefaafa82339bf0e6cf4bf41b1a2a90f7b2e25313a021eafa6234643acb9d5c9c22674d7bc793f1822743b48227a814a7a6604694296f33c2c59e743f4106"
  }
]

# ---------- PUBLIC PEM path ----------
PUBLIC_PEM_PATH = "public.pem"  # change if needed

# ---------- helper functions ----------
def hex_to_bytes(h):
    h = h.strip()
    if h.startswith("0x"):
        h = h[2:]
    return binascii.unhexlify(h)

def int_from_bytes_be(b):
    return int.from_bytes(b, 'big')

def int_from_bytes_le(b):
    return int.from_bytes(b, 'little')

def bytes32_from_plaintext(plaintext: str) -> bytes:
    # Contract takes first 32 bytes of the string data and pads with zeros on the right.
    b = plaintext.encode('utf-8')
    if len(b) >= 32:
        return b[:32]
    else:
        return b + b'\x00' * (32 - len(b))

def xor_ints(a: int, b: int) -> int:
    return a ^ b

def bytes32_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

# ---------- 1) Recover P_i (LCG outputs) from LCG-XOR rows ----------
lcg_outputs = []  # list of integers (256-bit)
used_rows = []    # store used LCG-XOR rows (for debugging)

for entry in chat_log:
    if entry['mode'] != 'LCG-XOR':
        continue
    ct_hex = entry['ciphertext']
    conv_time = entry['conversation_time']
    plaintext = entry['plaintext']

    # C: 32-byte big-endian from ciphertext hex
    C_bytes = hex_to_bytes(ct_hex)
    if len(C_bytes) != 32:
        # if not 32 bytes, left-pad with zeros to 32 (shouldn't happen for LCG-XOR)
        C_bytes = C_bytes.rjust(32, b'\x00')
    C_int = int_from_bytes_be(C_bytes)

    # T: conversation_time as 32-byte big-endian integer
    T_int = conv_time  # small integer; when XORing we use its 32-byte BE representation
    T_bytes = T_int.to_bytes(32, 'big')
    T_int32 = int_from_bytes_be(T_bytes)

    # S: first 32 bytes of plaintext, right-padded with zeros
    S_bytes = bytes32_from_plaintext(plaintext)
    S_int = int_from_bytes_be(S_bytes)

    # P = C XOR T XOR S
    P_int = C_int ^ T_int32 ^ S_int
    lcg_outputs.append(P_int)
    used_rows.append((conv_time, plaintext, ct_hex, hex(P_int)[2:].rjust(64,'0')))

print("[*] Recovered LCG outputs (first bytes shown):")
for i, (t, ptxt, chex, phex) in enumerate(used_rows):
    print(f"  idx={i} time={t:>3} plain={ptxt!r:25} ct={chex[:16]}... P={phex[:16]}...")

# ---------- 2) Recover modulus m by GCD trick ----------
def recover_modulus(xs):
    # xs: consecutive integer outputs x0,x1,x2,...
    if len(xs) < 4:
        raise ValueError("Need >=4 consecutive outputs")
    t = [ (xs[i+1] - xs[i]) for i in range(len(xs)-1) ]
    us = []
    for i in range(len(t)-2):
        u = t[i+2]*t[i] - t[i+1]*t[i+1]
        us.append(abs(u))
    g = 0
    for u in us:
        g = math.gcd(g, u)
    return g

m_candidate = recover_modulus(lcg_outputs)
print("\n[*] modulus candidate (gcd) bitlen:", m_candidate.bit_length())
print("    m (hex, first 64 chars):", hex(m_candidate)[:66])

# ---------- 3) Recover a and c (mod m) ----------
x0, x1, x2 = lcg_outputs[0], lcg_outputs[1], lcg_outputs[2]
# compute a = (x2 - x1) * inv(x1 - x0) mod m
den = (x1 - x0) % m_candidate
try:
    inv_den = pow(den, -1, m_candidate)
except ValueError as e:
    raise SystemExit("Modular inverse failed; candidate modulus may be multiple of real modulus.") from e

a = ((x2 - x1) * inv_den) % m_candidate
c = (x1 - a * x0) % m_candidate

print("\n[*] Recovered LCG parameters:")
print("    a (multiplier) bitlen:", a.bit_length())
print("    c (increment)   bitlen:", c.bit_length())
print("    m (modulus)     bitlen:", m_candidate.bit_length())

# Verify the recurrence on observed outputs
ok = True
for i in range(len(lcg_outputs)-1):
    lhs = (a * lcg_outputs[i] + c) % m_candidate
    if lhs != lcg_outputs[i+1]:
        ok = False
        print(f"[!] Verification failed at index {i}: expected {hex(lcg_outputs[i+1])}, got {hex(lhs)}")
        break

print("    recurrence verification:", "OK" if ok else "FAILED")

# ---------- 4) Recover seed (initial state) ----------
# The app uses: state = seed; x1 = (a*seed + c) % m  (one step)
# So seed = a^{-1} * (x1 - c) mod m
try:
    inv_a = pow(a, -1, m_candidate)
except ValueError as e:
    raise SystemExit("Failed to invert a modulo m; abort.") from e

seed = (inv_a * (x0 - c)) % m_candidate  # careful: x0 is first output: x0 = (a*seed + c) % m -> seed = a^{-1}(x0 - c)
# Alternate derivation depending on which x we consider first; above assumes lcg_outputs[0] is x0 (first nextVal)
print("\n[*] Recovered seed (little-endian SHA256(hostname) value) bitlen:", seed.bit_length())
print("    seed (hex, first 80 chars):", hex(seed)[:82])

# ---------- 5) Reconstruct RSA primes by replaying LCG (collect 8 primes) ----------
def lcg_step(a, c, m, state):
    return (a * state + c) % m

state = seed
primes = []
iters = 0
max_iters = 20000  # safety
while len(primes) < 8 and iters < max_iters:
    state = lcg_step(a, c, m_candidate, state)
    if state.bit_length() == 256 and isPrime(state):
        primes.append(state)
    iters += 1

print(f"\n[*] Collected {len(primes)} primes (iterations used: {iters})")
if len(primes) >= 1:
    print("    first prime (hex start):", hex(primes[0])[:66])
if len(primes) < 8:
    raise SystemExit("Failed to collect 8 primes within iteration budget. Try increasing max_iters.")

# ---------- 6) Reconstruct N and compare with public.pem ----------
N_candidate = 1
for p in primes:
    N_candidate *= p

# Load public.pem
pem_path = pathlib.Path(PUBLIC_PEM_PATH)
if not pem_path.exists():
    raise SystemExit(f"public.pem not found at {PUBLIC_PEM_PATH}; put it there or change path.")

pem_data = pem_path.read_bytes()
rsa_key = RSA.import_key(pem_data)
N_from_pem = rsa_key.n
e_from_pem = rsa_key.e
print("\n[*] RSA public key from PEM:")
print("    e =", e_from_pem)
print("    N bitlen:", N_from_pem.bit_length())
print("    N (hex prefix):", hex(N_from_pem)[:66])

if N_candidate == N_from_pem:
    print("[+] Reconstructed N matches public.pem modulus!")
else:
    print("[!] Reconstructed N DOES NOT match public.pem modulus. Something is off.")
    # print("N_candidate hex:", hex(N_candidate))
    # print("N_from_pem hex:", hex(N_from_pem))

# ---------- 7) Compute phi, d and decrypt RSA ciphertexts ----------
phi = 1
for p in primes:
    phi *= (p - 1)

d = pow(e_from_pem, -1, phi)
print("\n[*] Computed d bitlen:", d.bit_length())

# decrypt RSA ciphertexts in chat_log (they were encoded little-endian)
rsa_entries = [entry for entry in chat_log if entry['mode'] == 'RSA']
for i, entry in enumerate(rsa_entries):
    ct_hex = entry['ciphertext']
    # ciphertext bytes were produced with to_bytes(..., 'little') and rstrip(b'\x00') by the app: recover by reading hex as little-endian
    ct_bytes = hex_to_bytes(ct_hex)
    c_int = int_from_bytes_le(ct_bytes)
    m_int = pow(c_int, d, N_candidate)
    # original plaintext was converted to integer with bytes_to_long (big-endian), so convert back with big-endian
    pt_bytes = long_to_bytes(m_int)
    try:
        pt = pt_bytes.decode('utf-8')
    except Exception:
        pt = repr(pt_bytes)
    print(f"\n[+] Decrypted RSA message #{i+1} (time {entry['conversation_time']}):")
    print("    plaintext bytes (hex):", pt_bytes.hex())
    print("    plaintext:", pt)

print("\nDone.")
