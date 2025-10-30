from typing import ByteString, Sequence

# ---------------- shared helpers ----------------

def _le_bytes_to_int(b: ByteString) -> int:
    return int.from_bytes(b, "little")

def _int_to_le_bytes(x: int) -> bytes:
    return x.to_bytes(32, "little")

def _xor_first_dword_le(b: bytearray, val32: int) -> None:
    w = int.from_bytes(b[0:4], "little") ^ (val32 & 0xFFFFFFFF)
    b[0:4] = w.to_bytes(4, "little")

def _bytes_from_qwords_le(qwords: Sequence[int]) -> bytes:
    out = bytearray()
    for q in qwords:
        out += (q & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return bytes(out)

# ---------------- type1 (exponentiation mod 2^256) ----------------
# qwords: list/tuple of FOUR 64-bit ints.
# Layout exactly matches assembly: write 8-byte LE at offsets 0, 8, 15, 23 (the write at 15 overlaps).

def _type1_exponent_bytes_from_qwords(qwords: Sequence[int]) -> bytes:
    if len(qwords) != 4:
        raise ValueError("type1 qwords must have exactly 4 integers (64-bit each).")
    b = bytearray(31)
    def put_le(start: int, val: int):
        b[start:start+8] = (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    put_le(0,  qwords[0])
    put_le(8,  qwords[1])
    put_le(15, qwords[2])  # intentionally overwrites byte index 15 from prior store
    put_le(23, qwords[3])
    return bytes(b)

def _type1_exponent_int_from_qwords(qwords: Sequence[int]) -> int:
    return int.from_bytes(_type1_exponent_bytes_from_qwords(qwords), "little")

def type1_forward(buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    - XOR first 4 bytes (LE) with 'state' (32-bit)
    - Force byte 0 odd
    - result = base^E mod 2^256, with E built from qwords at offsets 0,8,15,23 (31 bytes total)
    - Post tweak: out[0] ^= saved_lsb; out[0] ^= 1
    """
    if len(buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    b = bytearray(buf)

    # initial XOR
    _xor_first_dword_le(b, state)

    # save LSB then force odd
    saved_lsb = b[0] & 1
    b[0] |= 1

    # exponentiation
    E = _type1_exponent_int_from_qwords(qwords)
    MOD = 1 << 256
    base = _le_bytes_to_int(b)
    result = pow(base, E, MOD)
    out = bytearray(_int_to_le_bytes(result))

    # final tweak
    out[0] ^= saved_lsb
    out[0] ^= 1
    return bytes(out)

def type1_reverse(out_buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    Exact inverse of type1_forward with the same qwords and state.
    """
    if len(out_buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    out = bytearray(out_buf)

    # recover saved_lsb and undo final tweak
    saved_lsb = out[0] & 1
    out[0] ^= saved_lsb
    out[0] ^= 1
    y = _le_bytes_to_int(out)

    # invert exponentiation modulo 2^255 (Euler for 2-adics)
    E = _type1_exponent_int_from_qwords(qwords)
    PHI = 1 << 255  # phi(2^256) = 2^255
    try:
        D = pow(E, -1, PHI)
    except ValueError:
        # Extended Euclid fallback
        def egcd(a, b):
            if b == 0:
                return (a, 1, 0)
            g, x1, y1 = egcd(b, a % b)
            return (g, y1, x1 - (a // b) * y1)
        g, x, _ = egcd(E, PHI)
        if g != 1:
            raise ValueError("Exponent has no inverse modulo 2^255 (E must be odd).")
        D = x % PHI

    MOD = 1 << 256
    base_with_or = pow(y, D, MOD)
    b = bytearray(_int_to_le_bytes(base_with_or))

    # undo forced odd using saved_lsb
    if saved_lsb == 0:
        b[0] = (b[0] - 1) & 0xFF

    # undo initial XOR
    _xor_first_dword_le(b, state)
    return bytes(b)

# ---------------- type2 (S-box per-byte)  [renamed from your old type3] ----------------
# qwords: list/tuple of THIRTY-TWO 64-bit ints -> 256 bytes S-box (must be a permutation of 0..255)

def _type2_sbox_from_qwords(qwords: Sequence[int]) -> bytes:
    if len(qwords) != 32:
        raise ValueError("type2 qwords must have exactly 32 integers (32*8 = 256 bytes).")
    sbox = _bytes_from_qwords_le(qwords)
    if len(set(sbox)) != 256:
        raise ValueError("type2 S-box must be a permutation of 0..255 (all unique).")
    return sbox

def _invert_sbox(sbox: bytes) -> bytes:
    if len(sbox) != 256:
        raise ValueError("S-box must be 256 bytes.")
    inv = bytearray(256)
    for i, v in enumerate(sbox):
        inv[v] = i
    return bytes(inv)

def type2_forward(buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    - XOR first 4 bytes (LE) with 'state' (32-bit)
    - Apply S-box (built from 32 qwords) to each of the 32 bytes
    """
    if len(buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    sbox = _type2_sbox_from_qwords(qwords)
    b = bytearray(buf)
    _xor_first_dword_le(b, state)
    for i in range(32):
        b[i] = sbox[b[i]]
    return bytes(b)

def type2_reverse(out_buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    Inverse of type2_forward with the same qwords and state.
    """
    if len(out_buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    sbox = _type2_sbox_from_qwords(qwords)
    inv = _invert_sbox(sbox)
    b = bytearray(out_buf)
    for i in range(32):
        b[i] = inv[b[i]]
    _xor_first_dword_le(b, state)
    return bytes(b)

# ---------------- type3 (32-byte permutation) [renamed from your old type4] ----------------
# qwords: list/tuple of FOUR 64-bit ints -> 32 bytes; must be a permutation of indices 0..31

def _type3_perm_from_qwords(qwords: Sequence[int]) -> bytes:
    if len(qwords) != 4:
        raise ValueError("type3 qwords must have exactly 4 integers (4*8 = 32 bytes).")
    perm = _bytes_from_qwords_le(qwords)
    vals = list(perm)
    if not all(0 <= v < 32 for v in vals) or len(set(vals)) != 32:
        raise ValueError("type3 permutation must be a bijection over 0..31 (all values unique in [0,31]).")
    return perm

def type3_forward(buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    - XOR first 4 bytes (LE) with 'state' (32-bit)
    - Permute: out[i] = in[perm[i]], where perm comes from qwords (32 bytes)
    """
    if len(buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    perm = _type3_perm_from_qwords(qwords)
    b = bytearray(buf)
    _xor_first_dword_le(b, state)
    out = bytearray(32)
    for i in range(32):
        out[i] = b[perm[i]]
    return bytes(out)

def type3_reverse(out_buf: bytes, qwords: Sequence[int], state: int) -> bytes:
    """
    Inverse of type3_forward with the same qwords and state.
    """
    if len(out_buf) != 32:
        raise ValueError("Input must be exactly 32 bytes.")
    perm = _type3_perm_from_qwords(qwords)
    b = bytearray(32)
    for i in range(32):
        b[perm[i]] = out_buf[i]
    _xor_first_dword_le(b, state)
    return bytes(b)
