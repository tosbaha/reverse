import json
import os
from typing import Dict, List, Tuple,ByteString
from pathlib import Path
from dataclasses import dataclass
from math import gcd as _gcd
from collections import Counter
from template_lib import type1_forward,type1_reverse,type2_forward,type2_reverse,type3_forward,type3_reverse
from tqdm import tqdm
import struct
import re

def _get_state_le32(state,seed_off: int) -> int:
    off = int(seed_off)
    return int.from_bytes(state[off:off+4], 'little', signed=False)

def load_mapping(path: str) -> Dict[int, str]:
    with open(path, 'r') as f:
        raw = json.load(f)
    mapping: Dict[int, str] = {}
    for k, v in raw.items():
        try:
            ki = int(k)
        except Exception:
            raise ValueError(f"mapping key is not an int: {k!r}")
        mapping[ki] = v
    return mapping

def parse_deps_json(path: str) -> Dict[str, List[str]]:
    with open(path, 'r') as f:
        data = json.load(f)
    return data

def add_le_u32(state: bytearray, word_index: int, delta: int) -> None:
    off = word_index * 4
    curr = struct.unpack_from('<I', state, off)[0]
    struct.pack_into('<I', state, off, (curr + delta) & 0xFFFFFFFF)

# State and license stuff
def update_license(license,res_id,index,random):
    off = index * 34
    license[off:off+2] = res_id.to_bytes(2, "little")
    license[off+2:off+34] = random

def update_state(state,res_map,res_id,index):
    found = next((o for o in res_map if o.get("i") == res_id), None)
    add_le_u32(state, int(res_id), index)
    for dep in found.get('d', []):
        add_le_u32(state, int(dep), index)

# ------------- U128 helpers for Template 4 remainder -------------
MASK64 = (1 << 64) - 1

@dataclass
class U128:
    lo: int  # uint64
    hi: int  # uint64

    def as_int(self) -> int:
        return ((self.hi & MASK64) << 64) | (self.lo & MASK64)

    @staticmethod
    def from_int(x: int) -> "U128":
        if x < 0:
            raise ValueError("U128 cannot be negative")
        return U128(lo=x & MASK64, hi=(x >> 64) & MASK64)

def clz64(x: int) -> int:
    x &= MASK64
    if x == 0:
        return 64
    return 64 - x.bit_length()

def add64(x: int, y: int) -> Tuple[int, int]:
    s = (x & MASK64) + (y & MASK64)
    return s & MASK64, 1 if s >> 64 else 0


def sub64(x: int, y: int) -> Tuple[int, int]:
    x &= MASK64
    y &= MASK64
    d = x - y
    borrow = 1 if d < 0 else 0
    return d & MASK64, borrow


def ucmp128(a_hi: int, a_lo: int, b_hi: int, b_lo: int) -> int:
    a_hi &= MASK64; a_lo &= MASK64; b_hi &= MASK64; b_lo &= MASK64
    if a_hi != b_hi:
        return -1 if a_hi < b_hi else 1
    if a_lo != b_lo:
        return -1 if a_lo < b_lo else 1
    return 0


def udivrem128_by_64(n_hi: int, n_lo: int, d: int) -> Tuple[int, int, int]:
    d &= MASK64
    if d == 0:
        raise ZeroDivisionError("division by zero")
    n_hi &= MASK64
    n_lo &= MASK64
    if n_hi < d:
        dividend = (n_hi << 64) | n_lo
        q = dividend // d
        r = dividend % d
        return 0, q & MASK64, r & MASK64
    else:
        q0 = n_hi // d
        r1 = n_hi % d
        dividend2 = (r1 << 64) | n_lo
        q1 = dividend2 // d
        r = dividend2 % d
        return q0 & MASK64, q1 & MASK64, r & MASK64


def umod128(a: U128, b: U128) -> U128:
    a_lo, a_hi = a.lo & MASK64, a.hi & MASK64
    b_lo, b_hi = b.lo & MASK64, b.hi & MASK64

    # Fast path: b fits in 64 bits
    if b_hi == 0:
        _, _, r = udivrem128_by_64(a_hi, a_lo, b_lo)
        return U128(lo=r, hi=0)

    # If b > a, remainder is a
    if ucmp128(a_hi, a_lo, b_hi, b_lo) < 0:
        return U128(lo=a_lo, hi=a_hi)

    # General 128/128 case
    shift = clz64(b_hi)
    inv = 64 - shift

    v_hi_prime = ((b_hi << shift) | (b_lo >> inv)) & MASK64 if shift != 0 else b_hi
    v_lo_prime = (b_lo << shift) & MASK64 if shift != 0 else b_lo

    if shift != 0:
        u_top_hi = (a_hi >> inv) & MASK64
        u_top_lo = ((a_lo >> inv) | ((a_hi << shift) & MASK64)) & MASK64
        u_low    = (a_lo << shift) & MASK64
    else:
        u_top_hi = 0
        u_top_lo = a_hi & MASK64
        u_low    = a_lo & MASK64

    qh, ql, rhat = udivrem128_by_64(u_top_hi, u_top_lo, v_hi_prime)
    assert qh == 0
    qhat = ql

    prod = (qhat * v_lo_prime) & ((1 << 128) - 1)
    prod_hi = (prod >> 64) & MASK64
    prod_lo = prod & MASK64

    overshoot = (rhat < prod_hi) or (rhat == prod_hi and u_low < prod_lo)
    if overshoot:
        lo, borrow = sub64(prod_lo, v_lo_prime)
        hi_tmp, borrow2 = sub64((prod_hi - borrow) & MASK64, v_hi_prime)
        prod_lo = lo
        prod_hi = hi_tmp
        qhat = (qhat - 1) & MASK64

    rem_lo_norm, borrow = sub64(u_low, prod_lo)
    rem_hi_norm, borrow2 = sub64((rhat - borrow) & MASK64, prod_hi)

    if shift != 0:
        rax = ((rem_hi_norm << inv) & MASK64) | ((rem_lo_norm >> shift) & MASK64)
        r8  = (rem_hi_norm >> shift) & MASK64
    else:
        rax = rem_lo_norm & MASK64
        r8  = rem_hi_norm & MASK64

    return U128(lo=rax & MASK64, hi=r8 & MASK64)


def umod128_simple(a: U128, b: U128) -> U128:
    A = a.as_int()
    B = b.as_int()
    if B == 0:
        raise ZeroDivisionError("u128 modulo by zero")
    return U128.from_int(A % B)


def _mat_mul_mod_4x4_int(A: List[List[int]], B: List[List[int]], mod: int) -> List[List[int]]:
    C = [[0]*4 for _ in range(4)]
    for i in range(4):
        Ai = A[i]
        for k in range(4):
            aik = Ai[k] % mod
            if aik == 0:
                continue
            Bk = B[k]
            for j in range(4):
                C[i][j] = (C[i][j] + aik * (Bk[j] % mod)) % mod
    return C

def _mat_pow_mod_4x4_int(A: List[List[int]], e: int, mod: int) -> List[List[int]]:
    R = [[0]*4 for _ in range(4)]
    for i in range(4):
        R[i][i] = 1 % mod
    P = [row[:] for row in A]
    x = int(e)
    while x > 0:
        if x & 1:
            R = _mat_mul_mod_4x4_int(R, P, mod)
        P = _mat_mul_mod_4x4_int(P, P, mod)
        x >>= 1
    return R

def _table_to_matrix_from_ints_col_major(T: List[int], mod: int) -> List[List[int]]:
    M4 = [[0]*4 for _ in range(4)]
    for j in range(4):
        for i in range(4):
            M4[i][j] = int(T[j*4 + i]) % mod
    return M4

def _matrix_to_table_col_major(M4: List[List[int]]) -> List[int]:
    T = [0]*16
    for j in range(4):
        for i in range(4):
            T[j*4 + i] = int(M4[i][j])
    return T

def _lcm(a: int, b: int) -> int:
    return a // _gcd(a, b) * b

def _gl4_exponent(p: int) -> int:
    L = 1
    for k in range(1, 5):
        L = _lcm(L, pow(p, k) - 1)
    return p * L

def _inv_mod(a: int, m: int) -> int:
    a %= m
    t0, t1, r0, r1 = 0, 1, m, a
    while r1:
        q = r0 // r1
        t0, t1, r0, r1 = t1, t0 - q*t1, r1, r0 - q*r1
    if r0 != 1:
        raise ValueError('inv_mod: no inverse')
    return t0 % m

def _recover_table_vals_from_R(R_table_col_major: List[int], e: int, mod_m: int) -> List[int]:
    EXP = _gl4_exponent(mod_m)
    if _gcd(e, EXP) != 1:
        raise ValueError('gcd(e, exp(GL(4,p))) != 1; inverse power not defined')
    d = _inv_mod(e, EXP)
    Rm = _table_to_matrix_from_ints_col_major(R_table_col_major, mod_m)
    P0m = _mat_pow_mod_4x4_int(Rm, d, mod_m)
    return _matrix_to_table_col_major(P0m)

def parse_solution_table(path: str,state) -> Dict[int, int]:
    with open(path, 'r') as f:
        report = json.load(f)

    prime = report['vals'][0]
    shift = report['vals'][1]
    tbl_pairs_low = report['vals'][2:18]
    targ_pairs_low = report['vals'][18:34]

    targ_pairs = []
    tbl_pairs = []
    for i in tbl_pairs_low:
        tbl_pairs.append((i,0))

    for i in targ_pairs_low:
        targ_pairs.append((i,0))

    R_vals = []
    for (lo, hi) in targ_pairs[:16]:
        val128 = ((int(hi) & MASK64) << 64) | (int(lo) & MASK64)
        R_vals.append(val128 % int(prime))
    try:
        rec_vals = _recover_table_vals_from_R(R_vals, int(shift), int(prime))
    except Exception as e:
        msg = f"P0 error: {e}"
        print(f"[!] {msg}")
        exit(0)

    key_groups: List[List[int]] = [[], [], [], []]
    for idx in range(16):
        k = idx % 4
        p0_lo = rec_vals[idx] & MASK64
        tbl_lo = int(tbl_pairs[idx][0]) & MASK64
        key_groups[k].append(p0_lo ^ tbl_lo)

    key_u64: List[int] = []
    for k in range(4):
        vals = key_groups[k]
        if not vals:
            msg = f"key error"
            exit(0)
        c = Counter(vals)
        kv, _freq = c.most_common(1)[0]
        key_u64.append(kv & MASK64)

    mismatches = 0
    for idx in range(16):
        k = idx % 4
        tbl_lo = int(tbl_pairs[idx][0]) & MASK64
        p0_lo = int(rec_vals[idx]) & MASK64
        calc = (tbl_lo ^ key_u64[k]) & MASK64
        if calc != p0_lo:
            mismatches += 1

    key_bytes = b''.join(int(x).to_bytes(8, 'little', signed=False) for x in key_u64)

    # solve the rest
    entries = report['functions']
    return solve_templates(key_bytes, entries,state)

def solve_templates(key_bytes,entries,state):

    input = key_bytes
    for entry in reversed(entries):
        temp_id = entry['template']
        seed_off = entry['seed_offset']
        constants = entry['constants']

        state_val = _get_state_le32(state,seed_off)
        if temp_id == 1:
            input = type1_reverse(input,constants,state_val)
        elif temp_id == 2:
            input = type2_reverse(input,constants,state_val)
        elif temp_id == 3:
            input = type3_reverse(input,constants,state_val)

    return input

def dump_state(state):
    fname = f"state_test.bin"
    with open(fname,'wb') as f:
        f.write(state)

def dump_license(license):
    fname = f"license.bin"
    with open(fname,'wb') as f:
        f.write(license)

def main():
    state = bytearray(10000 * 4)
    license = bytearray(10000 * 34)
    order = load_mapping("order.json")
    res_map = parse_deps_json("deps.json")
    index = 0
    for i in tqdm(order,desc='Creating License'):
        res_id = order[i] # DLL id
        res_path = f"outputs/{res_id}.json"
        dll_solution = parse_solution_table(res_path,state)
        update_state(state,res_map,res_id,index)
        update_license(license,int(res_id),index,dll_solution)
        index += 1        
    
    dump_state(state)
    dump_license(license)

if __name__ == '__main__':
    main()
