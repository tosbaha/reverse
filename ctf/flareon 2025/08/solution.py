from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.x86_const import *
import pefile
import struct
import random

MASK = (1 << 64) - 1
TARGET = 0x0BC42D5779FEC401

hash_table = [
    0x279342f, 0xc678db8, 0x87d0f40, 0xcc48d40, 0xc60a7f3,
    0x716c0d7, 0x32c5f65, 0xb49d7af, 0x1b186d3, 0x545d8d5,
    0x6b2f406, 0x9a868c,  0x7024229, 0x48bdaae, 0x5f8f14f,
    0x9d5d059, 0xdc0222f, 0x3d1d2b6, 0xd63209a, 0xb3c02cb,
    0x6fb781e, 0xf2d7eee, 0xca922ea, 0xadf00df, 0x4775803,
]

PAGE_SIZE = 0x1000
def page_align_up(x, sz=PAGE_SIZE): return (x + (sz - 1)) & ~(sz - 1)

def map_pe_into_unicorn(pe: pefile.PE):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(image_base, page_align_up(size), UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    for sec in pe.sections:
        va = image_base + sec.VirtualAddress
        raw = sec.get_data() or b""
        if raw:
            uc.mem_write(va, raw)
    # stack
    STACK_BASE = 0x7fff00000000
    STACK_SIZE = 0x200000
    uc.mem_map(STACK_BASE - STACK_SIZE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    return uc, image_base

def run_code(uc, index, digit, start_va, stop_va, timeout_insns=200000):
    STACK_TOP = 0x7fff00000000
    reg_rsp = STACK_TOP - 0x1000
    reg_rbp = STACK_TOP - 0x0800
    uc.reg_write(UC_X86_REG_RSP, reg_rsp)
    uc.reg_write(UC_X86_REG_RBP, reg_rbp)

    uc.mem_write(reg_rbp + 0x678, b"\xC3")
    uc.mem_write(reg_rbp + 0x400, ((index + 1) << 8).to_bytes(2, "little"))  # e.g. 00 01, 00 02, ...
    uc.mem_write(reg_rbp + 0x3BF,  (0x30 + digit).to_bytes(2, "little"))     # e.g. 31 00 for digit=1

    stopped = {"hit": False}
    def hook_code(uc_inst, address, size, user_data):
        if address == stop_va:
            stopped["hit"] = True
            uc_inst.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook_code)
    try:
        uc.emu_start(start_va, stop_va, timeout=0, count=timeout_insns)
    except Exception:
        if not stopped["hit"]:
            return None

    try:
        return uc.reg_read(UC_X86_REG_RAX) & MASK
    except Exception:
        return None

def build_char_table(uc, start_va, stop_va):
    table = [[0]*10 for _ in range(25)]
    for i in range(25):
        for d in range(10):
            v = run_code(uc, i, d, start_va, stop_va)
            if v is None:
                raise RuntimeError(f"Emulation failed at i={i}, d={d}")
            table[i][d] = v & MASK
    return table

def to_s64(x):
    x &= MASK
    return x - (1 << 64) if (x & (1 << 63)) else x

def solve_digits(char_table):
    contrib = [[(hash_table[i] * char_table[i][d]) & MASK for d in range(10)] for i in range(25)]

    base = 0
    for i in range(25):
        base = (base + contrib[i][0]) & MASK

    R = (TARGET - base) & MASK
    R_s = to_s64(R)       

    deltas = [[to_s64((contrib[i][d] - contrib[i][0]) & MASK) for d in range(10)] for i in range(25)]
    max_abs = [max(abs(x) for x in di) for di in deltas]

    order = sorted(range(25), key=lambda i: max_abs[i], reverse=True)

    rem_bound = [0]*(26)
    for k in range(24, -1, -1):
        rem_bound[k] = rem_bound[k+1] + max_abs[order[k]]

    sol = [0]*25
    best = {"gap": abs(R_s), "digits": sol[:]}

    def dfs(k, acc):
        gap = abs(R_s - acc)
        if gap < best["gap"]:
            best["gap"] = gap
            best["digits"] = sol[:]
            if gap == 0:
                return True

        if k == 25:
            return False

        if abs(R_s - acc) > rem_bound[k]:
            return False

        i = order[k]
        need = R_s - acc

        opts = sorted(range(10), key=lambda d: abs(need - deltas[i][d]))
        for d in opts:
            sol[i] = d
            if dfs(k+1, acc + deltas[i][d]):
                return True
        return False

    found = dfs(0, 0)
    return found, best["digits"]

def emulate_digits(uc, digits, start_va, stop_va):
    res = 0
    for i, val in enumerate(digits):
        char_code = run_code(uc, i, val, start_va, stop_va)
        res = (res + (hash_table[i] * char_code)) & MASK
    return res

def main():
    pe = pefile.PE("FlareAuthenticator.exe")
    uc, _ = map_pe_into_unicorn(pe)

    START = 0x140016711
    STOP  = 0x140016768

    # 1) build the per-index/per-digit table once (250 emulations)
    table = build_char_table(uc, START, STOP)
    #print("char table built.",table)
    # 2) solve
    ok, digits = solve_digits(table)

    # 3) verify
    result = emulate_digits(uc, digits, START, STOP)
    print("digits:", "".join(str(d) for d in digits))
    print(f"result: {result:016X}")
    print("OK!" if result == TARGET else "NO MATCH")
    for i in range(0, 25, 5):
        print(" ".join(str(d) for d in digits[i:i+5]))
if __name__ == "__main__":
    main()
