import os
import re
import json
import mmap
import argparse
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing as mp

def _dump_json(obj, fp):
    json.dump(obj, fp)


import pefile
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_OP_IMM, CS_OP_REG, CS_OP_MEM, CS_MODE_64
from capstone.x86_const import (
    X86_REG_RIP, X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
    X86_REG_RSI, X86_REG_RDI, X86_REG_R8, X86_REG_R8D, X86_REG_R9, X86_REG_R10,
    X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15, X86_REG_RSP
)
from tqdm import tqdm

# ----------------------------
# Constants / Regex
# ----------------------------
NUMERIC_DLL_RE = re.compile(r'^(\d+)(?:\.dll)?$', re.IGNORECASE)

QWORD_REGS = frozenset({
    X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
    X86_REG_RSI, X86_REG_RDI, X86_REG_R8, X86_REG_R9,
    X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13,
    X86_REG_R14, X86_REG_R15, X86_REG_RSP
})

TEMPLATE_VALUES = {0xC0: 1, 0x110: 2, 0x50: 3}

# ----------------------------
# Capstone mgmt (one per process)
# ----------------------------
_md = None
def get_md() -> Cs:
    global _md
    if _md is None:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        _md = md
    return _md

# Per-process memo for dep metadata to avoid re-opening same PE repeatedly
_dep_meta_cache: Dict[str, Dict] = {}

# ----------------------------
# Lightweight LRU cache + Sharded front
# ----------------------------
class LightweightPECache:
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.cache: OrderedDict[str, Dict] = OrderedDict()
        from threading import Lock
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, dll_path: str) -> Optional[Dict]:
        with self.lock:
            if dll_path in self.cache:
                self.cache.move_to_end(dll_path)
                self.hits += 1
                return self.cache[dll_path]
            self.misses += 1
            return None

    def put(self, dll_path: str, metadata: Dict):
        with self.lock:
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            self.cache[dll_path] = metadata
            self.cache.move_to_end(dll_path)

class ShardedPECache:
    def __init__(self, shards: int = 8, max_size_per_shard: int = 256):
        self.shards = [LightweightPECache(max_size=max_size_per_shard) for _ in range(shards)]

    def _idx(self, key: str) -> int:
        return (hash(key) & 0x7fffffff) % len(self.shards)

    def get(self, key: str):
        return self.shards[self._idx(key)].get(key)

    def put(self, key: str, val: Dict):
        return self.shards[self._idx(key)].put(key, val)

    def stats(self):
        hits = sum(s.hits for s in self.shards)
        misses = sum(s.misses for s in self.shards)
        total = hits + misses
        return hits, misses, (hits / total * 100.0) if total else 0.0

# Global cache (tuned in main)
_pe_cache: ShardedPECache = ShardedPECache(shards=8, max_size_per_shard=256)

# ----------------------------
# PE utilities
# ----------------------------
def _read_bytes_mmap(path: str, file_offset: int, size: int) -> bytes:
    with open(path, 'rb') as f:
        page = mmap.ALLOCATIONGRANULARITY
        start = (file_offset // page) * page
        delta = file_offset - start
        length = delta + size
        with mmap.mmap(f.fileno(), length, access=mmap.ACCESS_READ, offset=start) as mm:
            return mm[delta:delta+size]

def _va_to_file_offset(pe_obj: pefile.PE, va: int) -> Optional[int]:
    try:
        rva = va - pe_obj.OPTIONAL_HEADER.ImageBase
        return pe_obj.get_offset_from_rva(rva)
    except Exception:
        return None

# Export-only quick check (no imports)
def has_export_quick(dll_path: str, export_name: str) -> Tuple[bool, Optional[int], Optional[int]]:
    """
    Fast path: parse only export directory and return (has_export, image_base, export_va).
    Returns export VA if present, else None. Does NOT cache, to keep this phase IO-bound and parallel.
    """
    try:
        pe = pefile.PE(dll_path, fast_load=True)
        # If export dir size is 0, skip parsing
        ed = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        if ed.VirtualAddress == 0 or ed.Size == 0:
            pe.close()
            return (False, None, None)

        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        ])
        image_base = pe.OPTIONAL_HEADER.ImageBase
        export_va = None
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    name = sym.name.decode('utf-8', errors='ignore')
                    if name == export_name:
                        export_va = image_base + sym.address
                        break
        pe.close()
        return (export_va is not None, image_base if export_va else None, export_va)
    except Exception:
        return (False, None, None)

def load_pe_metadata(dll_path: str) -> Dict:
    cached = _pe_cache.get(dll_path)
    if cached:
        return cached

    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
    ])

    image_base = pe.OPTIONAL_HEADER.ImageBase
    img_size   = pe.OPTIONAL_HEADER.SizeOfImage

    import_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        nm = NUMERIC_DLL_RE
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            if nm.match(dll_name):
                for imp in entry.imports:
                    if imp.import_by_ordinal:
                        func_name = f"Ordinal_{imp.ordinal}"
                    else:
                        func_name = imp.name.decode('utf-8') if imp.name else None

                    if imp.address is not None:
                        rva = imp.address - image_base
                        import_map[rva] = (dll_name, func_name)

    export_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                name = sym.name.decode('utf-8', errors='ignore')
                export_map[name] = image_base + sym.address

    md = {
        'image_base': image_base,
        'img_size': img_size,
        'import_map': import_map,
        'export_map': export_map,
    }
    _pe_cache.put(dll_path, md)
    pe.close()
    return md


def read_bytes(filepath, offset, size):
    with open(filepath, 'rb') as f:
        f.seek(offset)         # Move the cursor to the offset
        data = f.read(size)    # Read 'size' bytes from that position
    return data


def read_function_code(dll_path: str, start_va: int, pe_obj: pefile.PE,
                       initial: int = 0x3000, maximum: int = 0x8000) -> bytes:
    md = get_md()
    window = initial
    fo = _va_to_file_offset(pe_obj, start_va)
    if fo is None:
        return b''

    last_buf = b''
    while window <= maximum:
        buf = _read_bytes_mmap(dll_path, fo, window)
        last_buf = buf
        for ins in md.disasm(buf, start_va):
            if ins.mnemonic == 'ret':
                end_off = (ins.address - start_va) + ins.size
                return buf[:end_off]
        window <<= 1
    return last_buf

# ----------------------------
# Instruction helpers
# ----------------------------
def _extract_imm64_load(ins: CsInsn) -> Optional[int]:
    if len(ins.operands) != 2:
        return None
    dst, src = ins.operands
    if dst.type == CS_OP_REG and dst.reg in QWORD_REGS and src.type == CS_OP_IMM:
        return src.imm & 0xFFFFFFFFFFFFFFFF
    return None

def analyze_functions(dis: List[CsInsn]) -> Dict:
    seed_off = None
    template = None
    constants = []

    for i, ins in enumerate(dis):
        mnemonic = ins.mnemonic

        if mnemonic == 'movabs' and len(ins.operands) == 2:
            val = _extract_imm64_load(ins)
            if val is not None:
                constants.append(val)

        elif mnemonic == 'sub' and template is None:
            val = _extract_imm64_load(ins)
            if val in TEMPLATE_VALUES:
                template = TEMPLATE_VALUES[val]
            else:
                break

        elif mnemonic == 'xor' and seed_off is None:
            if i >= 2:
                seed_ins = dis[i - 2]
                if seed_ins.mnemonic == 'add' and len(seed_ins.operands) == 2:
                    seed_off = seed_ins.operands[1].imm
                elif seed_ins.mnemonic == 'sub' and len(seed_ins.operands) == 2:
                    seed_off = - seed_ins.operands[1].imm
                else:
                    seed_off = 0
            else:
                seed_off = 0

    return {
        'seed_offset': seed_off,
        'template': template,
        'constants': constants
    }

# ----------------------------
# Streaming extractor (no full disasm list)
# ----------------------------
def extract_vals_streaming(code: bytes, start_va: int, dll_path: str,
                           metadata: Dict, dlls_dir: str) -> Dict:
    md = get_md()
    values = []
    functions = []
    prev_ins: Optional[CsInsn] = None

    img_base = metadata['image_base']
    img_size = metadata['img_size']
    import_map = metadata['import_map']

    for ins in md.disasm(code, start_va):
        mnem = ins.mnemonic

        if mnem == 'call':
            target_va = None
            op = ins.operands[0]
            if op.type == CS_OP_IMM:
                target_va = op.imm
            elif op.type == CS_OP_REG and prev_ins is not None:
                if len(prev_ins.operands) == 2 and prev_ins.operands[1].type == CS_OP_MEM:
                    mem = prev_ins.operands[1].mem
                    if mem.base == X86_REG_RIP:
                        target_va = prev_ins.address + prev_ins.size + mem.disp

            if target_va:
                # Imported target?
                imp = import_map.get(target_va - img_base)
                if imp:
                    dll_name, func_name = imp
                    dep_path = os.path.join(dlls_dir, dll_name)
                    if func_name and os.path.isfile(dep_path):
                        # Per-process memo for dep metadata
                        dep_meta = _dep_meta_cache.get(dep_path)
                        if dep_meta is None:
                            dep_meta = load_pe_metadata(dep_path)
                            _dep_meta_cache[dep_path] = dep_meta
                        export_va = dep_meta['export_map'].get(func_name)
                        if export_va:
                            try:
                                dep_pe = pefile.PE(dep_path, fast_load=True)
                                code2 = read_function_code(dep_path, export_va, dep_pe)
                                dep_pe.close()
                                if code2:
                                    insts = list(get_md().disasm(code2, export_va))
                                    fn = analyze_functions(insts)
                                    if fn['template'] is not None:
                                        functions.append(fn)
                            except Exception:
                                pass
                else:
                    # Local target?
                    if img_base <= target_va < img_base + img_size:
                        try:
                            pe_obj = pefile.PE(dll_path, fast_load=True)
                            code2 = read_function_code(dll_path, target_va, pe_obj)
                            pe_obj.close()
                            if code2:
                                insts = list(get_md().disasm(code2, target_va))
                                fn = analyze_functions(insts)
                                if fn['template'] is not None:
                                    functions.append(fn)
                        except Exception:
                            pass

        elif mnem == 'mov' and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type == CS_OP_REG and dst.reg == X86_REG_R8D:  # r8d
                if (src.imm & 0xFFFFFFFF) == 0x100:
                    break

        elif mnem == 'movabs' and len(ins.operands) == 2:

            val = _extract_imm64_load(ins)
            if val is not None:
                values.append(val)

        elif mnem == 'ret':
            break

        prev_ins = ins

    return {'functions': functions, 'vals': values}

# ----------------------------
# Worker: single DLL
# ----------------------------
def process_single_dll(dll_path: str, output_dir: Path, dlls_dir: str,
                       export_name: str) -> Tuple[str, bool, Optional[str]]:
    dll_name = os.path.basename(dll_path)
    try:
        # At this point the DLL is prefiltered to have the export; still guard:
        metadata = load_pe_metadata(dll_path)
        export_va = metadata['export_map'].get(export_name)
        if not export_va:
            return (dll_name, False, f"Export '{export_name}' not found")

        pe_obj = pefile.PE(dll_path, fast_load=True)
        code = read_function_code(dll_path, export_va, pe_obj)
        pe_obj.close()
        if not code:
            return (dll_name, False, "Failed to read code section")

        result = extract_vals_streaming(code, export_va, dll_path, metadata, dlls_dir)

        out_path = output_dir / f"{Path(dll_name).stem}.json"
        with open(out_path, 'w', encoding='utf-8') as f:
            _dump_json(result, f)

        return (dll_name, True, None)
    except Exception as e:
        return (dll_name, False, str(e))

# ----------------------------
# Orchestrator
# ----------------------------
def process_all_dlls(dlls_dir: str = "dlls", output_dir: str = "outputs",
                     max_workers: int = None, export_name: str = "_Z5checkPh"):
    dlls_path = Path(dlls_dir)
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    dll_files = list(dlls_path.glob("*.dll"))
    if not dll_files:
        print(f"No DLL files found in {dlls_dir}")
        return

    if max_workers is None:
        # Mixed IO/CPU; increase if your box is beefy NVMe
        max_workers = max(1, mp.cpu_count() // 2)

    print(f"Found {len(dll_files)} DLL files")
    print(f"Using {max_workers} processes")
    print(f"Output directory: {output_path.absolute()}")

    success = failed = 0
    chunk = 256

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for i in range(0, len(dll_files), chunk):
            for dll in dll_files[i:i+chunk]:
                futures.append(executor.submit(
                    process_single_dll, str(dll), output_path, dlls_dir, export_name
                ))

        with tqdm(total=len(futures), desc="Processing DLLs", unit="file") as pbar:
            for fut in as_completed(futures):
                dll_name, ok, err = fut.result()
                if ok:
                    success += 1
                else:
                    failed += 1
                    tqdm.write(f"✗ {dll_name}: {err}")
                pbar.update(1)

    hits, misses, hit_rate = _pe_cache.stats()
    print("\n" + "="*60)
    print(f"Processing Complete!")
    print(f"  Success:   {success}")
    print(f"  Failed:    {failed}")
    print(f"  Total:     {len(dll_files)} considered\n")
    print(f"Cache Performance:")
    print(f"  Hits:      {hits}")
    print(f"  Misses:    {misses}")
    print(f"  Hit Rate:  {hit_rate:.1f}%")
    print("=" * 60)

# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description='Process DLL files and generate JSON reports')
    parser.add_argument('--dlls-dir', default='dlls', help='Directory containing DLL files')
    parser.add_argument('--output-dir', default='outputs', help='Directory for output JSON files')
    parser.add_argument('--threads', type=int, default=None, help='Number of processes (default: auto)')
    parser.add_argument('--export', default='_Z5checkPh', help='Export function name to analyze')
    parser.add_argument('--cache-size', type=int, default=2048, help='Approx total LRU entries (sharded)')

    args = parser.parse_args()

    # Reconfigure sharded cache based on desired total size
    total = max(64, int(args.cache_size))
    shards = 16 if total >= 2048 else 8
    per_shard = max(32, (total + shards - 1) // shards)

    global _pe_cache
    _pe_cache = ShardedPECache(shards=shards, max_size_per_shard=per_shard)

    process_all_dlls(
        dlls_dir=args.dlls_dir,
        output_dir=args.output_dir,
        max_workers=args.threads,
        export_name=args.export
    )
   
if __name__ == '__main__':
    main()
