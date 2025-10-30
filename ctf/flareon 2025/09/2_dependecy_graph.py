import pefile
import os
import sys
import json
from pathlib import Path
from typing import Set, List, Dict, Tuple
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from functools import lru_cache
from collections import deque

DLL_MAP = Dict[str, List[str]]
_DIRECT_IMPORTS_MAP = None

def _worker_init(direct_imports_map):
    """Initializer that runs in each worker process to set a read-only global."""
    global _DIRECT_IMPORTS_MAP
    _DIRECT_IMPORTS_MAP = direct_imports_map

def _compute_transitive_for(dll_name: str) -> Tuple[str, List[str]]:
    """
    Top-level worker function (picklable). Uses _DIRECT_IMPORTS_MAP populated
    by the initializer in each worker process.
    """
    global _DIRECT_IMPORTS_MAP
    all_deps: List[str] = []
    seen = set()
    queue = deque()

    # safe guard: if map missing (shouldn't happen), return empty
    if not _DIRECT_IMPORTS_MAP:
        return dll_name, []

    # Seed queue with direct numeric imports
    for imp in _DIRECT_IMPORTS_MAP.get(dll_name, []):
        if is_numeric_dll(imp) and imp != dll_name:
            seen.add(imp)
            queue.append(imp)

    while queue:
        cur = queue.popleft()
        all_deps.append(cur)
        for imp in _DIRECT_IMPORTS_MAP.get(cur, []):
            if is_numeric_dll(imp) and imp not in seen and imp != dll_name:
                seen.add(imp)
                queue.append(imp)

    return dll_name, all_deps

# --- Utils ---
def is_numeric_dll(dll_name: str) -> bool:
    return dll_name.lower().endswith('.dll') and dll_name[:-4].isdigit() and len(dll_name) == 8


def parse_dll_imports(dll_path: str) -> Tuple[str, List[str]]:
    dll_name = Path(dll_path).name
    imports = []
    try:
        # ⚡ OPTIMIZATION: Disable rich parsing
        pe = pefile.PE(dll_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = [entry.dll.decode('utf-8', errors='ignore') for entry in pe.DIRECTORY_ENTRY_IMPORT]
        pe.close()
    except Exception:
        pass
    return dll_name, imports


def parse_all_dlls_parallel(dll_folder: Path, numeric_dlls: List[str]) -> DLL_MAP:
    num_workers = max(1, multiprocessing.cpu_count() - 1)  # ⚡ Keep 1 core free
    dll_paths = [str(dll_folder / dll) for dll in numeric_dlls]
    results = {}

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        for dll_name, imports in tqdm(
            executor.map(parse_dll_imports, dll_paths, chunksize=64),  # ⚡ Use chunking
            total=len(dll_paths),
            desc="Parsing DLLs (Step 1)",
            unit="dll"
        ):
            results[dll_name] = imports
    return results


# --- Parallel Graph Expansion ---
def _get_transitive_deps_worker(start_dll_name: str, direct_imports_map: DLL_MAP) -> Tuple[str, List[str]]:
    seen: Set[str] = set()
    deps: List[str] = []
    queue = deque(direct_imports_map.get(start_dll_name, []))

    while queue:
        dll = queue.popleft()
        if dll in seen or not is_numeric_dll(dll) or dll == start_dll_name:
            continue
        seen.add(dll)
        deps.append(dll)
        for dep in direct_imports_map.get(dll, []):
            if dep not in seen:
                queue.append(dep)

    return start_dll_name, deps


def build_transitive_closure_parallel(direct_imports_map: DLL_MAP) -> DLL_MAP:
    """
    Rewritten to use top-level worker and initializer to avoid pickling local functions.
    """
    print("Step 2: Building complete dependency graph (Transitive Closure) in parallel...")

    numeric_dlls = [dll for dll in direct_imports_map.keys() if is_numeric_dll(dll)]
    num_workers = max(1, multiprocessing.cpu_count() - 1)

    transitive_map: DLL_MAP = {}

    # Pass the whole dict once to each worker via initializer (it will be pickled once per worker)
    with ProcessPoolExecutor(max_workers=num_workers, initializer=_worker_init, initargs=(direct_imports_map,)) as executor:
        # executor.map uses an internal iterator; use chunksize to reduce overhead
        for dll_name, deps in tqdm(executor.map(_compute_transitive_for, numeric_dlls, chunksize=64),
                                   total=len(numeric_dlls),
                                   desc="Graph Traversal (Step 2)", unit="dll"):
            transitive_map[dll_name] = deps

    return transitive_map

def dll_to_id(dll_name: str) -> str:
    return dll_name[:-4]


def generate_dependency_report(dll_folder: str, output_file: str) -> None:
    dll_path = Path(dll_folder)
    if not dll_path.is_dir():
        sys.exit(f"Error: {dll_folder} is not a valid directory")

    numeric_dlls = [f"{i:04d}.dll" for i in range(10000) if (dll_path / f"{i:04d}.dll").exists()]
    print(f"Found {len(numeric_dlls)} numeric DLLs")

    # Step 1: Parse imports
    direct_imports_map = parse_all_dlls_parallel(dll_path, numeric_dlls)

    # Step 2: Build dependency graph
    transitive_map = build_transitive_closure_parallel(direct_imports_map)

    # Step 3: Write compact JSON
    print(f"\nStep 3: Writing {output_file}...")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write('[')
        for i, dll in enumerate(tqdm(numeric_dlls, desc="Writing Output", unit="dll")):
            if i:
                f.write(',')
            entry = {"i": dll_to_id(dll), "d": [dll_to_id(x) for x in transitive_map.get(dll, [])]}
            json.dump(entry, f, separators=(',', ':'))
        f.write(']')

    print(f"\n✓ Done! {len(numeric_dlls)} DLLs processed → {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <dll_folder> [deps.json]")
        sys.exit(1)

    folder = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "deps.json"
    multiprocessing.freeze_support()
    generate_dependency_report(folder, output)


if __name__ == "__main__":
    main()
