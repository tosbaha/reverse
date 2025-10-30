
import os, struct, pefile
from typing import List
import os
import pefile
from aplib import APLib

def _u16(b, off): return struct.unpack_from("<H", b, off)[0]
def _u32(b, off): return struct.unpack_from("<I", b, off)[0]

class ResNode:
    __slots__ = ("type_key","name_key","lang_key","data_rva","size")
    def __init__(self, t, n, l, rva, sz):
        self.type_key, self.name_key, self.lang_key = t, n, l
        self.data_rva, self.size = int(rva), int(sz)

def _sec_bounds_for_rva(pe: pefile.PE, rva: int):
    sec = pe.get_section_by_rva(rva)
    if not sec:
        raise ValueError("Resource RVA does not map to any section")
    sec_rva  = int(sec.VirtualAddress)
    sec_size = max(int(sec.Misc_VirtualSize), int(sec.SizeOfRawData))
    return sec, sec_rva, sec_size

def _read_name_string_rel(rs_bytes: bytes, rel_off: int, sec_len: int) -> str:
    """
    Read IMAGE_RESOURCE_DIR_STRING_U at rs_bytes[rel_off ...], where rel_off is section-relative.
    """
    if rel_off + 2 > sec_len:  # WORD Length
        raise ValueError("Name length OOB")
    wlen = _u16(rs_bytes, rel_off); rel_off += 2
    byte_count = wlen * 2
    if rel_off + byte_count > sec_len:
        raise ValueError("Name string OOB")
    return rs_bytes[rel_off:rel_off+byte_count].decode("utf-16le", errors="ignore")

def _parse_dir(rs_bytes: bytes, sec_len: int, base_rel: int,
               level_keys: list, out_nodes: List[ResNode], depth: int = 0):
    """
    Recursively parse IMAGE_RESOURCE_DIRECTORY starting at section-relative offset base_rel.
    All offsets here are section-relative (0..sec_len).
    """
    # Directory header (16 bytes)
    if base_rel < 0 or base_rel + 16 > sec_len:
        return
    NumberOfNamedEntries = _u16(rs_bytes, base_rel + 12)
    NumberOfIdEntries    = _u16(rs_bytes, base_rel + 14)
    total_entries = NumberOfNamedEntries + NumberOfIdEntries

    entries_rel = base_rel + 16
    table_end   = entries_rel + total_entries * 8
    if table_end > sec_len:
        # Truncated directory table; stop gracefully
        total_entries = max(0, (sec_len - entries_rel) // 8)

    for i in range(total_entries):
        e_rel = entries_rel + i * 8
        name_or_id = _u32(rs_bytes, e_rel + 0)
        off2       = _u32(rs_bytes, e_rel + 4)

        # name_or_id: high bit -> offset to UNICODE string (section-relative)
        if name_or_id & 0x80000000:
            name_rel = (name_or_id & 0x7FFFFFFF)
            try:
                key = _read_name_string_rel(rs_bytes, name_rel, sec_len)
            except Exception:
                key = f"badname_0x{name_rel:X}"
        else:
            key = name_or_id  # numeric id

        is_subdir   = bool(off2 & 0x80000000)
        target_rel  = (off2 & 0x7FFFFFFF)

        if is_subdir:
            if depth >= 2:  # expect max 3 levels: TYPE -> NAME -> LANG
                continue
            if 0 <= target_rel < sec_len:
                _parse_dir(rs_bytes, sec_len, target_rel, level_keys + [key], out_nodes, depth + 1)
            continue

        # IMAGE_RESOURCE_DATA_ENTRY (16 bytes) at target_rel (section-relative)
        if target_rel < 0 or target_rel + 16 > sec_len:
            continue
        data_rva = _u32(rs_bytes, target_rel + 0)
        data_sz  = _u32(rs_bytes, target_rel + 4)

        keys = level_keys + [key]
        t = keys[0] if len(keys) > 0 else None
        n = keys[1] if len(keys) > 1 else None
        l = keys[2] if len(keys) > 2 else None
        out_nodes.append(ResNode(t, n, l, data_rva, data_sz))

def enumerate_resources_manual(pe: pefile.PE) -> List[ResNode]:
    """
    Returns list[ResNode] by parsing .rsrc manually using section-relative offsets only.
    """
    res_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
    ]
    if not res_dd.VirtualAddress:
        return []
    sec, sec_rva, sec_size = _sec_bounds_for_rva(pe, res_dd.VirtualAddress)

    # Pull the WHOLE .rsrc section into memory
    rs_bytes = pe.get_data(sec_rva, sec_size)
    if not rs_bytes:
        return []

    sec_len = len(rs_bytes)
    # Root directory start is section-relative:
    root_rel = int(res_dd.VirtualAddress) - sec_rva
    if not (0 <= root_rel < sec_len):
        return []

    nodes: List[ResNode] = []
    _parse_dir(rs_bytes, sec_len, root_rel, [], nodes, 0)
    return nodes

def dump_all_resources(path_exe: str, out_dir: str, verbose_every: int = 500) -> int:

    # expects enumerate_resources_manual(pe) and ResNode to be defined as earlier
    pe = pefile.PE(path_exe, fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        )
    except Exception:
        pass

    nodes = enumerate_resources_manual(pe)
    if not nodes:
        print("[-] No resources found (manual parse).")
        return 0

    os.makedirs(out_dir, exist_ok=True)
    count = 0
    for i, n in enumerate(nodes, 1):
        try:
            blob = pe.get_data(n.data_rva, n.size)
        except Exception:
            blob = None
        if not blob:
            continue
        blob = blob[: n.size]

        id_txt = f"{n.name_key:04d}"
        fname = os.path.join(out_dir, f"{id_txt}.dll")
        blob = APLib(blob,False).depack()

        try:
            with open(fname, "wb") as f:
                f.write(blob)
            count += 1
            if verbose_every and (i % verbose_every == 0):
                print(f"[+] Dumped {i}/{len(nodes)} (last: {fname}, {len(blob)} bytes)")
        except Exception as e:
            print(f"[!] Failed writing {fname}: {e}")

    print(f"[+] Dumped {count} resource payload(s) to: {out_dir}")
    return count

if __name__ == "__main__":
    dumped = dump_all_resources("10000.exe", "dlls")
    print("Total dumped:", dumped)