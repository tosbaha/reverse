#!/usr/bin/env python3
"""
reconstruct_sequence.py

Usage:
  python reconstruct_sequence.py --deps deps.json --counts counts.txt --out mapping.json

What it does:
- Parses deps.json (DAG, immediate dependencies only, no recursion).
- Parses counts.txt (10,000 hex sums with 'h' suffix, in id order 0000..9999).
- Computes s[u] = sum of indices where id u was selected as the main id.
- Partitions indices 1..9999 so each id's assigned indices sum to s[u].
- Assigns index 0 arbitrarily (it contributes 0).
- Writes a JSON mapping: {"0":"....","1":"....",...,"9999":"...."}.
"""

from __future__ import annotations
import argparse
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional

# ---------- Input parsing ----------

def parse_counts_txt(path: Path) -> List[int]:
    """Parse counts.txt containing 10,000 hex values with 'h' suffix."""
    data = path.read_text().replace("\n", ",").replace(" ", "")
    if not data:
        raise ValueError("counts.txt is empty")
    parts = [p for p in data.split(",") if p]
    if len(parts) != 10000:
        raise ValueError(f"Expected 10,000 counts, got {len(parts)}")
    counts = []
    for p in parts:
        s = p.strip()
        if not s.endswith(("h", "H")):
            raise ValueError(f"Invalid token (missing 'h' suffix): {s}")
        s = s[:-1]
        if s.lower().startswith("0x"):
            s = s[2:]
        s = s.replace("_", "")
        counts.append(int(s, 16))
    return counts

def parse_deps_json(path: Path) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Returns:
      children: dict id -> list of immediate deps (deduped, order preserved)
      ids_in_order: ["0000", "0001", ..., "9999"] (as discovered; also validated)
    """
    data = json.loads(path.read_text())
    # Build children map and ensure 10k ids 0000..9999 exist
    expected = [f"{i:04d}" for i in range(10000)]
    seen = set()
    children: Dict[str, List[str]] = {}
    for entry in data:
        i = entry["i"]
        d = entry.get("d", [])
        if i in seen:
            # If duplicates appear, last wins (or we can error; choose strict)
            raise ValueError(f"Duplicate id in deps.json: {i}")
        seen.add(i)
        # de-duplicate while preserving order
        seen_child = set()
        clean = []
        for c in d:
            if c == i:
                # spec says d doesn't include main id; if present, ignore or error
                # We'll ignore with a warning-like behavior
                continue
            if c not in seen_child:
                seen_child.add(c)
                clean.append(c)
        children[i] = clean

    missing = set(expected) - seen
    extra = seen - set(expected)
    if missing or extra:
        msg = []
        if missing: msg.append(f"missing {len(missing)} ids")
        if extra: msg.append(f"found {len(extra)} unexpected ids")
        raise ValueError("deps.json id set mismatch: " + ", ".join(msg))

    # Ensure every id has an entry (if some omitted, treat as empty deps)
    for i in expected:
        children.setdefault(i, [])
    return children, expected

# ---------- Graph utilities ----------

def topo_sort_from_children(children: Dict[str, List[str]]) -> List[str]:
    """Topological order for DAG with edges u -> v for v in children[u]."""
    indeg = defaultdict(int)
    for u in children:
        indeg[u]  # ensure key
    for u, outs in children.items():
        for v in outs:
            indeg[v] += 1
    q = deque([u for u, deg in indeg.items() if deg == 0])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in children[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(order) != len(children):
        raise RuntimeError("Graph has cycles or disconnected anomalies (should not happen after your check).")
    return order

def build_parents(children: Dict[str, List[str]]) -> Dict[str, List[str]]:
    parents: Dict[str, List[str]] = {u: [] for u in children}
    for u, outs in children.items():
        for v in outs:
            parents[v].append(u)
    return parents

# ---------- Recover s from counts ----------

def recover_s(counts: List[int], ids: List[str], children: Dict[str, List[str]]) -> List[int]:
    """
    For each id j:
      C_j = s_j + sum_{u: j in d(u)} s_u
    In topo order (parents before children), we have:
      s_j = C_j - sum_{u in parents(j)} s_u
    """
    id_to_idx = {i: idx for idx, i in enumerate(ids)}
    parents = build_parents(children)
    topo = topo_sort_from_children(children)  # parents before children

    # Work in id order for outputs
    s = [0] * len(ids)
    # We'll compute s in topo order but store by id index
    computed = set()
    for j in topo:
        pj = parents[j]
        sj = counts[id_to_idx[j]] - sum(s[id_to_idx[u]] for u in pj)
        if sj < 0:
            raise ValueError(f"Recovered negative s for id {j}: {sj}. Check inputs.")
        s[id_to_idx[j]] = sj
        computed.add(j)

    # sanity: sum(s) must equal sum(1..9999)
    total_needed = 9999 * 10000 // 2  # 49_995_000
    if sum(s) != total_needed:
        raise ValueError(f"Sum(s)={sum(s)} != {total_needed}. Inputs inconsistent?")
    return s

# ---------- Assign indices 1..9999 to hit targets s[u] ----------

def assign_indices(s: List[int], ids: List[str]) -> List[str]:
    n = 10000
    owner = [""] * n

    # rem per id index
    rem = s[:]  # copy

    def T(k: int) -> int:
        return k * (k + 1) // 2

    assigned = set()  # track which ids have been given an index > 0
    for k in range(9999, 0, -1):
        sum_small = T(k - 1)  # max sum you can still form after using k

        forced_idx: Optional[int] = None
        max_over = -1
        for i_idx, r in enumerate(rem):
            over = r - sum_small
            if over > 0 and r >= k:
                if over > max_over:
                    max_over = over
                    forced_idx = i_idx

        if forced_idx is not None:
            i_idx = forced_idx
        else:
            i_idx = None
            best_r = -1
            for j_idx, r in enumerate(rem):
                if r >= k and r > best_r:
                    best_r = r
                    i_idx = j_idx
            if i_idx is None:
                raise RuntimeError(f"No feasible id found to take index {k}. Need repair/backtracking.")

        rem[i_idx] -= k
        owner[k] = ids[i_idx]
        assigned.add(ids[i_idx])

    # Find the single id that wasn't assigned any k>0 and give it index 0
    remaining = [i for i in ids if i not in assigned]
    if len(remaining) != 1:
        total_left = sum(rem)
        raise RuntimeError(f"Expected exactly one unassigned id for index 0, found {len(remaining)}. "
                           f"Total leftover rem sum={total_left}.")
    owner[0] = remaining[0]

    bad = [(ids[i], r) for i, r in enumerate(rem) if r != 0]
    if bad:
        total_left = sum(r for _, r in bad)
        raise RuntimeError(f"Post-assignment remainder not zero for {len(bad)} ids, total leftover={total_left}. "
                           f"First few: {bad[:5]}")

    return owner

# ---------- Utilities ----------

def make_mapping(owner: List[str]) -> Dict[str, str]:
    """owner[k] is id; return dict with string keys"""
    return {str(k): owner[k] for k in range(len(owner))}

def save_json(obj, path: Path):
    path.write_text(json.dumps(obj, indent=2))


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", type=Path, required=True)
    ap.add_argument("--counts", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()


    children, ids = parse_deps_json(args.deps)
    counts = parse_counts_txt(args.counts)

    s = recover_s(counts, ids, children)
    owner = assign_indices(s, ids)
    mapping = make_mapping(owner)

    save_json(mapping, args.out)
    print(f"Done. Wrote mapping to: {args.out}")
    # Optional: quick validation
    # Rebuild counts from mapping and deps to ensure we match input
    ok = validate_mapping(mapping, children, ids, counts)
    print(f"Validation: {'OK' if ok else 'FAILED'}")

def validate_mapping(mapping: Dict[str, str],
                     children: Dict[str, List[str]],
                     ids: List[str],
                     orig_counts: List[int]) -> bool:
    """
    Recompute counts from the produced mapping and compare to orig_counts.
    """
    id_to_idx = {i: idx for idx, i in enumerate(ids)}
    counts = [0] * len(ids)
    for k_str, u in mapping.items():
        k = int(k_str)
        # Add k to main id and its immediate deps
        counts[id_to_idx[u]] += k
        for v in children[u]:
            counts[id_to_idx[v]] += k
    return counts == orig_counts

if __name__ == "__main__":
    main()
