import json
from typing import Dict, List, Tuple, Iterable

def build_graph(states_json: List[dict]) -> Dict[int, List[Tuple[int, int]]]:
    graph: Dict[int, List[Tuple[int, int]]] = {}
    for entry in states_json:
        state_id = int(entry["case"][0])
        transitions = []
        for p in entry.get("pos", []):
            cmp_imm = int(p["cmp_imm"])
            next_state = int(p["next_state"])
            transitions.append((cmp_imm, next_state))
        graph[state_id] = transitions
    return graph


def enumerate_sequences(
    graph: Dict[int, List[Tuple[int, int]]],
    start_state: int,
    length: int,
) -> Iterable[Tuple[List[int], str]]:
    stack: List[Tuple[int, List[int]]] = [(start_state, [])]

    while stack:
        state, seq = stack.pop()
        # print(f"[DEBUG] At state {state}, seq so far {seq}")

        if len(seq) == length:
            s = "".join(chr(x % 256) for x in seq)
            # print(f"[DEBUG] Completed sequence: {seq} -> {repr(s)}")
            yield (seq, s)
            continue

        transitions = graph.get(state, [])
        # if not transitions:
        #     print(f"[DEBUG] Dead end at state {state}, seq={seq}")
        for (val, nxt) in transitions:
            # print(f"[DEBUG]  Trying val={val} (chr={chr(val%256)!r}), next_state={nxt}")
            stack.append((nxt, seq + [val]))


def run_from_file(path: str, start_state: int = 0, length: int = 16):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    graph = build_graph(data)

    count = 0
    for ints, s in enumerate_sequences(graph, start_state, length):
        print(s)
        count += 1


if __name__ == "__main__":
    run_from_file("state.json", start_state=0, length=16)
