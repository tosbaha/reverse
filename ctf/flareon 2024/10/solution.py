import angr
import claripy
import logging

logging.disable(logging.WARNING)

def solve(catid):
    project = angr.Project("Catbert.exe", auto_load_libs=False)
    start_addr = 0x140001699  # Entry point of the code
    string_addr = 0x140003103  # Address of the Unicode string
    success_addr = 0x140001749  # Address for success
    fail_addr = 0x1400017B2     # Address for failure
    meme_id = 0x14003885E

    # Create a symbolic 32-byte input (16 characters in UTF-16)
    unicode_string = claripy.BVS("unicode_string", 32 * 8)

    state = project.factory.blank_state(addr=start_addr)
    state.memory.store(meme_id, claripy.BVV(bytes([catid]), 8))
    state.memory.store(string_addr, unicode_string)

    # Constrain the Unicode characters to printable ASCII
    for i in range(16):
        char = unicode_string.get_byte(i * 2)
        high_byte = unicode_string.get_byte(i * 2 + 1)
        state.solver.add(high_byte == 0)
        state.solver.add(char >= 0x20, char <= 0x7E)

    simgr = project.factory.simulation_manager(state)
    simgr.explore(find=success_addr, avoid=fail_addr)

    if simgr.found:
        solution_state = simgr.found[0]
        solution = solution_state.solver.eval(unicode_string, cast_to=bytes)
        decoded_solution = solution.decode('utf-16le')
        print(f"    \033[1;32m🐈 Found a paw-sible solution:\033[0m \033[1;34m{decoded_solution}\033[0m")
    else:
        print("    \033[1;31m🐾🕵️ Cat-tastrophe! Solution not found!\033[0m")

for i in range(3):
    print(f"\033[1;35m🐾🔍 Investigating meowstery \033[1;34mcatmeme{i+1}.jpg.c4tb\033[0m")
    solve(i)
