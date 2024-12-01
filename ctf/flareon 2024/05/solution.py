from __future__ import print_function
import collections
import capstone
import os
import binascii

from unicorn import *
from unicorn.x86_const import *

BASE_ADDRESS = 0x7f4a18c86000 
STACK_ADDRESS = 0x2000000  # 32MB stack address (higher memory)
RBP_DATA_ADDRESS = 0x3000000  # 48MB for RBP data

def disassemble(code, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
    for i in cs.disasm(code, addr):
        return i
    
def hook_code(emu, address, size, user_data):
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def intr_hook(emu, intno, data):
    print(" \-> interrupt={:d}".format(intno))
    return

def hexdump(data, length=16):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('Input must be bytes or bytearray.')

    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_chunk = ' '.join(f'{b:02x}' for b in chunk)
        ascii_chunk = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        result.append(f'{i:08x}  {hex_chunk:<{length*3}}  {ascii_chunk}')
    
    return '\n'.join(result)

def load_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

def create_new_file(original_file,new_bytes):
    # original_file = "liblzma.so.5.4.1"
    new_file = "liblzma.so.5.4.1.modified"
    offset = 0x23960

    # Read the original file and create a modified copy
    with open(original_file, "rb") as original, open(new_file, "wb") as modified:
        # Copy the original file content to the new file
        modified.write(original.read())

    # Modify the new file at the specified offset
    with open(new_file, "r+b") as modified:
        # Seek to the specified offset
        modified.seek(offset)
        # Write the new bytes
        modified.write(new_bytes)

def hook_code(mu:Uc, address, size, user_data):

    code = mu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))

    # Stopping at 0x98E7 (adjusted for mapped memory)
    if address == 0x7F4A18C8F8E7:
        print(f"Reached stopping point at address: 0x{address:X}")
        print_registers(mu)

        new_data_address = RBP_DATA_ADDRESS + 1024 
        print(f"Setting RAX to new data region: 0x{new_data_address:X}")

        original_bytes = mu.mem_read(0x7F4A18CA9960,0x0F96)
        mu.mem_write(new_data_address, bytes(original_bytes))

        # Set RAX to the new memory region
        mu.reg_write(UC_X86_REG_RAX, new_data_address)

        # Skip unwanted code blocks by setting RIP to 0x0991E
        new_rip = 0x7f4a18c8f925
        print(f"Changing RIP to skip to: 0x{new_rip:X}")
        mu.reg_write(UC_X86_REG_RIP, new_rip)  # Set RIP to the new address
        mu.reg_write(UC_X86_REG_RDX,0x0F96)
        
    # Stopping at 0x993A
    elif address == 0x7F4A18C8F93A:
        print(f"Reached second stopping point at address: 0x{address:X}")
        r8_address = mu.reg_read(UC_X86_REG_R8)
        dump = mu.mem_read(r8_address,32)

        decrypted_data = mu.mem_read(r8_address,0x0F96)
        with open("shellcode.bin", "wb") as f:
            f.write(decrypted_data)

        create_new_file(LIB_PATH,decrypted_data)


        mu.reg_write(UC_X86_REG_RIP, 0x7F4A18CAA7DF)  # Set RIP to the new address
        mu.reg_write(UC_X86_REG_RDX,0x0F96)

        # 7F4A18CAA7DF
        # 07F4A18CAA7DF -> Decrypt

        # 7F4A18CAA82F
        insn = disassemble(dump, r8_address)
        print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))

        print(hexdump(dump))
        
        print_registers(mu)
        mu.emu_stop()  # Finally stop emulation here

def print_registers(mu):
    print(f"RIP: 0x{mu.reg_read(UC_X86_REG_RIP):X}")
    print(f"RBP: 0x{mu.reg_read(UC_X86_REG_RBP):X}")
    print(f"RSP: 0x{mu.reg_read(UC_X86_REG_RSP):X}")
    print(f"RAX: 0x{mu.reg_read(UC_X86_REG_RAX):X}")
    print(f"RBX: 0x{mu.reg_read(UC_X86_REG_RBX):X}")
    print(f"RCX: 0x{mu.reg_read(UC_X86_REG_RCX):X}")
    print(f"RDX: 0x{mu.reg_read(UC_X86_REG_RDX):X}")
    print(f"R8: 0x{mu.reg_read(UC_X86_REG_R8):X}")

def emulate(filepath, rbp_data_hex):
    # Initialize Unicorn emulator for x86-64
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    code = load_file(filepath)
    mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)  # 2MB of code space
    mu.mem_map(STACK_ADDRESS, 2 * 1024 * 1024)  # 2MB of stack space
    mu.mem_map(RBP_DATA_ADDRESS, 2 * 1024 * 1024)  # 2MB of RBP data space
    mu.mem_write(BASE_ADDRESS, code)

    rbp_data = binascii.unhexlify(rbp_data_hex)
    mu.mem_write(RBP_DATA_ADDRESS, rbp_data)

    mu.reg_write(UC_X86_REG_RBP, RBP_DATA_ADDRESS)  # Point RBP to our data
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + 0x2000)  # Set stack pointer

    # Hook to stop at 0x98E7

    # Start emulating at the offset 0x98C0
    START_ADDRESS = 0x7F4A18C8F8C0
    END_ADDRESS = 0x7F4A18C8F93C #0x7F4A18C8F93C
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x7F4A18C8F3F0, end=END_ADDRESS)

    # Emulate from 0x98C0 to 0x98E7
    try:
        mu.emu_start(START_ADDRESS, END_ADDRESS)
    except UcError as e:
        print(f"Error during emulation: {e}")


LIB_PATH = "liblzma.so.5.4.1"

hex_string = "487a40c5943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66ff236839f4dcd711a528629555858d1b7f9a7c20d36de0e19eaa30596da59b9b90d178f41423d7eeb1507b5dc039cb849a85998cc611f379b4d0af250bdab372d0c3716e2a3404b1151ad49a94a1a958e266b98916ab0a708eecbd0f3d20147d05f9e67a9f12d6c158d6fa5bd32d58a176d7e618516e66c314814038a9a4f80acea50685c2f740d9f000ab68ada79423a702a9917fbbd95535163bc8394ff7b8170b782641e3c1fa0ad4f7ae0e381edbd395eab4010e3452db2dc0fbc790115037102e82e9fa915430615a3c39478219669739eaa721b7c52326b23ad14ef31fd2acfa3aef9deca0cb65741a773ce9fb660963de2ac4b682078638ee171c120e6c18b8712a645e048641cc9b281eb3e3d3e48546483a99822b186a22e841725c8cbc9ba05d2ca8f1ec0691f9d42756f7b423ea19ce685df1f35157b1011ac665dc3f0147cc6c56ca56b90c4570683f8d8692dea681ffb147733ed7753773627aec3dc2557e7d95bd5983ba784af12fbfe060870272de4b901a67c5b1e8cf749743aadf00371c4965fed5d533b39047785f1843afcdabe7c1069bde791d43ac6bde9cb0a7bddc775b4006a536343317c3f32dfae7dd6da84b53ec717382b84670efeeca590228dfa0076a5972c37b71c969cccfbce3dc03c4fe67862ad"
emulate(LIB_PATH, hex_string)




