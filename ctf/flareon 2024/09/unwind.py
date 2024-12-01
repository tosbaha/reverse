from dataclasses import dataclass, field
from typing import List, Optional
import struct

# Simulating enum for Unwind Op Codes
class UnwindOpCodes:
    UWOP_PUSH_NONVOL = 0
    UWOP_ALLOC_LARGE = 1
    UWOP_ALLOC_SMALL = 2
    UWOP_SET_FPREG = 3
    UWOP_SAVE_NONVOL = 4
    UWOP_SAVE_NONVOL_FAR = 5
    UWOP_SPARE_CODE1 = 6
    UWOP_SPARE_CODE2 = 7
    UWOP_SAVE_XMM128 = 8
    UWOP_SAVE_XMM128_FAR = 9
    UWOP_PUSH_MACHFRAME = 10

UnwindOpCodesNames = [
    'UWOP_PUSH_NONVOL',
    'UWOP_ALLOC_LARGE',
    'UWOP_ALLOC_SMALL',
    'UWOP_SET_FPREG',
    'UWOP_SAVE_NONVOL',
    'UWOP_SAVE_NONVOL_FAR',
    'UWOP_SPARE_CODE1',
    'UWOP_SPARE_CODE2',
    'UWOP_SAVE_XMM128',
    'UWOP_SAVE_XMM128_FAR',
    'UWOP_PUSH_MACHFRAME'
]


Registers = [
    "RAX", # 0
    "RCX", # 1
    "RDX", # 2
    "RBX",# 3
    "RSP",# 4
    "RBP",# 5
    "RSI",# 6
    "RDI",# 7
    "R8", # 8
    "R9",# 9
    "R10", # 10
    "R11", # 11
    "R12", # 12
    "R13", # 13
    "R14", # 14
    "R15", # 15
    "UN",
    "UN",
    "UN",
    "UN",
    "UN",
    "UN",
    "UN",
    "UN",
]

# Translating the RtlpUnwindOpSlotTable
RtlpUnwindOpSlotTable = [
    1,  # UWOP_PUSH_NONVOL
    2,  # UWOP_ALLOC_LARGE (or 3, special case in lookup code)
    1,  # UWOP_ALLOC_SMALL
    1,  # UWOP_SET_FPREG
    2,  # UWOP_SAVE_NONVOL
    3,  # UWOP_SAVE_NONVOL_FAR
    0,  # UWOP_SPARE_CODE1
    0,  # UWOP_SPARE_CODE2
    2,  # UWOP_SAVE_XMM128
    3,  # UWOP_SAVE_XMM128_FAR
    1   # UWOP_PUSH_MACHFRAME
]

# Simulating the UNWIND_CODE struct as a class
@dataclass
class UnwindCode:
    CodeOffset: int
    UnwindOp: int
    OpInfo: int

# Simulating the UNWIND_INFO struct as a class
@dataclass
class UnwindInfo:
    Version: int
    Flags: int
    SizeOfProlog: int
    CountOfCodes: int
    FrameRegister: int
    FrameOffset: int
    UnwindCode: List[UnwindCode]

@dataclass
class ContextRecord:
    Rsp: int
    Rip: int
    Xmm0: List[int]  # Assuming list for floating-point registers
    Rax: List[int]   # Assuming list for integer registers

@dataclass
class ContextPointers:
    IntegerContext: List[Optional[int]] = field(default_factory=lambda: [None] * 16)
    FloatingContext: List[Optional[int]] = field(default_factory=lambda: [None] * 16)

@dataclass
class RuntimeFunction:
    BeginAddress: int
    UnwindData: int

def parse_unwind_codes(unwind_codes, count):
    unwind_operations = []
    unwind_texts = []

    i = 0

    while i < count * 2:  # count is the number of UNWIND_CODE entries, each taking 2 bytes
        code_offset = unwind_codes[i]
        op_code = unwind_codes[i + 1] & 0x0F
        op_info = (unwind_codes[i + 1] >> 4) & 0xFF

        # Print the decoded information

        register_name = Registers[op_info]
        unwind_text = f"{UnwindOpCodesNames[op_code]} {op_info}"

        # print(f"UNWIND_CODE <{hex(code_offset)},{hex(op_code)}, {op_info}>; {UnwindOpCodesNames[op_code]} {register_name}")
        slots = RtlpUnwindOpSlotTable[op_code]

        # Handle the different operations
        if op_code == UnwindOpCodes.UWOP_PUSH_NONVOL:
            unwind_operations.append("UWOP_PUSH_NONVOL")
            unwind_text += f" {register_name}"
        elif op_code == UnwindOpCodes.UWOP_ALLOC_LARGE:
            unwind_operations.append("UWOP_ALLOC_LARGE")
            
            if op_info == 1:
                result = int.from_bytes(unwind_codes[i + 2: i+4], byteorder='little')
                unwind_text += f" {hex(result)}"     
                slots += 1
            else:
                unwind_text += f" {hex(unwind_codes[i + 2])}"     


            #print(f"dw {hex(unwind_codes[i + 2])}")  # Extra slot for UWOP_SAVE_NONVOL
        elif op_code == UnwindOpCodes.UWOP_ALLOC_SMALL:
            unwind_operations.append("UWOP_ALLOC_SMALL")
        elif op_code == UnwindOpCodes.UWOP_SET_FPREG:
            unwind_operations.append("UWOP_SET_FPREG")
        elif op_code == UnwindOpCodes.UWOP_SAVE_NONVOL:
            unwind_operations.append("UWOP_SAVE_NONVOL")
            unwind_text += f"\ndw {hex(unwind_codes[i + 2])}"     
            # print(f"dw {hex(unwind_codes[i + 2])}")  # Extra slot for UWOP_SAVE_NONVOL
        elif op_code == UnwindOpCodes.UWOP_SAVE_NONVOL_FAR:
            unwind_operations.append("UWOP_SAVE_NONVOL_FAR")
        elif op_code == UnwindOpCodes.UWOP_SPARE_CODE1:
            unwind_operations.append("UWOP_SPARE_CODE1")
        elif op_code == UnwindOpCodes.UWOP_SPARE_CODE2:
            unwind_operations.append("UWOP_SPARE_CODE2")
        elif op_code == UnwindOpCodes.UWOP_SAVE_XMM128:
            unwind_operations.append("UWOP_SAVE_XMM128")
        elif op_code == UnwindOpCodes.UWOP_SAVE_XMM128_FAR:
            unwind_operations.append("UWOP_SAVE_XMM128_FAR")
        elif op_code == UnwindOpCodes.UWOP_PUSH_MACHFRAME:
            unwind_operations.append("UWOP_PUSH_MACHFRAME")

        unwind_texts.append(unwind_text)
        # Increment `i` based on the number of slots the current opcode occupies
        i += slots * 2  # Each slot is 2 bytes

    return (unwind_operations,unwind_texts)

def extract_unwind_info(data):
    parsed_info = {}
    header = struct.unpack_from("<B B B B", data, 0)  # Read first 4 bytes
    version_and_flags = header[0]  # Version and Flags (high nibble is version, low nibble is flags)
    version = version_and_flags >> 3
    flags = version_and_flags & 0x07
    prolog_size = header[1]  # Prolog size in bytes
    unwind_codes_count = header[2]  # Number of unwind codes

    code_size = unwind_codes_count
    if code_size % 2 != 0:
        code_size += 1  # Add one slot for padding if necessary

    unwind_codes_start = 4
    
    unwind_codes_end = unwind_codes_start + unwind_codes_count * 2  # Each unwind code is 2 bytes
    unwind_codes = data[unwind_codes_start:]

    # print(unwind_codes)
    # print(f"Codes: {unwind_codes.hex()}")

    unwind_codes_parsed,unwind_text = parse_unwind_codes(unwind_codes,unwind_codes_count)

    offset_position = unwind_codes_start + code_size * 2  # Each unwind code is 2 bytes

    frame_register_offset = (header[3] >> 4) & 0xF
    frame_register = header[3] & 0xF # if > 0 we have a source register.

    parsed_info['version'] = version
    parsed_info['flags'] = flags
    parsed_info['prolog_size'] = prolog_size
    parsed_info['unwind_codes_count'] = unwind_codes_count
    parsed_info['frame_register'] = frame_register
    parsed_info['frame_register_offset'] = frame_register_offset
    parsed_info['parsed'] = unwind_codes_parsed
    parsed_info['hex'] = unwind_codes
    parsed_info['unwind_text'] = unwind_text

    if flags & 0x01:  # Check if UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER is set
    # Exception handler RVA comes after the unwind codes array
        exception_handler_rva = struct.unpack_from("<I", data, offset_position)[0]  # 4 bytes
        parsed_info['exception_handler_rva'] = exception_handler_rva
        offset_position += 4  # Move past exception handler RVA


    return parsed_info

def find_unwind_ptr(data,pos):
    piVar1 = [0] * 4  # Allocate a list of 3 integers
    piVar1[0] = pos
    piVar1[1] = piVar1[0] + 1
    byte_value = data[pos+1:pos+1+1][0]
    piVar1[2] = piVar1[1] + 1 + byte_value
    
    local_28 = (piVar1[2] & 1) != 0
    
    if local_28: 
        piVar1[2] += 1
    return piVar1[2]
