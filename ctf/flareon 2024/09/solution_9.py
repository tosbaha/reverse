import ctypes
import struct
from unicorn import *
from unicorn.x86_const import *
import pefile
import capstone
import json

from registers import get_register
from unwind import extract_unwind_info,Registers
from context import EXCEPTION_RECORD,CONTEXT,CONTEXT_EX

with open('tables.json', 'r') as f:
    operation_tables = json.load(f)

def round_up_page(val: int) -> int:
    return val - val % -0x1000

def load_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()
    
def map_file(mu,filepath,address):
    pe = pefile.PE(filepath)
    
    for x in pe.sections:
        mu.mem_map(address + x.VirtualAddress, round_up_page(x.Misc_VirtualSize))
        mu.mem_write(address + x.VirtualAddress, x.get_data())

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

def create_exception_record(exception_code, exception_flags, exception_record_address, exception_address, exception_info=None):
    exception_record = EXCEPTION_RECORD()
    exception_record.ExceptionCode = exception_code
    exception_record.ExceptionFlags = exception_flags
    exception_record.ExceptionRecord = exception_record_address  # Pass 0 if no nested EXCEPTION_RECORD
    exception_record.ExceptionAddress = exception_address
    exception_record.NumberParameters = 0 if not exception_info else len(exception_info)
    
    if exception_info:
        for i in range(len(exception_info)):
            exception_record.ExceptionInformation[i] = exception_info[i]

    return exception_record

def create_context(mu:Uc):
    context = CONTEXT()
    context.Rax = mu.reg_read(UC_X86_REG_RAX)
    context.Rbx = mu.reg_read(UC_X86_REG_RBX)
    context.Rcx = mu.reg_read(UC_X86_REG_RCX)
    context.Rdi = mu.reg_read(UC_X86_REG_RDI)
    context.Rdx = mu.reg_read(UC_X86_REG_RDX)
    context.Rip = mu.reg_read(UC_X86_REG_RIP)
    context.Rsi = mu.reg_read(UC_X86_REG_RSI)
    context.Rbp = mu.reg_read(UC_X86_REG_RBP)
    context.Rsp = mu.reg_read(UC_X86_REG_RSP)
    
    context.R8 = mu.reg_read(UC_X86_REG_R8)
    context.R9 = mu.reg_read(UC_X86_REG_R9)
    context.R10 = mu.reg_read(UC_X86_REG_R10)
    context.R11 = mu.reg_read(UC_X86_REG_R11)
    context.R12 = mu.reg_read(UC_X86_REG_R12)
    context.R13 = mu.reg_read(UC_X86_REG_R13)
    context.R14 = mu.reg_read(UC_X86_REG_R14)
    context.R15 = mu.reg_read(UC_X86_REG_R15)
    
    # Read MXCSR register
    context.MxCsr = mu.reg_read(UC_X86_REG_MXCSR)
    context.EFlags = mu.reg_read(UC_X86_REG_EFLAGS)
    return context

def create_context_ex(mu:Uc,allocation_size):
    context_ex = CONTEXT_EX()
    context_size =  ctypes.sizeof(CONTEXT)
    context_ex.All.Offset = -context_size & 0xFFFFFFFF
    context_ex.All.Length = allocation_size
    context_ex.Legacy.Offset = -context_size & 0xFFFFFFFF
    context_ex.Legacy.Length = context_size
    context_ex.XState.Offset = 0xF0
    context_ex.XState.Length = 0x168
    return context_ex

def dump_exception_record_to_bytes(context):
    # Convert the structure to a byte string
    return ctypes.string_at(ctypes.addressof(context), ctypes.sizeof(context))

# I wish this could work lol but couln't setup the GDT so I manually handled Unwind.
def create_exception_buffer(mu:Uc,address):

    # CONTEXT          @ rsp + 0   : 4d0
    # CONTEXT_EX       @ rsp + 4d0 : 18
    # alignment        @ rsp + 4e8 : 8
    # EXCEPTION_RECORD @ rsp + 4f0 : 98
    # alignment        @ rsp + 588 : 8
    # MACHINE_FRAME    @ rsp + 590 : 28                       | alignas(16) from RSP in exception / xstate
    # alignment        @ rsp + 5b8 : 8
    # xstate           @ rsp + 5c0 : CONTEXT_EX.Xstate.Length | alignas(64) from RSP in exception
    allocation_size = 0x728
    context = create_context(mu)
    context_ex = create_context_ex(mu,allocation_size)
    csp = context.Rsp - allocation_size

    exception_code = 0xc0000096  # Privileged instruction exception code
    exception_flags = 0x0        # No flags
    exception_record_address = 0  # No nested exception (use 0)
    exception_address = address  # Example address where the exception occurred
    exception_info = []  # No additional exception information

# Create the EXCEPTION_RECORD
    exception_record = create_exception_record(exception_code, exception_flags, exception_record_address, exception_address, exception_info)
    buffer = bytearray()
    buffer.extend(ctypes.string_at(ctypes.addressof(context), ctypes.sizeof(context)))
    buffer.extend(ctypes.string_at(ctypes.addressof(context_ex), ctypes.sizeof(context_ex)))
        # Add alignment (0x8 bytes)
    buffer.extend(b'\x00' * 8)
    buffer.extend(ctypes.string_at(ctypes.addressof(exception_record), ctypes.sizeof(exception_record)))
    buffer.extend(b'\x00' * 8)
    # Add MACHINE_FRAME (assuming size of 0x28)

    address_data = struct.pack("<Q", address)
    buffer.extend(address_data)
    # Unknown
    buffer.extend(b'\x00' * 16)
    context_data = struct.pack("<Q", context.Rsp)
    buffer.extend(context_data)
    # Unknown
    buffer.extend(b'\x00' * 16)

    # Hope it works :D 
    buffer.extend(struct.pack("<QIIQQQQQQ", 0, 4, 8, 0, 0, 0, 0, 0, 0))
    buffer_bytes = bytes(buffer)
    mu.mem_write(csp,buffer_bytes)
    return csp # this stack pointer will be used as RSP

def dump_exception_record_to_bytes(exception_record):
    # Convert the structure to a byte string
    return ctypes.string_at(ctypes.addressof(exception_record), ctypes.sizeof(exception_record))

def parse_stack_bytes(stack_bytes):
    context = CONTEXT()
    context_ex = CONTEXT_EX()
    exception_record = EXCEPTION_RECORD()

    # Load CONTEXT
    ctypes.memmove(ctypes.addressof(context), stack_bytes[0:0x4D0], ctypes.sizeof(CONTEXT))
    
    # Load CONTEXT_EX
    ctypes.memmove(ctypes.addressof(context_ex), stack_bytes[0x4D0:0x4D0 + 0x18], ctypes.sizeof(CONTEXT_EX))
    print(stack_bytes[0x4D0:0x4D0 + 0x18])

    # Load EXCEPTION_RECORD
    ctypes.memmove(ctypes.addressof(exception_record), stack_bytes[0x4F0:0x4F0 + 0x98], ctypes.sizeof(EXCEPTION_RECORD))
    
    return context, context_ex, exception_record

BASE_ADDRESS = 0x140000000  # 16MB base address for code
STACK_ADDRESS = 0x66A0000  # Stack base address
STACK_SIZE = 0x300000    # Stack size
SHELL_CODE_ADDRESS = 0x06A30000 
MY_CONTEXT_ADDR = 0x1408A6A30 # I used a pointer from main exe as CONTEXT

def disassemble(code, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
    for i in cs.disasm(code, addr):
        return i

def print_registers(mu):
    print(f"rip={mu.reg_read(UC_X86_REG_RIP):X} rax ={mu.reg_read(UC_X86_REG_RAX):X} rbx={mu.reg_read(UC_X86_REG_RBX):X} rcx: {mu.reg_read(UC_X86_REG_RCX):X} rdx={mu.reg_read(UC_X86_REG_RDX):X} rbp={mu.reg_read(UC_X86_REG_RBP):X}  rsp={mu.reg_read(UC_X86_REG_RSP):X} rsi={mu.reg_read(UC_X86_REG_RSI):X} rdi={mu.reg_read(UC_X86_REG_RDI):X} r8={mu.reg_read(UC_X86_REG_R8):X} r9={mu.reg_read(UC_X86_REG_R9):X} r10={mu.reg_read(UC_X86_REG_R10):X} r11={mu.reg_read(UC_X86_REG_R11):X} r12={mu.reg_read(UC_X86_REG_R12):X} r13={mu.reg_read(UC_X86_REG_R13):X} r14={mu.reg_read(UC_X86_REG_R14):X} r15={mu.reg_read(UC_X86_REG_R15):X}" )

def fix_context(mu:Uc,info,user_data):
    fix_stack(mu,info)    
    new_addr = info['exception_handler_rva'] + SHELL_CODE_ADDRESS

    context = create_context(mu)
    context_bytes = ctypes.string_at(ctypes.addressof(context), ctypes.sizeof(context))

    mu.reg_write(UC_X86_REG_RIP,new_addr)    
    mu.mem_write(MY_CONTEXT_ADDR,context_bytes)
    mu.reg_write(UC_X86_REG_R9,0x14001F560);

def find_unwind(mu:Uc,next_byte):
    piVar1 = [0] * 3
    param_1_address = mu.reg_read(UC_X86_REG_RIP)

    piVar1[0] = param_1_address - SHELL_CODE_ADDRESS 
    piVar1[1] = piVar1[0] + 1
    piVar1[2] = piVar1[1] + 1 + next_byte
    local_28 = (piVar1[2] & 1) != 0  
    
    if local_28:
        piVar1[2] += 1
    return piVar1


CONTEXT_REGISTERS = {
    0x34: "MxCsr",
    0x78: "Rax", 0x80: "Rcx", 0x88: "Rdx", 0x90: "Rbx",
    0x98: "Rsp", 0xA0: "Rbp", 0xA8: "Rsi", 0xB0: "Rdi",
    0xB8: "R8",  0xC0: "R9",  0xC8: "R10", 0xD0: "R11",
    0xD8: "R12", 0xE0: "R13", 0xE8: "R14", 0xF0: "R15",
    0xF8: "Rip"
}

def find_offset(register_name):
    for offset, name in CONTEXT_REGISTERS.items():
        if name.lower() == register_name.lower():
            return offset  # Return the offset as a hex string
    return None

Unicorn_Registers = [
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RBX,
    UC_X86_REG_RSP,
    UC_X86_REG_RBP,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_RAX
]

def fix_stack(mu:Uc,info):
    stack_info = []
    src_reg = info['frame_register']
    reg_name = Registers[src_reg]

    if src_reg > 0:
        stack_info.append(f';src {reg_name}')
    for code in info['unwind_text']:
        unwind_code = code.split(' ')
        if 'UWOP_SET_FPREG' in code:
            stack_info.append('; fixing UWOP_SET_FPREG address based?')
            # FP = RSP + UNWIND_INFO.FPRegOffset*16
        elif 'UWOP_PUSH_MACHFRAME' in code:
            alloc_type = unwind_code[1]
            current_rsp = mu.reg_read(UC_X86_REG_RSP)
            if alloc_type == '1':
                stack_info.append('add rsp, 20h')
            else:
                stack_info.append('add rsp, 18h')
            stack_info.append(f'mov rax, qword ptr[rsp]')
        
            # Unicorn
            displacement = 0x20 if alloc_type == '1' else 0x18
            mu.reg_write(UC_X86_REG_RSP,current_rsp+displacement)
            stack_value = mu.mem_read(current_rsp+displacement,8)
            rax_value = int.from_bytes(stack_value, byteorder='little')
            mu.reg_write(UC_X86_REG_RAX,rax_value)

        elif 'UWOP_ALLOC_LARGE' in code:
            alloc_type = unwind_code[1]
            alloc_size = int(unwind_code[2],16)
            if alloc_type == '1':
                stack_info.append(f'add {reg_name.lower()}, 0{alloc_size}; ; MINE INFO 1')
            else:
                stack_info.append(f"add {reg_name.lower()}, 0{8*alloc_size};; MINE INFO 0")
            
            # Unicorn
            displacement = alloc_size if alloc_type == '1' else 8 * alloc_size
            unicorn_reg = Unicorn_Registers[src_reg]
            original_val = mu.reg_read(unicorn_reg)
            mu.reg_write(unicorn_reg,original_val+displacement)

        elif 'UWOP_ALLOC_SMALL' in code:
            alloc_size = int(unwind_code[1],16)

            # Unicorn
            unicorn_reg = Unicorn_Registers[src_reg]
            original_val = mu.reg_read(unicorn_reg)
            amount = original_val + (8 + 8*alloc_size)
            mu.reg_write(unicorn_reg,amount)

            stack_info.append(f"add {reg_name.lower()}, 0{8+8*alloc_size};; MINE INFO 0")
        elif 'UWOP_PUSH_NONVOL' in code:
            dest_register = unwind_code[2]
            offset_val = find_offset(dest_register)
            stack_info.append(f'mov qword ptr {dest_register.lower()}, [{reg_name.lower()}]; MINEY {src_reg}')
            stack_info.append(f'mov qword ptr [context+{offset_val}], {dest_register.lower()}; MINEZ')
           
            # Unicorn 
            src_reg_obj = get_register(reg_name)
            dest_reg_obj = get_register(dest_register)
            unicorn_dest_reg = dest_reg_obj.unicorn_id
            unicorn_src_reg = src_reg_obj.unicorn_id

            src_val = mu.reg_read(unicorn_src_reg)
            stack_value = mu.mem_read(src_val,8)
            rax_value = int.from_bytes(stack_value, byteorder='little')
            mu.reg_write(unicorn_dest_reg,rax_value)
            mu.mem_write(MY_CONTEXT_ADDR,bytes(stack_value))
    return stack_info        

def hook_invalid(mu:Uc, user_data):
    current_pc = mu.reg_read(UC_X86_REG_RIP)

    next_byte = mu.mem_read(current_pc+1,1)[0]
    runtime_addr = find_unwind(mu,next_byte)
    info = runtime_addr[2]
    parsed = extract_unwind_info(user_data[info:info+200])
    fix_context(mu,parsed,user_data)
    return True

traced_numbers = []
traced_addresses = []


def fix_jump(mu:Uc):
    current_eflags = mu.reg_read(UC_X86_REG_EFLAGS)

# Set the Zero Flag (bit 6) in the EFLAGS register
    zero_flag = 1 << 6  # This is the bit position for ZF in the EFLAGS register
    new_eflags = current_eflags | zero_flag
    mu.reg_write(UC_X86_REG_EFLAGS, new_eflags)

szSerial = "asdljasdPASkasdlj9080lK213nBxZzH"
# szSerial = "A234B678C0abDdefEhijFlmnOpqrStux"
def get_pos_string(chr):
    global szSerial
    return szSerial.index(chr)

target_or_address = None
target_register = None
target_addresses = {}  # Dictionary to map target addresses to target registers and operations
trace_log = []
operations = []

def add_operation(operations_dict, new_operation):
    # Check if there are any existing operations
    # if operations_dict["operations"]:
    #     # Get the last operation in the list
    #     last_operation = operations_dict["operations"][-1]
    #     # Check if the last operation is "or"
    #     if last_operation["op"] == "or":
    #         # print("Skipping addition of new operation due to last operation being 'or'.")
    #         return  # Skip adding the new operation

    # If the check passes, add the new operation
    operations_dict["operations"].append(new_operation)


def find_table(mu:Uc,addr):

    registers =  [
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RBX,
        UC_X86_REG_RBP,
        UC_X86_REG_RSI,
        UC_X86_REG_RDI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
    ]

    bytes = []
    for reg in registers:
        reg_val = mu.reg_read(reg)
        for table in operation_tables:
            if (table['address'] == hex(reg_val)):
                bytes.append(hex(table['byte'])) 
    return bytes


def is_sub_with_displacement(mu: Uc, instruction):
    # Ensure there are exactly two operands
    if len(instruction.operands) != 2:
        return False

    # Define destination and source operands
    dest_op = instruction.operands[0]
    src_op = instruction.operands[1]

    # Case 1: sub <mem>, <reg> (e.g., sub qword ptr ss:[rbp+0xD8], r14)
    if dest_op.type == capstone.x86.X86_OP_MEM and src_op.type == capstone.x86.X86_OP_REG:
        # Get details of the destination memory operand
        base_reg = dest_op.mem.base
        index_reg = dest_op.mem.index
        displacement = dest_op.mem.disp
        
        # Get the source register ID
        src_register = instruction.reg_name(src_op.reg)
        src_reg_obj = get_register(src_register)
        unicorn_src_reg = src_reg_obj.unicorn_id

        # Resolve base and index values
        base_value = mu.reg_read(get_register(base_reg).unicorn_id) if base_reg else 0
        index_value = mu.reg_read(get_register(index_reg).unicorn_id) if index_reg else 0
        mem_address = base_value + index_value + displacement

        # Get values for the memory address and register
        mem_value = struct.unpack("<Q", mu.mem_read(mem_address, 8))[0]
        src_value = mu.reg_read(unicorn_src_reg)

        # Perform subtraction: memory - register
        calculated_value = mem_value - src_value
        return {
            'org': hex(mem_value), #big
            'amount': hex(src_value), #small
            'result': hex(calculated_value)
        }

    # Case 2: sub <reg>, <mem> (e.g., sub rdi, qword ptr ds:[rsi+0xF0])
    elif dest_op.type == capstone.x86.X86_OP_REG and src_op.type == capstone.x86.X86_OP_MEM:
        # Get details of the source memory operand
        base_reg = src_op.mem.base
        index_reg = src_op.mem.index
        displacement = src_op.mem.disp

        # Get the destination register ID
        dest_register = instruction.reg_name(dest_op.reg)
        dest_register_obj = get_register(dest_register)
        unicorn_dest_reg = dest_register_obj.unicorn_id

        # Resolve base and index values
        base_value = mu.reg_read(get_register(base_reg).unicorn_id) if base_reg else 0
        index_value = mu.reg_read(get_register(index_reg).unicorn_id) if index_reg else 0
        mem_address = base_value + index_value + displacement

        # Get values for the register and memory address
        dest_value = mu.reg_read(unicorn_dest_reg)
        mem_value = struct.unpack("<Q", mu.mem_read(mem_address, 8))[0]

        # Perform subtraction: register - memory
        calculated_value = dest_value - mem_value
        return {
            'org': hex(dest_value), #big
            'amount': hex(mem_value), #small
            'result': hex(calculated_value)
        }

    else:
        # If the operands do not match the expected types, return False
        return False

def is_add_with_displacement(mu:Uc,instruction):
    
    # Expect two operands: destination register and memory with base register + displacement
    if len(instruction.operands) != 2:
        return False

    # Check if the first operand (destination) is a register
    dest_op = instruction.operands[0]
    if dest_op.type != capstone.x86.X86_OP_REG:
        return False

    # Check if the second operand (source) is memory with a displacement
    src_op = instruction.operands[1]
    if src_op.type == capstone.x86.X86_OP_MEM:
        base_reg = src_op.mem.base
        dest_register = instruction.reg_name(instruction.operands[0].reg)
        displacement = src_op.mem.disp
        
        if base_reg != 0:
            src_reg_obj = get_register(base_reg)
            dest_register_obj = get_register(dest_register)

            unicorn_src_reg = src_reg_obj.unicorn_id
            unicorn_des_reg = dest_register_obj.unicorn_id

            reg_value = mu.reg_read(unicorn_src_reg)
            dest_value = mu.reg_read(unicorn_des_reg)

            mem_address = reg_value + displacement
            mem_value = struct.unpack("<Q", mu.mem_read(mem_address, 8))[0]
            calculated_value = mem_value + dest_value

            for table in operation_tables:
                table_address = int(table['address'],16)
                if table_address <= calculated_value < table_address + 256:
                    return {'byte': table['byte'], 'table':  table['address']}
            
        # Return True if there's a base register and a non-zero displacement
        return False

    return False

def analyze_instruction(mu, addr):
    if len(trace_log) == 0:
        return
                
    last_block = trace_log[len(trace_log)-1]
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    instruction = mu.mem_read(addr, 15)  # Read a max-length x86-64 instruction
    inst = next(cs.disasm(instruction, addr))
    
    # Detect `shl REG1, 0x18` and check for `or REG2, REG1` pattern
    if inst.mnemonic == "shl" and len(inst.operands) == 2:
        if inst.operands[1].type == capstone.x86.X86_OP_IMM and inst.operands[1].imm == 0x18:
            reg1 = inst.reg_name(inst.operands[0].reg)
            next_addr = addr + inst.size
            next_instruction = mu.mem_read(next_addr, 15)
            next_inst = next(cs.disasm(next_instruction, next_addr))
            
            if next_inst.mnemonic == "or" and len(next_inst.operands) == 2:
                if next_inst.operands[1].reg == inst.operands[0].reg:
                    # Calculate the result of `or` manually
                    reg1_val = mu.reg_read(eval(f"UC_X86_REG_{reg1.upper()}"))
                    reg2 = next_inst.reg_name(next_inst.operands[0].reg)
                    reg2_val = mu.reg_read(eval(f"UC_X86_REG_{reg2.upper()}"))
                    
                    # Apply the or operation as it would occur
                    result = (reg2_val & ~(0xFF << 24)) | ((reg1_val & 0xFF) << 24)
                    last_block['operations'].append({
                        "address": hex(next_addr),
                        "offset": hex(next_addr-SHELL_CODE_ADDRESS),
                        "op": "or",
                        # "reg1": reg1,
                        # "reg1_value": hex(reg1_val),
                        # "reg2": reg2,
                        # "initial_reg2_value": hex(reg2_val),
                        "result": hex(result),
                    })

    elif inst.mnemonic == "sub":
        val = is_sub_with_displacement(mu,inst)
        if val != False and val != None:
            operation = {
                'org':val['org'],
                'amount':val['amount'],
                'op': 'sub',
                'result':val['result']
            }
            add_operation(last_block,operation)


    elif inst.mnemonic == "add":
       val =  is_add_with_displacement(mu,inst)
       if val != False:
            operation = {
                        # "address": hex(addr),
                        # "offset": hex(addr-SHELL_CODE_ADDRESS),
                        'op': 'mov',
                        'table':val['table'],
                        'byte': hex(val['byte'])
            }
            add_operation(last_block,operation)

    # Detect `xor REG, qword ptr [MEMORY]`
    elif inst.mnemonic == "xor" and len(inst.operands) == 2:
        if inst.operands[1].type == capstone.x86.X86_OP_MEM:
            target_reg = inst.reg_name(inst.operands[0].reg)
            mem_base = inst.reg_name(inst.operands[1].mem.base)
            mem_disp = inst.operands[1].mem.disp
            
            # Get values from registers and memory
            target_reg_val = mu.reg_read(eval(f"UC_X86_REG_{target_reg.upper()}"))
            mem_base_val = mu.reg_read(eval(f"UC_X86_REG_{mem_base.upper()}"))
            mem_address = mem_base_val + mem_disp
            mem_value = struct.unpack("<Q", mu.mem_read(mem_address, 8))[0]
            
            # Calculate the result of the xor
            xor_result = target_reg_val ^ mem_value

            last_block['operations'].append({
                "op": "xor",
                "target_register": target_reg,
                "target_reg_value": hex(target_reg_val),
                "mem_address": mem_address,
                "mem_value": hex(mem_value),
                "result":  hex(xor_result),
            })

def find_shl_or_pattern_unicorn(mu:Uc,instruction, addr):
    global target_or_address, target_register
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True  # Enable detailed mode to access operands

    # Disassemble the current instruction
    inst = next(cs.disasm(instruction, addr))

    # Check for `shl REG, 0x18`
    if inst.mnemonic == "shl" and len(inst.operands) == 2:
        if inst.operands[1].type == capstone.x86.X86_OP_IMM and inst.operands[1].imm == 0x18:
            reg1_name = inst.reg_name(inst.operands[0].reg)

            # Read the next instruction to check if it's `or REG2, REG1`
            next_addr = addr + inst.size
            next_instruction = mu.mem_read(next_addr, 15)  # Read max 15 bytes for one x64 instruction
            next_inst = next(cs.disasm(next_instruction, next_addr))

            if next_inst.mnemonic == "or" and len(next_inst.operands) == 2:
                if next_inst.operands[1].reg == inst.operands[0].reg:  # REG1 in `or`
                    target_or_address = next_inst.address + next_inst.size
                    target_register = next_inst.reg_name(next_inst.operands[0].reg)  # REG2 in `or`
                    return True
    return False


def find_pattern_and_set_target(mu, instruction, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True  # Enable detailed mode for operands

    inst = next(cs.disasm(instruction, addr))

    # Check for `shl REG, 0x18` followed by `or REG2, REG1`
    if inst.mnemonic == "shl" and len(inst.operands) == 2:
        if inst.operands[1].type == capstone.x86.X86_OP_IMM and inst.operands[1].imm == 0x18:
            reg1_name = inst.reg_name(inst.operands[0].reg)
            next_addr = addr + inst.size
            next_instruction = mu.mem_read(next_addr, 15)
            next_inst = next(cs.disasm(next_instruction, next_addr))

            if next_inst.mnemonic == "or" and len(next_inst.operands) == 2:
                if next_inst.operands[1].reg == inst.operands[0].reg:
                    target_addresses[next_inst.address + next_inst.size] = {
                        "operation": "or",
                        "target_register": next_inst.reg_name(next_inst.operands[0].reg),
                    }
                    print(f"Set trace for `or` operation at 0x{next_inst.address + next_inst.size:x}")

    # Check for `xor REG, qword ptr [REG + offset]`
    elif inst.mnemonic == "xor" and len(inst.operands) == 2:
        if inst.operands[1].type == capstone.x86.X86_OP_MEM:
            reg_name = inst.reg_name(inst.operands[0].reg)
            target_addresses[inst.address + inst.size] = {
                "operation": "xor",
                "target_register": reg_name,
                "memory_base": inst.reg_name(inst.operands[1].mem.base),
                "memory_disp": inst.operands[1].mem.disp,
            }
            print(f"Set trace for `xor` operation at 0x{inst.address + inst.size:x}")


def hook_code(mu:Uc, address, size, user_data):
    instruction = mu.mem_read(address, size)
    global operations

    if instruction[0] == 0xF4:
        hook_invalid(mu,user_data)

    insn = disassemble(instruction, address)
    if insn.mnemonic == 'mul':
        rax = mu.reg_read(UC_X86_REG_RAX)
        rsp = mu.reg_read(UC_X86_REG_RSP)
        stack_value = mu.mem_read(rsp,8)
        index_val = get_pos_string(chr(rax))
        rsp_value = int.from_bytes(stack_value, byteorder='little')
        trace_log.append({
            'hex': hex(rax),         # Store directly as a string
            'chr': chr(rax),
            'index': index_val,
            'acc' : hex(rsp_value * rax),
            'multiplier': hex(rsp_value),
            'operations': [],

        })

    else:
        analyze_instruction(mu,address)
    
    if insn.mnemonic == 'test':
        print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic,insn.op_str))
        print_registers(mu)
    if insn.mnemonic == 'cmovne':
        fix_jump(mu)

def emulate(binary:str,shellcode:str):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(SHELL_CODE_ADDRESS, 0x800000)  # 8MB for shell code.
    mu.mem_map(STACK_ADDRESS, STACK_SIZE)  # 20MB of stack space

    map_file(mu,binary,BASE_ADDRESS)
    data = load_file(shellcode)
    mu.mem_write(SHELL_CODE_ADDRESS, data)
    mu.hook_add(UC_HOOK_CODE,hook_code,user_data=data)

    rbp = 0x00000000067FF5B0
    rsp = 0x00000000067FF070  # Leave space for the stack frame

    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rbp)
    mu.reg_write(UC_X86_REG_RIP, 0x140001642) # before call
    byte_data = SHELL_CODE_ADDRESS.to_bytes(4, byteorder='little')
    mu.mem_write(0x14089B8E0,byte_data)

    global szSerial                            
    mu.mem_write(0x14089B8E8,  bytes(szSerial,'utf8'))

    mu.reg_write(UC_X86_REG_RCX, 0x14089B8E8) # 
    
    try:
        mu.emu_start(0x140001642, 0x1400011f0)
        print(json.dumps(trace_log))
        print_registers(mu)
    except UcError as e:
        with open('trace.json', 'w') as f: # it is expected to crash. because we finally do API call
            json.dump(trace_log, f, indent=4)
        print(f"Emulation error: {e}")

binary = "serpentine.exe"
shellcode = "obfuscated_code.txt"
emulate(binary,shellcode)

