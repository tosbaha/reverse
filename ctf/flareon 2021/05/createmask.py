from os import write
from unicorn import *
from unicorn.x86_const import *

mask_table = bytearray()

def code_hook(emu, address, size, user_data):
    if (address == 0x40194D): # if the hook address 0040194d XOR ESI,ECX, note cl
        ecx = emu.reg_read(UC_X86_REG_CL)
        mask_table.append(ecx)
    return

mu = Uc(UC_ARCH_X86,UC_MODE_64)
BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024
start_addr = 0x401707 # start of encrypt
end_addr = 0x0401964 # end of encrypt

source = '0234567890' # dummy string to test the algorithm
source_addr = 0x555555756000
mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.mem_write(BASE,open('./zyppe', 'rb').read()) #open our file
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1) #create the stack

mu.mem_map(source_addr, 0x1000, 0o3) #set the permisson for read and write
mu.mem_write(source_addr, bytes(source,'utf-8')) #read it
mu.reg_write(UC_X86_REG_RDI, source_addr) #point register to source address
mu.reg_write(UC_X86_REG_RAX, source_addr)
mu.hook_add(UC_HOOK_CODE, code_hook) # add breakpoint for every step

mu.emu_start(start_addr, end_addr) 
final = ''.join('0x{:02x}, '.format(x) for x in mask_table)
print(final)

f = open('./mask.bin', "wb")
f.write(mask_table)
f.close()
