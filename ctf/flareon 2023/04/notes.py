# 0000000062F42210 | 31D2                     | xor edx,edx                             |
# 0000000062F42212 | 4D:89F0                  | mov r8,r14                              | r14:"sihost.exe"
# 0000000062F42215 | C1CA 0D                  | ror edx,D                               |
# 0000000062F42218 | 49:83C0 01               | add r8,1                                |
# 0000000062F4221C | 89D1                     | mov ecx,edx                             |
# 0000000062F4221E | 0FBED0                   | movsx edx,al                            |
# 0000000062F42221 | 41:0FB600                | movzx eax,byte ptr ds:[r8]              |
# 0000000062F42225 | 31CA                     | xor edx,ecx                             |
# 0000000062F42227 | 84C0                     | test al,al                              |
# 0000000062F42229 | 75 EA                    | jne aimbot2.62F42215                    |
# 0000000062F4222B | 31C0                     | xor eax,eax                             |
# 0000000062F4222D | EB 0F                    | jmp aimbot2.62F4223E                    |

import struct

def process_string(input_string):
    edx = 0
    index = 0
    eax = ord(input_string[0])
    while index < len(input_string):
        edx = ROR(edx,0xD)
        ecx = edx
        edx = eax
        index += 1
        if index < len(input_string):
            eax = ord(input_string[index])
        edx = edx ^ ecx
        #print("Step %d %x" % (index,edx))
    return edx


def ROL(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)
    

def ROR(data, shift, size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)



table1 = b'\xc1\x8c\xed\x14\x93\xd7\xb6\x55\x9b\xcf\xb7\x54\x87\xc8\xb7\x55\x93\xcd\xae\x57\x9b\xc0\xb6\x56\x86\x8b\xec\x09\xc4\x99\xeb\x1d\xa9\xfb\x9a\x67\x00'
table2 = b'\xcb\x99\xf7\x05\xc7\x99\xfb\x0b\xdd\xd8\xac\x54\x99\xc8\x99\x65\x00'
table3 = b'\x8b\x8e\xfc\x16\xda\x91\xf6\x0a\x8b\xc2\xb9\x46\xa9\xfb\x9a\x67\x00\x00'
table4 = b'\xdd\x90\xfc\x44\xcd\x9d\xfa\x16\xd0\x88\xed\x0d\xc6\x96\xb9\x0b\xcf\xd8\xed\x0c\xc0\x8b\xb9\x06\xc5\x97\xfb\x44\xde\x99\xea\x44\xda\x8d\xfa\x07\xcc\x8b\xea\x02\xdc\x94\x99\x65'

tables = [
    table1,
    table2,
    table3,
    table4
]


def xor_dwords_with_seed(index, len,seed):

    src = tables[index]
    result = bytearray()

    for i in range(0, len, 4):
        dword = struct.unpack('<I', src[i:i+4])[0]  # Extract a double-word (4 bytes) from the source
        xor_result = dword ^ seed
        result.extend(struct.pack('<I', xor_result))

    return result    

# 00000060EB8FF0C0  22 76 65 72 73 69 6F 6E 22 3A 20 22 36 2E 32 30  "version": "6.20  

result = xor_dwords_with_seed(0,0x24,0x6499F8A9) # http://127.0.0.1:57328/2/summary
print(result)
result = xor_dwords_with_seed(1,0x10,0x6499F8A9) # bananabot 5000
print(result)
result = xor_dwords_with_seed(2,0x10,0x6499F8A9) # "version": 
print(result)
result = xor_dwords_with_seed(3,0x2c,0x6499F8A9) # the decryption of this blob was successful 
print(result)


# result = xor_dwords_with_seed(table2,0x10,0x6499F8A9)
# print(result)

# 000002B4956F002A | 48:83C4 08               | add rsp,8                               |
# 000002B4956F002E | 48:83E4 F0               | and rsp,FFFFFFFFFFFFFFF0                |
# 000002B4956F0032 | 48:83EC 08               | sub rsp,8                               |
# 000002B4956F0036 | 48:8BEC                  | mov rbp,rsp                             |
# 000002B4956F0039 | 48:8D6424 E8             | lea rsp,qword ptr ss:[rsp-18]           |
# 000002B4956F003E | 48:8D05 1B080000         | lea rax,qword ptr ds:[2B4956F0860]      |
# 000002B4956F0045 | 48:8945 E8               | mov qword ptr ss:[rbp-18],rax           |
# 000002B4956F0049 | 48:8D05 48080000         | lea rax,qword ptr ds:[2B4956F0898]      |
# 000002B4956F0050 | 48:8945 F0               | mov qword ptr ss:[rbp-10],rax           |
# 000002B4956F0054 | 6A 00                    | push 0                                  |
# 000002B4956F0056 | 8F45 F8                  | pop qword ptr ss:[rbp-8]                |
# 000002B4956F0059 | 48:8D05 48080000         | lea rax,qword ptr ds:[2B4956F08A8]      |




# Usage
# 000000006855AF94 # x64dbg.exe
# 000000003755DCD4
# 00000000B2C6B4E9 # explorer.exe
# 00000000F255062F # ollydbg.exe
# 000000005E620917
# 00000000374755BE
# 000000A42CE7E160
# 00000000843E42CC
# 000000003A083D2B
# 

r14 = "sauerbraten.exe"  # sauerbraten.exe 1c5e2e7b  # miner.exe b37f3437  aimbot.exe # b74c5cb2
result = process_string(r14)
print("%x" % result)
