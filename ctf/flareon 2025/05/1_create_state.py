import argparse
import json
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
import pefile

def va_to_offset(pe, va, image_base=None):
    if image_base is None:
        image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    try:
        return pe.get_offset_from_rva(rva)
    except Exception as e:
        raise ValueError(f"VA {hex(va)} -> invalid RVA {hex(rva)}: {e}")

def find_section_containing_va(pe, va):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    for s in pe.sections:
        start = s.VirtualAddress
        end = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if start <= rva < end:
            return s
    return None

def read_dd_table(pe, jpt_va, max_cases=None):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    sec = find_section_containing_va(pe, jpt_va)
    if not sec:
        raise ValueError(f"jpt VA {hex(jpt_va)} not inside any section")
    sec_file_start = sec.PointerToRawData
    sec_file_end = sec.PointerToRawData + max(sec.SizeOfRawData, sec.Misc_VirtualSize)
    jpt_off = va_to_offset(pe, jpt_va, image_base)
    available = sec_file_end - jpt_off
    if available <= 0:
        raise ValueError("No room for table entries in section")
    max_entries_by_section = available // 4
    if max_cases is None:
        count = max_entries_by_section
    else:
        count = min(max_cases, max_entries_by_section)
    entries = []
    data = pe.__data__[jpt_off:jpt_off + count*4]
    for i in range(count):
        v = struct.unpack_from('<I', data, i*4)[0]
        target_va = image_base + v    
        entries.append((i, v, target_va))
    return entries

def disasm_bytes(pe, va, max_bytes=4096):
    try:
        off = va_to_offset(pe, va)
    except Exception:
        return []
    sec = find_section_containing_va(pe, va)
    if sec:
        sec_file_end = sec.PointerToRawData + max(sec.SizeOfRawData, sec.Misc_VirtualSize)
        max_b = sec_file_end - off
        max_b = max(16, min(max_b, max_bytes))
    else:
        max_b = max_bytes
    data = pe.__data__[off:off+max_b]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(data, va))
    return insns

def find_state(pe,case_va):
    print(f"Case {case_va:08X}")
    handler_insns = disasm_bytes(pe, case_va, max_bytes=256)
    next_state = None
    handler_addr = None

    for h in handler_insns[:12]:
        if h.mnemonic.lower() == 'mov' and len(h.operands) >= 2:
            op0 = h.operands[0]
            op1 = h.operands[1]
            if op0.type == x86_const.X86_OP_MEM and op1.type == x86_const.X86_OP_IMM:
                imm_state = op1.imm
                next_state = imm_state
                handler_addr = h.address
                break
    return (next_state,handler_addr)

def get_imm_from_operand(op):
    # returns immediate if operand is imm
    try:
        if op.type == x86_const.X86_OP_IMM:
            return op.imm
    except Exception:
        pass
    return None

def analyze_case(pe,case_va,max_bytes=200):
    print(f"Analyzing case 0x{case_va:08X}")
    matches = []
    insns = disasm_bytes(pe, case_va, max_bytes)
    # 0F B6 44 24 30  movzx   eax, [rsp+59398h+var_59368]
    for i, ins in enumerate(insns):
        if ins.mnemonic.lower() == 'cmp' and  len(ins.operands) >= 2:
            # print(ins)
            # print(ins.disp)
            # print(ins.disp_offset)
            next_ins = insns[i+1]
            if next_ins.mnemonic.lower() == 'jz' or next_ins.mnemonic.lower() == 'je':
                imm = get_imm_from_operand(ins.operands[1])
                # print(next_ins)
                # print(next_ins.op_str.strip())
                result = find_state(pe,int(next_ins.op_str.strip(),16))
                matches.append(
                    {
                    'mod': result[0],
                    'addr': result[1],
                    'val': chr(imm)
                }
                )
    print(matches)

def parse_case(pe, case_va, stop_va, max_insts=100, handler_follow_jmp=True):
    matches = []
    insns = disasm_bytes(pe, case_va, max_bytes=4096)
    addr_to_insn = {ins.address: ins for ins in insns}
    count = 0
    for i, ins in enumerate(insns):
        count += 1
        if count > max_insts:
            break
        if ins.mnemonic.lower() == 'jmp':
            # try to extract immediate jmp target
            tgt = None
            try:
                if ins.operands and ins.operands[0].type == x86_const.X86_OP_IMM:
                    tgt = ins.operands[0].imm
            except Exception:
                try:
                    op = ins.op_str.strip()
                    if op.startswith('0x') or op.startswith('0X'):
                        tgt = int(op, 16)
                except:
                    tgt = None
            if tgt == stop_va:
                break
        # look for cmp imm then jz next
        if ins.mnemonic.lower() == 'cmp':

            imm = None
            try:
                if len(ins.operands) >= 2:
                    imm = get_imm_from_operand(ins.operands[1])
            except Exception:
                imm = None
            if imm is None:
                continue

            if i+1 < len(insns):
                next_ins = insns[i+1]
                if next_ins.mnemonic.lower() in ('je','jz','jne','jnz'):
                    # capture jz target
                    jz_tgt = None
                    try:
                        if next_ins.operands and next_ins.operands[0].type == x86_const.X86_OP_IMM:
                            jz_tgt = next_ins.operands[0].imm
                    except Exception:
                        try:
                            op = next_ins.op_str.strip()
                            if op.startswith('0x') or op.startswith('0X'):
                                jz_tgt = int(op,16)
                        except:
                            jz_tgt = None
                    if jz_tgt is None:
                        continue
                    # disasm at jz_tgt a small window to find mov [mem], imm
                    handler_insns = disasm_bytes(pe, jz_tgt, max_bytes=256)
                    next_state = None
                    handler_addr = None
                    for h in handler_insns[:12]:
                        # look for "mov [mem], imm"
                        if h.mnemonic.lower() == 'mov' and len(h.operands) >= 2:
                            op0 = h.operands[0]
                            op1 = h.operands[1]
                            # destination is memory?
                            try:
                                if op0.type == x86_const.X86_OP_MEM and op1.type == x86_const.X86_OP_IMM:
                                    imm_state = op1.imm
                                    next_state = imm_state
                                    handler_addr = h.address
                                    break
                            except Exception:
                                pass

                        if h.mnemonic.lower() == 'jmp' and handler_follow_jmp:
                            # try follow one-level jmp
                            jmp_t = None
                            try:
                                if h.operands and h.operands[0].type == x86_const.X86_OP_IMM:
                                    jmp_t = h.operands[0].imm
                            except Exception:
                                try:
                                    op = h.op_str.strip()
                                    if op.startswith('0x') or op.startswith('0X'):
                                        jmp_t = int(op,16)
                                except:
                                    jmp_t = None
                            if jmp_t:
                                # disasm shallow at jmp_t
                                handler2 = disasm_bytes(pe, jmp_t, max_bytes=256)
                                for h2 in handler2[:12]:
                                    if h2.mnemonic.lower() == 'mov' and len(h2.operands) >= 2:
                                        try:
                                            if h2.operands[0].type == x86_const.X86_OP_MEM and h2.operands[1].type == x86_const.X86_OP_IMM:
                                                imm_state = h2.operands[1].imm
                                                next_state = imm_state
                                                handler_addr = h2.address
                                                break
                                        except Exception:
                                            pass
                                if next_state is not None:
                                    break
                    if next_state is not None:
                        # store found mapping: at this case, if input char == imm, next_state = next_state
                        matches.append({
                            "cmp_addr": hex(ins.address),
                            "cmp_imm": imm,
                            "jz_target": hex(jz_tgt),
                            "handler_addr": hex(handler_addr) if handler_addr else None,
                            "next_state": next_state
                        })
    return matches

def main():
    parser = argparse.ArgumentParser(description="Dump switch/jump-table cases using capstone + pefile.")
    parser.add_argument("binary", help="PE file")
    args = parser.parse_args()

    pe = pefile.PE(args.binary, fast_load=True)
    jpt_va = 0x140C687B8
    stop_va = 0x140CC122C
    pe.full_load()
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"[+] ImageBase = {hex(image_base)}")
    print(f"[+] Reading jump-table at VA {hex(jpt_va)} (stop jmp target {hex(stop_va)})")
    size = 65535
    entries = read_dd_table(pe,jpt_va,size)

    final = []
    for i,entry in enumerate(entries):
        #analyze_case(pe,entry[2])
        result = parse_case(pe,entry[2],0x140C685EE,200)
        final.append({"case": entry, "pos":result})
    
    with open("state.json", "w") as f:
        json.dump(final, f, indent=2)



    # analyze_case(pe,entry[2])


    # analyze_patterns()

    #print(entries)
    # 0x140860241
    # 0x140860241
    # .text:0000000140C91750
    # .text:0000000140C91750                 dd offset loc_1400AC5CB - 140000000h, offset loc_1407134F0 - 140000000h
#0140C69750



main()
