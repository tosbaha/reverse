from ctypes import alignment
from re import M
import sys
import dnfile
import hashlib
from pefile import PE, DIRECTORY_ENTRY, PEFormatError
import json


filepath = sys.argv[1]

pe = dnfile.dnPE(filepath)
typedefs = pe.net.mdtables.TypeDef

result = {}

for element in typedefs:
    for method in element.MethodList:
        rva = method.row.Rva
        offset = pe.get_offset_from_rva(rva)
        header = pe.get_data(rva,12)
        print(header.hex())
        flags = header[0]
        
        if ( flags & 0x3 == 2): # tiny header
            size = flags  >> 2 & 0x3f
            headerSize = 1
            codeStart = offset + headerSize
            #aligned = size + headerSize
        else: #fat header
            flags |= header[1] << 8
            headerSize = 4 * (flags >> 12 & 0xf)
            flags = flags & 0xfff
            size = PE.get_dword_from_offset(pe,offset+4)
            codeStart = offset + headerSize
            #alligned = (( (headerSize + size) // 4) + 1) * 4
        result[method.row.Name] = {
            "rva": rva,
            "offset":offset,
            "size": size,
            "header":headerSize,
            "codestart":codeStart
        }
        print("Name: %s RVA %02x Offset: %02x Size: %02x Header %02x Code Start %02x" % (method.row.Name,rva, offset, size,headerSize,codeStart))
        
    print("=============")

# convert into JSON:
y = json.dumps(result)
print(y)
