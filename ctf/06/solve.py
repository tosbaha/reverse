from ctypes import (windll, wintypes, c_uint64, cast, POINTER, Union, c_ubyte,
                    LittleEndianStructure, byref, c_size_t)
import zlib
import json
import struct

# types and flags
DELTA_FLAG_TYPE             = c_uint64
DELTA_FLAG_NONE             = 0x00000000
DELTA_APPLY_FLAG_ALLOW_PA19 = 0x00000001

# structures
class DELTA_INPUT(LittleEndianStructure):
    class U1(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID),
                    ('lpStart', wintypes.LPVOID)]
    _anonymous_ = ('u1',)
    _fields_ = [('u1', U1),
                ('uSize', c_size_t),
                ('Editable', wintypes.BOOL)]


class DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID),
                ('uSize', c_size_t)]


# functions
ApplyDeltaB = windll.msdelta.ApplyDeltaB
ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT,
                        POINTER(DELTA_OUTPUT)]
ApplyDeltaB.rettype = wintypes.BOOL
DeltaFree = windll.msdelta.DeltaFree
DeltaFree.argtypes = [wintypes.LPVOID]
DeltaFree.rettype = wintypes.BOOL

#xor the traffic
def xor(data):
    key = bytearray('meoow','utf-8')
    l = len(key)
    result =  bytearray((
        (data[i] ^ key[i % l]) for i in range(0,len(data))
    ))
    return result

def apply_patchfile_to_file(inbuf, patch_contents):
    buf = cast(bytes(inbuf), wintypes.LPVOID)
    buflen = len(inbuf)
    # some patches (Windows Update MSU) come with a CRC32 prepended to the file
    # if the file doesn't start with the signature (PA) then check it
    if patch_contents[:2] != b"PA":
        paoff = patch_contents.find(b"PA")
        if paoff != 4:
            raise Exception("Patch is invalid")
        crc = int.from_bytes(patch_contents[:4], 'little')
        patch_contents = patch_contents[4:]
        if zlib.crc32(patch_contents) != crc:
            raise Exception("CRC32 check failed. Patch corrupted or invalid")

    applyflags = DELTA_FLAG_NONE
    dd = DELTA_INPUT()
    ds = DELTA_INPUT()
    dout = DELTA_OUTPUT()

    ds.lpcStart = buf
    ds.uSize = buflen
    ds.Editable = False
    dd.lpcStart = cast(patch_contents, wintypes.LPVOID)
    dd.uSize = len(patch_contents)
    dd.Editable = False
    status = ApplyDeltaB(applyflags, ds, dd, byref(dout))
    if status == 0:
        raise Exception("Patch failed")
    buf = dout.lpStart
    n = dout.uSize
    outbuf = bytes((c_ubyte*n).from_address(buf))
    DeltaFree(buf)
    return outbuf

with open('dump.json') as r:
    packets = json.load(r)
    for packet in packets:
        layers = packet['_source']['layers']
        if 'data_raw' in layers:
            raw_bytes =  layers['data_raw'][0]
            data_bytes = bytes.fromhex(raw_bytes)
            patch_bytes = data_bytes[12:]
            empty_bytes = bytearray(4096)
            patched_bytes = apply_patchfile_to_file(empty_bytes,patch_bytes)
            xored_bytes = xor(patched_bytes)
            search = xored_bytes.find(bytes('@flare-on.com','utf-8'))
            if (search != -1):
                result = xored_bytes[search-50:search+50].decode('utf-8')
                print(result)
                break
