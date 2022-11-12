png_header = bytearray([0x89,0x50,0x4E,0x47, 0x0D, 0x0A, 0x1A, 0x0A])
encrypted =  bytearray([0xC7,0xC7,0x25,0x1D,0x63,0x0D,0xF3,0x56])

def ROR(data, shift, size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)
result = ''
for i in range(len(png_header)):
    key = png_header[i]
    key += i % 0xFF
    key = ROR(key,i) % 0xFF
    key = key ^ encrypted[i]
    result += chr(key)
print(result)
