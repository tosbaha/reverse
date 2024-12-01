def load_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

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
