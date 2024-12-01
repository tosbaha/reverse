import base64

def decode_xor(encoded, key):
    decoded = base64.b64decode(encoded)
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(decoded)])

encoded_string = 'cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=='
key = b"FlareOn2024"
result = decode_xor(encoded_string, key)
print(result.decode('utf-8'))
