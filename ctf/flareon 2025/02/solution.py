from arc4 import ARC4

def derive_key_from_signature(u: bytes) -> bytes:
    return bytes(u[i] ^ ((i + 42) & 0xFF) for i in range(len(u)))

def arc4_decipher(key: bytes, ciphertext: bytes) -> bytes:
    cipher = ARC4(key)
    return cipher.decrypt(ciphertext)

LEAD_RESEARCHER_SIGNATURE = b"m\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS"
KEY = derive_key_from_signature(LEAD_RESEARCHER_SIGNATURE)
print("Key:", KEY.decode('utf-8'))

ENCRYPTED_CHIMERA_FORMULA = (
    b"r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2"
    b"\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90"
)
decrypted_formula = arc4_decipher(KEY, ENCRYPTED_CHIMERA_FORMULA)
print("Decrypted Chimera Formula:", decrypted_formula.decode())
