from Crypto.Cipher import ChaCha20
import base64

def decrypt_chacha20(cipher,ciphertext, key, nonce):
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text

if __name__ == "__main__":
    key =  bytes.fromhex("B48F8FA4C856D496ACDECD16D9C94CC6B01AA1C0065B023BE97AFDD12156F3DC")
    nonce = bytes.fromhex("3FD480978485D818")
    cipher = ChaCha20.new(key=key, nonce=nonce)

    packets = [
        bytes.fromhex("f2 72 d5 4c 31 86 0f"),
        bytes.fromhex("3f bd 43 da 3e e3 25"),
        bytes.fromhex("86 df d7"),
        bytes.fromhex("c5 0c ea 1c 4a a0 64 c3 5a 7f 6e 3a b0 25 84 41 ac 15 85 c3 62 56 de a8 3c ac 93 00 7a 0c 3a 29 86 4f 8e 28 5f fa 79 c8 eb 43 97 6d 5b 58 7f 8f 35 e6 99 54 71 16"),
        bytes.fromhex("fc b1 d2 cd bb a9 79 c9 89 99 8c"),
        bytes.fromhex("61 49 0b"),
        bytes.fromhex("ce 39 da"),
        bytes.fromhex("57 70 11 e0 d7 6e c8 eb  0b 82 59 33 1d ef 13 ee 6d 86 72 3e ac 9f 04 28  92 4e e7 f8 41 1d 4c 70 1b 4d 9e 2b 37 93 f6 11  7d d3 0d ac ba"),
        bytes.fromhex("2c ae 60 0b 5f 32 ce a1 93 e0 de 63 d7 09 83 8b d6"), 
        bytes.fromhex("a7 fd 35"),
        bytes.fromhex("ed f0 fc"),
        bytes.fromhex("80 2b 15 18 6c 7a 1b 1a  47 5d af 94 ae 40 f6 bb 81 af ce dc 4a fb 15 8a  51 28 c2 8c 91 cd 7a 88 57 d1 2a 66 1a ca ec"),
        bytes.fromhex("ae c8 d2 7a 7c f2 6a 17 27 36 85"),
        bytes.fromhex("35 a4 4e"),
        bytes.fromhex("2f 39 17"),
        bytes.fromhex("ed 09 44 7d ed 79 72 19  c9 66 ef 3d d5 70 5a 3c 32 bd b1 71 0a e3 b8 7f  e6 66 69 e0 b4 64 6f c4 16 c3 99 c3 a4 fe 1e dc  0a 3e c5 82 7b 84 db 5a 79 b8 16 34 e7 c3 af e5  28 a4 da 15 45 7b 63 78 15 37 3d 4e dc ac 21 59  d0 56"),
        bytes.fromhex("f5 98 1f 71 c7 ea 1b 5d 8b 1e 5f 06 fc 83 b1 de f3 8c 6f 4e 69 4e 37 06 41 2e ab f5 4e 3b 6f 4d 19 e8 ef 46 b0 4e 39 9f 2c 8e ce 84 17 fa"),
        bytes.fromhex("40 08 bc"),
        bytes.fromhex("54 e4 1e"),
        bytes.fromhex("f7 01 fe e7 4e 80 e8 df  b5 4b 48 7f 9b 2e 3a 27 7f a2 89 cf 6c b8 df 98  6c dd 38 7e 34 2a c9 f5 28 6d a1 1c a2 78 40 84"),
        bytes.fromhex("5c a6 8d 13 94 be 2a 4d 3d 4d 7c 82 e5"),
        bytes.fromhex("31 b6 da c6 2e f1 ad 8d  c1 f6 0b 79 26 5e d0 de aa 31 dd d2 d5 3a a9 fd  93 43 46 38 10 f3 e2 23 24 06 36 6b 48 41 53 33  d4 b8 ac 33 6d 40 86 ef a0 f1 5e 6e 59"),
        bytes.fromhex("0d 1e c0 6f 36"),
    ]

    for i,packet in enumerate(packets):
        header = "\u001b[34m-->" if i % 2 == 0 else "\u001b[35m<--"
        decrypted_message = decrypt_chacha20(cipher,packet,key,nonce)
        if decrypted_message.startswith(b'RDBudF9V'):
            flag = base64.b64decode(decrypted_message).decode('utf-8')
        print(f"{header}\u001b[0m {decrypted_message.decode()}")
    
    print(f"\n\u001b[34mFlag:\u001b[0m {flag}")

