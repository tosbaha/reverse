import glob
import os

def readFile(filename):
    with open(filename,'rb') as f:
        bytes = f.read()
        f.close()
        return bytes

def writeFile(filename,bytes):
    with open(filename,'wb') as f:
        f.write(bytes)
        f.close()

def decrypt(filename,mask):
    src = readFile(filename)
    bytes = bytearray()
    v2 = 0
    for i in range(len(src)):
        byte = src[i]
        byte ^= mask[i] ^ v2
        v2 = mask[i]
        bytes.append(byte)
    original_name = os.path.basename(filename).replace('.broken','')
    print("Decrypted %s" % original_name)
    writeFile('./Decrypted/' + original_name,bytes)

mask = readFile('./mask.bin')
for filename in glob.iglob('./Documents/' + '*.broken', recursive=True):
    decrypt(filename,mask)