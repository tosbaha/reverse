import hashlib
import itertools

def getPermutations(arr):
    permutations =  list(itertools.permutations(arr))
    result = []
    for element in permutations:
        result.append(''.join(element))
    return result

def encrypt(fl,jet):
    byte_arr = [0x96, 0x25, 0xA4, 0xA9, 0xA3, 0x96, 0x9A, 0x90, 0x9F, 0xAF, 0xE5, 0x38, 0xF9, 0x81, 0x9E, 0x16, 0xF9, 0xCB, 0xE4, 0xA4, 0x87, 0x8F, 0x8F, 0xBA, 0xD2, 0x9D, 0xA7, 0xD1, 0xFC, 0xA3, 0xA8]
    fl_byte = bytearray(fl.encode('utf-8'))
    jet_byte = bytearray(jet.encode('utf-8'))
    for index in range(len(byte_arr)):
        byte_arr[index] = byte_arr[index] ^ fl_byte[index % len(fl)]
        byte_arr[index] = (byte_arr[index] - jet_byte[ index % 17]) & 0xFF
    return  ''.join(map(chr, byte_arr))    

#possible values for floatsam and jetsam
float_array = ['DFWEyEW','PXopvM','BGgsuhn']
jetsam_array = ['newaui','HwdwAZ','SLdkv']

float_permutations = getPermutations(float_array)
jetsam_permutations = getPermutations(jetsam_array)

for float_str in float_permutations:
    for jet_str in jetsam_permutations:
        result = encrypt(float_str,jet_str)
        md5_hash = hashlib.md5(result.encode('utf-8')).hexdigest()
        if md5_hash == '6c5215b12a10e936f8de1e42083ba184':
            print("Found: %s" % result )
            print('Float %s JetSam %s' %(float_str,jet_str))