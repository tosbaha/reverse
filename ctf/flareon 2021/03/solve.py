import glob
import json
import binascii

name_hashes = [
0x0B59395A9,0x1BB5AB29,0x0E,
0x5EFDD04B,0x3F8468C8,0x12,
0x0ECED85D0,0x82D23D48,0x2,
0x0D8549214,0x472EE5,0x1D,
0x2C2F024D,0x0C9A060AA,0x0C,
0x18A5232,0x24D235,0x0D,
0x72B88A33,0x81576613,0x14,
0x674404E2,0x5169E129,0x0B,
0x307A73B5,0x0E560E13E,0x1C,
0x13468704,0x2358E4A9,0x15,
0x94F6471B,0x0D6341A53,0x5,
0x0EDA1CF75,0x0BAFA91E5,0x18,
0x0BBAC124D,0x0A697641D,0x19,
0x0F707E4C3,0x0EF185643,0x7,
0x0D702596F,0x79C28915,0x0A,
0x86A10848,0x59108FDC,0x1,
0x0D640531C,0x0EF3DE1E8,0x13,
0x7B665DB3,0x0A3A903B0,0x3,
0x0AB1321CC,0x0EEEDEAD7,0x4,
0x4F6066D8,0x9C8A3D07,0x11,
0x256047CA,0x4085BE9E,0x9,
0x3FC91ED3,0x379549C9,0x8,
0x0A424AFE4,0x0EF871347,0x1B,
0x550901DA,0x1FCEC6B,0x10,
0x10A29E2D,0x0E76056AA,0x16,
0x56CBC85F,0x356F1A68,0x0F,
0x80DFE3A6,0x9D0AB536,0x1E,
0x0E657D4E1,0x0B4E9FD30,0x17,
0x2BA1E1D4,0x0BE66D918,0x1A,
0x7D33089B,0x67C1F585,0x6
]

name_map = {}
for filename in glob.iglob('./antioch/' + '**/json', recursive=True):
  f = open(filename)
  data = json.load(f)
  if "author" in data:
    author_id = data["id"]
    author = data['author']
    print(author)
    print(author_id)
    print('File %s ' % filename)
    byte_array = bytes(author + "\n", 'utf-8')
    hash = binascii.crc32(byte_array) #calculate crc32 of name by appending "\n"
    index = name_hashes.index(hash)
    order = name_hashes[index+2]
    name_map[order] = author_id
    print('Order %d' % order)
    print("----------")
  f.close()

dictionary_items = name_map.items()
sorted_items = sorted(dictionary_items)
for item in sorted_items:
  source_dir = "./antioch/" + item[1] + '/layer'
  print("COPY %s/*.dat ./" % source_dir )