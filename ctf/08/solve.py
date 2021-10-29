import base64

def isPrintable(char):
    whitespace = [' ', '\r', '\n', '\t']
    if chr(char) in whitespace:
        return True
    return char > 0x20 and char < 0x7F

def readbase64File(name):
    with open(name,'rb') as f:
        result = bytearray(base64.b64decode(f.read()))
        f.close()
        return result

def writeFile(name,content):
    with open(name,'wb') as f:
        f.write(content)
        f.close()

first_table = readbase64File('./first_table.txt') #4fny3zLzDRYIOe37Ax
second_table = readbase64File('./second_table.txt') #b2JDN2
# first_table = readbase64File('./second_layer_first.txt') #4fny3zLzDRYIOe37Ax
# second_table = readbase64File('./second_layer_second.txt') #b2JDN2
dictlist = [dict() for x in range(64)]
for i,val in enumerate(first_table):
    for j in range(0x20,0x7F):
        plain = (first_table[i] - second_table[i % len(second_table)] - j) & 0xFF
        if isPrintable(plain):
            index = i % len(second_table) % 64
            if j in dictlist[index]:
                dictlist[index][j] += 1
            else:
                dictlist[index][j] = 1

all_possibilities = []
for index,val in enumerate(dictlist):
    counts = sorted(val.items(), key=lambda item: item[1], reverse=True)
    letter_candidates = []
    (x,highfreq) = counts[0]

    for i in range(20):
        (l,frequency) = counts[i]
        if (frequency == highfreq):
            letter_candidates.append(chr(l))
    all_possibilities.append(letter_candidates)

print(all_possibilities)
final = ''
for item in all_possibilities:
    if len(item) > 1:
        final += '*'
    else:
        final += item[0]
print(final)

final = ''
for item in all_possibilities:
    print(item)
    if len(item) > 1:
        final += item[len(item)-1]
    else:
        final += item[0]
print(final)