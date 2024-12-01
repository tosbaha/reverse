import json
from collections import Counter

f = open('./trace.json') 
trace1 = json.load(f)

def construct_key(candidates):
    counts = Counter(candidates)
    repeated_elements = [byte for byte, count in counts.items() if count >= 2]
    if (len(repeated_elements) == 4):
        reversed_hex_number = '0x' + ''.join(byte[2:] for byte in reversed(repeated_elements))
        return reversed_hex_number
    else:
        return f"Failed {candidates}"

def process_key(acc,seed,op):
    if op == '+':
        return acc + seed
    elif op == '-':
        return acc - seed
    elif op == '^':
        return acc ^ seed

def subtract_from_0x100(arr):
    for i in range(len(arr)):
        arr[i] = (0x100 - arr[i]) & 0xFF
    return arr  

def guess_constant(trace,previous=0):
    function_name = '+'
    current_key = []
    
    operations = trace['operations']
    seed = ord(trace['chr']) * int(trace['multiplier'],16)
    complimentary_key = False
    functions = {'extras':[], 'confirmation' :[],'const': f"* {trace['multiplier']}",  'const_sign':'+='}

    for i,op in enumerate(operations):
        if i == 0 and  op['op'] == 'mov' and op['byte'] == '0x0':
            function_name += '+'
            functions['const'] = f"* {trace['multiplier']}"
            functions['const_sign'] = '+='
        elif i== 0 and op['op'] == 'sub':
            functions['const_sign'] = '+='
            functions['const'] = f"* -{trace['multiplier']}"
        elif i == 0 and  op['op'] == 'mov' and op['byte'] == '0x1':
            function_name += '-'
            functions['const'] = f"* {trace['multiplier']}"
            functions['const_sign'] = '-='
        elif i== 0 and op['op'] == 'xor':
            function_name += '^'
            functions['const_sign'] = f"^="
            functions['const'] = f"* {trace['multiplier']}"
        elif op['op'] == 'sub' and (op['amount'] == '0x100' or op['amount'] == '0x10000' or op['amount'] == '0x100000000'):
            complimentary_key = True

        elif op['op'] == 'or':
            functions['confirmation'].append({
                'result': op['result']
            })

        elif op['op'] == 'mov':
            if op['byte'] == '0x0':
                function_name += '+'
            elif op['byte'] == '0x1':
                function_name += '-'
            elif op['byte'] == '0x2a':
                pass
            elif len(current_key) < 4:
                 current_key.append(op['byte'])
        elif op['op'] == 'xor':
            function_name += '^'
        
        if len(current_key) == 4:

            revised_key = [hex(0x100 - int(x, 16)) for x in current_key]
            key_revision = '0x' + ''.join(byte[2:].zfill(2) for byte in reversed(revised_key))
            
            if complimentary_key == True:
                current_key =  [hex(0x100 - int(x, 16)) for x in current_key]            
            function = function_name[-1]


            accum = '0x' + ''.join(byte[2:].zfill(2) for byte in reversed(current_key))
            functions['extras'].append({
                'val':accum,
                'alt':key_revision,
                'sign':complimentary_key,
                'op':f"{function}="
            })

            complimentary_key = False
            result = process_key(int(accum,16),seed,function)
            current_key = []
    return functions


def create_code():
    for i,obj in enumerate(trace1):
        item = trace1[i]
        prev = 0 if i % 8 == 0 else trace1[i]['operations']
        functions = guess_constant(item,prev)
        if i % 8 == 0:
            print(f"def checkpoint_{i//8}(flag):")
            print(f"    accumulated_value = flag[{item['index']}] {functions['const']}")
            if (len(functions['extras']) > 0):
                print(f"    accumulated_value {functions['const_sign']} {functions['extras'][0]['val']} #{functions['extras'][0]['alt']}")
            else:
                print(f"   # accumulated_value {functions['const_sign']} UNKNOWN")

            print(f"    assert({functions['confirmation'][0]['result']} == accumulated_value)")

        else:
            if functions and functions.get('const') is not None:
                print(f"    accumulated_value {functions['const_sign']} flag[{item['index']}] {functions['const']}")
            for i,element in enumerate(functions['extras']):
                print(f"    accumulated_value {element['op']} {element['val']} #{functions['extras'][0]['alt']}")
                if i < len(functions['confirmation']):
                    print(f"    assert({functions['confirmation'][i]['result']} == accumulated_value)")
                else:
                    print(f"    #confirm accumulated_value")         
        if i > 0 and i % 9 == 1:
            print(f"    accumulated_value &= 0xffffffffffffffff")
            print(f"    return accumulated_value\n")

create_code()
