def IDAStringToByteArray(str):
    tokens = str.split(' ')
    output = []
    for t in tokens:
        output.append(int(t, 16))
    
    return output

def ByteArrayToWordArray(arr):
    si = iter(arr)
    return [c | (next(si, 0) << 8) for c in si]

print('Cheat String Generator\nGenerates a series of cheats checking for a specified string of bytes and replacing it with another\n')

address = int(input('Enter the starting address: '), 16) & 0x00FFFFFF

input_bytes = IDAStringToByteArray(input('Enter original bytes: '))
output_bytes = IDAStringToByteArray(input('Enter replaced bytes: '))

input_words = ByteArrayToWordArray(input_bytes)
output_words = ByteArrayToWordArray(output_bytes)

for ii, oi in zip(input_words, output_words):
   print(f'{address | 0xD0000000:0>8X} {ii:0>4X}')
   print(f'{address | 0x80000000:0>8X} {oi:0>4X}') 
   address += 2
