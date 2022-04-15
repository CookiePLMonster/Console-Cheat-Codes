def printVersions(versions):
    num = 1
    for v in versions:
        print(f'\t{num}. {v}')
        num = num + 1

def readFile(version):
    lines = []
    with open(f'resource/gt2-ws/{version}.cht') as f:
        lines = [line.rstrip() for line in f.readlines()]
    return lines

def parseTag(line):
    tag = ()
    start = line.find('{')
    end = line.find('}')
    if start != -1 and end != -1:
        tag = (start, end+1, line[start+1:end].lower())
    return tag

print('Gran Turismo 2: Widescreen Cheat Generator\nGenerates a widescreen cheat for Gran Turismo 2, tailored for a specified aspect ratio and game version\n')
print('Select the game version to generate the cheat for:')

versions = ['NTSC-U 1.2', 'NTSC-U 1.1', 'NTSC-J 1.1', 'NTSC-J 1.0', 'PAL']
printVersions(versions)

choice = 0
while not 1 <= choice <= len(versions):
    choice = int(input(''))

print('Select the aspect ratio to generate the patch for, in \'X:Y\' format (e.g. 16:9):')
while True:
    try:
        AR = tuple(map(int, input('').split(':', 1)))
        if len(AR) != 2:
            continue
        break
    except ValueError:
        continue

origAR = (4, 3)

lines = readFile(versions[choice-1])
for line in lines:
    parsed = parseTag(line)
    if parsed:
        start, end, tag = parsed
        if tag == 'ar':
            line = line[0:start] + f'{AR[0]}:{AR[1]}' + line[end:]
        elif tag[0] == 'm':
            # Multiply by AR
            oldValue = int(tag[1:], 16)
            newValue = int(oldValue * AR[0] * origAR[1] / AR[1] / origAR[0])
            line = line[0:start] + f'{oldValue & 0xffff:0>4X}{newValue & 0xffff:0>4X}' + line[end:]
        elif tag[0] == 'd':
            # Divide by AR
            oldValue = int(tag[1:], 16)
            newValue = int(oldValue * AR[1] * origAR[0] / AR[0] / origAR[1])
            line = line[0:start] + f'{oldValue & 0xffff:0>4X}{newValue & 0xffff:0>4X}' + line[end:]
    print(line)