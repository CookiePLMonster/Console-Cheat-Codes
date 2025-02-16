import binascii
import json
import mmap
import re
import struct
from abc import ABC, abstractmethod
from bidict import bidict

def readU32(buf, addr):
    return struct.unpack_from('<I', buf, addr)[0]

def readCString(buf, addr, encoding='ascii'):
    return buf[addr:].split(b'\x00', 1)[0].decode(encoding)

def vaddrToOffset(vaddr):
    return vaddr - 0x100000 + 0x1000

def padList(l, length):
    extra_length = length - len(l)
    l.extend(0 for _ in range(extra_length))
    return l

def trimZeroes(arr):
    while len(arr) > 0 and arr[-1] == 0:
        arr = arr[:-1]
    return arr

def openFileMapping(path):
    with open(path) as f:
        return mmap.mmap(f.fileno(), 0, None, mmap.ACCESS_READ)

# Parsers
class ShaderParserBase(ABC):
    def __init__(self, eventNamesPtr, numEventNames, scannerConfigsPtr, numScannerConfigsPtr, scanners):
        self.eventNamesPtr = eventNamesPtr
        self.numEventNames = numEventNames
        self.scannerConfigsPtr = scannerConfigsPtr
        self.numScannerConfigsPtr = numScannerConfigsPtr
        self.scanners = scanners

    @abstractmethod
    def unpack(self, elf, eventNames, entry):
        pass

    @abstractmethod
    def pack(self, getKeyEventIdFn, config):
        pass

    def isWordRelevant(self, index):
        return True

class ScannerParserHP2(ShaderParserBase):
    configFormat = '<8bII2B2BbBH2II'

    def unpack(self, elf, eventNames, entry):
        newEntry = {}
        newEntry['configs'] = trimZeroes(entry[:8])
        newEntry['eventName'] = eventNames.get(entry[8], f'JOY_EVENT_UNK_{entry[8]}')
        if entry[9] != 0:
            newEntry['scanner'] = self.scanners[entry[9]]
        newEntry['xor'] = entry[10:12]
        newEntry['index'] = [(x >> 5) for x in entry[12:14]]
        newEntry['shift'] = [(x & 0x1F) for x in entry[12:14]]
        newEntry['invert'] = entry[14]
        newEntry['graph'] = entry[15]
        newEntry['unk16'] = entry[16]
        newEntry['glyph'] = trimZeroes(entry[17:19])
        if entry[19] != 0:
            newEntry['button'] = readCString(elf, vaddrToOffset(entry[19]))
        else:
            newEntry['button'] = ''

        return newEntry

    def pack(self, getKeyEventIdFn, config):
        return struct.pack(self.configFormat,
            *padList(config['configs'], 8),
                getKeyEventIdFn(config['eventName']),
                self.scanners.inverse.get(config.get('scanner'), 0),
                *config['xor'],
                config['index'][0] << 5 | (config['shift'][0] & 0x1F),
                config['index'][1] << 5 | (config['shift'][1] & 0x1F),
                config['invert'], config['graph'], config['unk16'],
                *padList(config['glyph'], 2),
                0
            )

    def isWordRelevant(self, index):
        return index != 8 # We don't care about 'button'

class ScannerParserUG1(ShaderParserBase):
    configFormat = '<8bII2B2BbBHII'

    def unpack(self, elf, eventNames, entry):
        newEntry = {}
        newEntry['configs'] = trimZeroes(entry[:8])
        newEntry['eventName'] = eventNames.get(entry[8], f'JOY_EVENT_UNK_{entry[8]}')
        if entry[9] != 0:
            try:
                newEntry['scanner'] = self.scanners[entry[9]]
            except KeyError as e:
                e.add_note(f'Unknown scanner function! Address: {entry[9]:08X}')
                raise
        newEntry['xor'] = entry[10:12]
        newEntry['index'] = [(x >> 5) for x in entry[12:14]]
        newEntry['shift'] = [(x & 0x1F) for x in entry[12:14]]
        newEntry['invert'] = entry[14]
        newEntry['graph'] = entry[15]
        newEntry['unk16'] = entry[16]
        newEntry['glyph'] = entry[17]
        if entry[18] != 0:
            newEntry['button'] = readCString(elf, vaddrToOffset(entry[18]))
        else:
            newEntry['button'] = ''

        return newEntry

    def pack(self, getKeyEventIdFn, config):
        return struct.pack(self.configFormat,
            *padList(config['configs'], 8),
                getKeyEventIdFn(config['eventName']),
                self.scanners.inverse.get(config.get('scanner'), 0),
                *config['xor'],
                config['index'][0] << 5 | (config['shift'][0] & 0x1F),
                config['index'][1] << 5 | (config['shift'][1] & 0x1F),
                config['invert'], config['graph'], config['unk16'],
                config['glyph'],
                0
            )

    def isWordRelevant(self, index):
        return index != 7 # We don't care about 'button'

def getParserForElf(elf):
    hash = binascii.crc32(elf) & 0xFFFFFFFF

    try:
        UG1_PAL_NTSCU = ScannerParserUG1(
                eventNamesPtr=0x4E1FF0, numEventNames=169,
                scannerConfigsPtr=0x44C400, numScannerConfigsPtr=0x500128,
            scanners=bidict({
                0x2D4FD0 : 'TypeChanged',
                0x2D5010 : 'DigitalAnyButton',
                0x2D5098 : 'DigitalDown',
                0x2D51B0 : 'DigitalDownPlus',
                0x2D51D0 : 'DigitalUpOrDown',
                0x2D52E0 : 'DigitalUpOrDownPlus',
                0x2D5300 : 'DigitalDoublePress',
                0x2D5478 : 'DigitalRepeat',
                0x2D55D0 : 'DigitalSteer',
                0x2D5678 : 'DigitalAnalog',
                0x2D58C8 : 'DigitalAnalogDown',
                0x2D5A40 : 'DigitalAnalogUpOrDown',
                0x2D5B68 : 'Analog'
        }))

        data = {
            # Hot Pursuit 2 NTSC-U
            0xb879bb85 : ScannerParserHP2(
                eventNamesPtr=0x2FA2D0, numEventNames=130,
                scannerConfigsPtr=0x2DC500, numScannerConfigsPtr=0x32FBE0,
            scanners=bidict({
                0x1545E8 : 'TypeChanged',
                0x1546B0 : 'DigitalDown',
                0x154A90 : 'DigitalRepeat',
                0x1547E8 : 'DigitalUpOrDown',
                0x154C90 : 'DigitalAnalog',
                0x154628 : 'DigitalAnyButton',
                0x154E48 : 'Analog',
                0x154918 : 'DigitalDoublePress',
                0x154BE8 : 'DigitalSteer',
            })),

            # Hot Pursuit 2 NTSC-U A1.56 prototype
            0x6297bb64 : ScannerParserHP2(
                eventNamesPtr=0x2F1B48, numEventNames=130,
                scannerConfigsPtr=0x2D3AC0, numScannerConfigsPtr=0x326C40,
            scanners=bidict({
                0x1541A0 : 'TypeChanged',
                0x1541E0 : 'DigitalAnyButton',
                0x154268 : 'DigitalDown',
                0x154380 : 'DigitalDownPlus',
                0x1543A0 : 'DigitalUpOrDown',
                0x1544B0 : 'DigitalUpOrDownPlus',
                0x1544D0 : 'DigitalDoublePress',
                0x154648 : 'DigitalRepeat',
                0x1547A0 : 'DigitalSteer',
                0x154848 : 'DigitalAnalog',
                0x154A00 : 'Analog',
            })),

            # Underground NTSC-U
            0xb0fcc39b : UG1_PAL_NTSCU,

            # Underground PAL (same as NTSC-U)
            0xc1faa5d5 : UG1_PAL_NTSCU,

            # Underground NTSC-J (EA Best Hits)
            0xad838821 : ScannerParserUG1(
                eventNamesPtr=0x4EE500, numEventNames=169,
                scannerConfigsPtr=0x453100, numScannerConfigsPtr=0x50D0A8,
            scanners=bidict({
                0x2DB618 : 'TypeChanged',
                0x2DB658 : 'DigitalAnyButton',
                0x2DB6E0 : 'DigitalDown',
                0x2DB7F8 : 'DigitalDownPlus',
                0x2DB818 : 'DigitalUpOrDown',
                0x2DB928 : 'DigitalUpOrDownPlus',
                0x2DB948 : 'DigitalDoublePress',
                0x2DBAC0 : 'DigitalRepeat',
                0x2DBC18 : 'DigitalSteer',
                0x2DBCC0 : 'DigitalAnalog',
                0x2DBF10 : 'DigitalAnalogDown',
                0x2DC088 : 'DigitalAnalogUpOrDown',
                0x2DC1B0 : 'Analog'
            })),
        }
        return data[hash]
    except KeyError as e:
        e.add_note(f'Unknown game specified! ELF CRC32: {hash:08X}')
        raise

def dumpEventNames(elfPath, output):
    events = []
    with openFileMapping(elfPath) as elf:
        parser = getParserForElf(elf)

        FORMAT = '<II'
        entrySize = struct.calcsize(FORMAT)

        startOffset = vaddrToOffset(parser.eventNamesPtr)
        for entry in struct.iter_unpack(FORMAT, elf[startOffset:startOffset+(entrySize*parser.numEventNames)]):
            events.append({'id': entry[0], 'name': readCString(elf, vaddrToOffset(entry[1]))})

    with open(output, 'w') as f:
        json.dump(events, f, indent=2)

def dumpScannerConfigs(elfPath, eventNamesPath, output):
    scannerConfigs = []

    def getEventNames():
        result = {}
        with open(eventNamesPath) as f:
            for event in json.load(f):
                result[event['id']] = event['name']
        return result

    with openFileMapping(elfPath) as elf:
        parser = getParserForElf(elf)

        entrySize = struct.calcsize(parser.configFormat)
        eventNames = getEventNames()

        startOffset = vaddrToOffset(parser.scannerConfigsPtr)
        numScannerConfigs = readU32(elf, vaddrToOffset(parser.numScannerConfigsPtr))
        for entry in struct.iter_unpack(parser.configFormat, elf[startOffset:startOffset+(entrySize*numScannerConfigs)]):
            scannerConfigs.append(parser.unpack(elf, eventNames, entry))

    with open(output, 'w') as f:
        json.dump(scannerConfigs, f, indent=2)

def generatePnachFile(elfPath, eventNamesPath, scannerConfigsPath, output):

    def getEventIds():
        result = {}
        with open(eventNamesPath) as f:
            for event in json.load(f):
                result[event['name']] = event['id']
        return result

    def getScannerConfigs():
        result = []
        with open(scannerConfigsPath) as f:
            result = json.load(f)
        return result

    with openFileMapping(elfPath) as elf:
        parser = getParserForElf(elf)
        entrySize = struct.calcsize(parser.configFormat)
        NEW_CONFIGS = getScannerConfigs()

        startOffset = parser.scannerConfigsPtr
        origNumScannerConfigs = readU32(elf, vaddrToOffset(parser.numScannerConfigsPtr))
        if len(NEW_CONFIGS) > origNumScannerConfigs:
            raise ValueError(f'Out of space for scanner configs! Specified {len(NEW_CONFIGS)} configs, max {origNumScannerConfigs}')

        with open(output, 'w') as pnach:
            EVENT_IDS = getEventIds()
            def getKeyEventId(key):
                match = re.match(r'JOY_EVENT_UNK_(\d+)', key)
                if match:
                    return int(match.group(1))
                return EVENT_IDS[key]

            LINE_TEMPLATE = 'patch=0,EE,{0:X},extended,{1:X}\n'
            if origNumScannerConfigs != len(NEW_CONFIGS):
                pnach.write(LINE_TEMPLATE.format(parser.numScannerConfigsPtr, len(NEW_CONFIGS)))
            for config in NEW_CONFIGS:

                # Pack and unpack again to integers so we can generate a pnach
                patchedMem = struct.unpack(f'<{entrySize // 4}I', parser.pack(getKeyEventId, config))
                offset = startOffset
                for index, value in enumerate(patchedMem):
                    if parser.isWordRelevant(index) and readU32(elf, vaddrToOffset(offset)) != value:
                        pnach.write(LINE_TEMPLATE.format(offset | 0x20000000, value))
                    offset += 4

                startOffset += entrySize


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='NFS Scanner Config Tool.')
    parser.add_argument('--elf', type=str, help='path to game elf', metavar='ELF_PATH', required=True)
    parser.add_argument('--event-names', type=str, dest='event_names', metavar='EVENT_NAMES_JSON',
                        help='path to the JSON file with event names (required by --dump-scanner-configs and --generate-pnach)')
    parser.add_argument('--scanner-configs', type=str, dest='scanner_configs', metavar='SCANNER_CONFIGS_JSON',
                        help='path to the JSON file with scanner configs (required by --generate-pnach)')

    parser.add_argument('--dump-event-names', type=str, dest='dump_event_names', metavar='EVENT_NAMES_JSON',
                        help='dump event names to a JSON file')
    parser.add_argument('--dump-scanner-configs', type=str, dest='dump_scanner_configs', metavar='SCANNER_CONFIGS_JSON',
                        help='dump scanner configs to a JSON file')
    parser.add_argument('--generate-pnach', type=str, dest='generate_pnach', metavar='PNACH_PATH',
                        help='generate a patch file with new scanner configs')

    args = parser.parse_args()

    if args.dump_event_names:
        dumpEventNames(args.elf, args.dump_event_names)

    if args.dump_scanner_configs:
        dumpScannerConfigs(args.elf, args.event_names, args.dump_scanner_configs)

    if args.generate_pnach:
        generatePnachFile(args.elf, args.event_names, args.scanner_configs, args.generate_pnach)
