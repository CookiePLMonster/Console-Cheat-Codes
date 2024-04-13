import json
import mmap
import struct

def readCString(buf, addr, encoding='ascii'):
    return buf[addr:].split(b'\x00', 1)[0].decode(encoding)

def openFileMapping(path):
    with open(path) as f:
        return mmap.mmap(f.fileno(), 0, None, mmap.ACCESS_READ)

def dumpEventNames(elfPath, output):
    events = []
    with openFileMapping(elfPath) as elf:
        FORMAT = '<II'
        ENTRY_SIZE = struct.calcsize(FORMAT)
        NUM_ENTRIES = 130

        def vaddrToOffset(vaddr):
            return vaddr - 0x100000 + 0x1000

        START_OFFSET = 0x1FB2D0
        for entry in struct.iter_unpack(FORMAT, elf[START_OFFSET:START_OFFSET+(ENTRY_SIZE*NUM_ENTRIES)]):
            events.append({'id': entry[0], 'name': readCString(elf, vaddrToOffset(entry[1]))})

    with open(output, 'w') as f:
        json.dump(events, f, indent=2)

def dumpScannerConfigs(elfPath, eventNamesPath, numConfigs, output):
    scannerConfigs = []

    def getEventNames():
        result = {}
        with open(eventNamesPath) as f:
            for event in json.load(f):
                result[event['id']] = event['name']
        return result

    with openFileMapping(elfPath) as elf:
        FORMAT = '<8BII2B2BbBH2II'
        ENTRY_SIZE = struct.calcsize(FORMAT)
        EVENT_NAMES = getEventNames()
        CALLBACKS = {
            0x1545E8 : 'TypeChanged',
            0x1546B0 : 'DigitalDown',
            0x154A90 : 'DigitalRepeat',
            0x1547E8 : 'DigitalUpOrDown',
            0x154C90 : 'DigitalAnalog',
            0x154628 : 'DigitalAnyButton',
            0x154E48 : 'Analog',
            0x154918 : 'DigitalDoublePress',
            0x154BE8 : 'DigitalSteer',
        }

        def vaddrToOffset(vaddr):
            return vaddr - 0x100000 + 0x1000

        START_OFFSET = 0x1DD500
        for entry in struct.iter_unpack(FORMAT, elf[START_OFFSET:START_OFFSET+(ENTRY_SIZE*numConfigs)]):
            def trimZeroes(arr):
                while len(arr) > 0 and arr[-1] == 0:
                    arr = arr[:-1]
                return arr

            newEntry = {}
            newEntry['configs'] = trimZeroes(entry[:8])
            newEntry['eventName'] = EVENT_NAMES.get(entry[8], f'JOY_EVENT_UNK_{entry[8]}')
            if entry[9] != 0:
                newEntry['scanner'] = CALLBACKS[entry[9]]
            newEntry['xor'] = entry[10:12],
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

            scannerConfigs.append(newEntry)

    with open(output, 'w') as f:
        json.dump(scannerConfigs, f, indent=2)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Need for Speed Hot Pursuit 2 Scanner Config Tool.')
    parser.add_argument('--elf', type=str, help='path to game elf')
    parser.add_argument('--event-names', type=str, dest='event_names', help='path to the JSON file with event names')
    parser.add_argument('--scanner-configs', type=str, dest='scanner_configs', help='path to the JSON file with scanner configs')

    parser.add_argument('--dump-event-names', type=str, dest='dump_event_names', help='dump event names to a JSON file')
    parser.add_argument('--dump-scanner-configs', type=str, dest='dump_scanner_configs', help='dump scanner configs to a JSON file')
    parser.add_argument('--num-scanner-configs', type=int, dest='num_scanner_configs', help='number of scanner configs to dump')

    args = parser.parse_args()

    if args.dump_event_names:
        dumpEventNames(args.elf, args.dump_event_names)

    if args.dump_scanner_configs:
        dumpScannerConfigs(args.elf, args.event_names, args.num_scanner_configs, args.dump_scanner_configs)
