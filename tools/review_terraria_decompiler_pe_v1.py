"""Inspect a decompiler PE file without loading/executing it. Static evidence only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


class PE:
    def __init__(self, raw):
        self.raw = raw
        self.take(0, 64)
        if self.take(0, 2) != b'MZ':
            raise ValueError('Missing DOS signature')
        self.pe = self.unpack('<I', 0x3c)[0]
        if self.take(self.pe, 4) != b'PE\0\0':
            raise ValueError('Missing PE signature')
        self.machine, count = self.unpack('<HH', self.pe + 4)
        size, self.characteristics = self.unpack('<HH', self.pe + 20)
        self.optional = self.pe + 24
        self.take(self.optional, size)
        if size < 112 or self.unpack('<H', self.optional)[0] != 0x20b:
            raise ValueError('Expected PE32+ optional header')
        self.headers = self.unpack('<I', self.optional + 60)[0]
        self.sections = []
        for index in range(count):
            offset = self.optional + size + 40 * index
            section = self.take(offset, 40)
            virtual_size, rva, raw_size, file_offset = struct.unpack_from('<IIII', section, 8)
            self.take(file_offset, raw_size)
            self.sections.append(dict(name=section[:8].rstrip(b'\0').decode('ascii'),
                                      virtual_size=virtual_size, rva=rva,
                                      raw_size=raw_size, file_offset=file_offset))
        self.directories = []
        directory_count = self.unpack('<I', self.optional + 108)[0]
        if directory_count > (size - 112) // 8:
            raise ValueError('Directories exceed optional header')
        for index in range(directory_count):
            self.directories.append(self.unpack('<II', self.optional + 112 + 8 * index))

    def take(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.raw):
            raise ValueError('PE file bounds exceeded')
        return self.raw[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.take(offset, struct.calcsize(fmt)))

    def at_rva(self, rva, size):
        mappings = []
        if rva < self.headers and rva + size <= self.headers:
            mappings.append(rva)
        for section in self.sections:
            delta = rva - section['rva']
            if 0 <= delta and delta + size <= section['raw_size']:
                mappings.append(section['file_offset'] + delta)
        if len(mappings) != 1:
            raise ValueError('Unmapped or ambiguous RVA')
        self.take(mappings[0], size)
        return mappings[0]

    def string(self, rva):
        data = bytearray()
        for index in range(4096):
            value = self.raw[self.at_rva(rva + index, 1)]
            if value == 0:
                return data.decode('ascii')
            data.append(value)
        raise ValueError('Unterminated PE string')

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def imports(self):
        rva, size = self.directory(1)
        if rva == size == 0:
            return []
        if not rva or size < 20:
            raise ValueError('Invalid import directory')
        imports = []
        for offset in range(0, size - 19, 20):
            entry = self.unpack('<IIIII', self.at_rva(rva + offset, 20))
            if not any(entry):
                return imports
            original_thunk, timestamp, chain, name_rva, first_thunk = entry
            name = self.string(name_rva)
            if not name or any(c in name for c in '/\\:'):
                raise ValueError('Unexpected DLL import name')
            symbols = []
            thunk = original_thunk or first_thunk
            for index in range(65536):
                value = self.unpack('<Q', self.at_rva(thunk + 8 * index, 8))[0]
                if value == 0:
                    break
                if value >> 63:
                    symbols.append(dict(ordinal=value & 0xffff))
                else:
                    hint = self.unpack('<H', self.at_rva(value, 2))[0]
                    symbols.append(dict(name=self.string(value + 2), hint=hint))
            else:
                raise ValueError('Unterminated import thunk array')
            imports.append(dict(dll=name, symbols=symbols, timestamp=timestamp,
                                forwarder_chain=chain))
        raise ValueError('Unterminated import descriptor array')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine', type=Path)
    parser.add_argument('--expect-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.engine.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != args.expect_sha256:
        raise ValueError('Engine SHA differs from explicit identity')
    pe = PE(raw)
    stack_reserve, stack_commit = pe.unpack('<QQ', pe.optional + 72)
    imports = pe.imports()
    report = dict(scope='Static PE inspection; file never loaded or executed.',
                  inspector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  path=str(args.engine.resolve()), bytes=len(raw), sha256=digest,
                  machine=hex(pe.machine), optional_magic='0x20b',
                  stack_reserve=stack_reserve, stack_commit=stack_commit,
                  entry_rva=hex(pe.unpack('<I', pe.optional + 16)[0]),
                  subsystem=pe.unpack('<H', pe.optional + 68)[0],
                  dll_characteristics=hex(pe.unpack('<H', pe.optional + 70)[0]),
                  sections=pe.sections, imports=imports,
                  delay_import_directory=pe.directory(13),
                  clr_directory=pe.directory(14),
                  header_gates_passed=(pe.machine == 0x8664 and stack_reserve == 33554432
                                       and stack_commit == 4096 and bool(pe.characteristics & 2)
                                       and not bool(pe.characteristics & 0x2000)),
                  dependencies_resolved=False, engine_executed=False,
                  runtime_smoke_passed=False, C_coverage_addition=0)
    if args.output.exists():
        raise FileExistsError('Preserve previous PE review')
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps({k: report[k] for k in ('sha256', 'machine', 'stack_reserve',
                                            'stack_commit', 'header_gates_passed')}))
    print(json.dumps({'DLLs': [row['dll'] for row in imports]}))


if __name__ == '__main__':
    main()
