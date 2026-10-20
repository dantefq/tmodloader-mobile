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
                                      raw_size=raw_size, file_offset=file_offset,
                                      characteristics=struct.unpack_from('<I', section, 36)[0]))
        self.section_table_end = self.optional + size + 40 * count
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
            if not first_thunk:
                raise ValueError('Missing import address table')
            self.at_rva(first_thunk, 8)
            thunk = original_thunk or first_thunk
            for index in range(65536):
                value = self.unpack('<Q', self.at_rva(thunk + 8 * index, 8))[0]
                iat_value = self.unpack('<Q', self.at_rva(first_thunk + 8 * index, 8))[0]
                if bool(value) != bool(iat_value):
                    raise ValueError('ILT/IAT termination mismatch')
                if value == 0:
                    break
                if value >> 63:
                    if value & ~((1 << 63) | 0xffff) or not value & 0xffff:
                        raise ValueError('Invalid ordinal import encoding')
                    symbols.append(dict(ordinal=value & 0xffff))
                else:
                    if value & ~0x7fffffff:
                        raise ValueError('Reserved bits in name import encoding')
                    hint = self.unpack('<H', self.at_rva(value, 2))[0]
                    symbols.append(dict(name=self.string(value + 2), hint=hint))
            else:
                raise ValueError('Unterminated import thunk array')
            imports.append(dict(dll=name, symbols=symbols, timestamp=timestamp,
                                forwarder_chain=chain))
        raise ValueError('Unterminated import descriptor array')

    def static_gate_failures(self):
        failures = []
        entry = self.unpack('<I', self.optional + 16)[0]
        image_size = self.unpack('<I', self.optional + 56)[0]
        alignment = self.unpack('<I', self.optional + 32)[0]
        file_alignment = self.unpack('<I', self.optional + 36)[0]
        reserve, commit = self.unpack('<QQ', self.optional + 72)
        def disjoint(ranges):
            ordered = sorted((start, end) for start, end in ranges if end > start)
            return all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:]))
        conditions = {
            'AMD64_required': self.machine == 0x8664,
            '32MiB_stack_required': reserve == 33554432 and commit == 4096,
            'executable_not_DLL_required': bool(self.characteristics & 2) and not self.characteristics & 0x2000,
            'console_subsystem_required': self.unpack('<H', self.optional + 68)[0] == 3,
            'delay_imports_unsupported': self.directory(13) == (0, 0),
            'bound_imports_unsupported': self.directory(11) == (0, 0),
            'CLR_unsupported': self.directory(14) == (0, 0),
            'image_size_invalid': (image_size > 0 and 0 < self.headers <= image_size
                                   and alignment > 0 and not alignment & (alignment - 1)
                                   and image_size % alignment == 0
                                   and all(s['rva'] + max(s['virtual_size'], s['raw_size']) <= image_size
                                           for s in self.sections)),
            'headers_or_file_alignment_invalid': (self.section_table_end <= self.headers <= len(self.raw)
                and 512 <= file_alignment <= 65536 and not file_alignment & (file_alignment - 1)
                and alignment >= file_alignment and self.headers % file_alignment == 0),
            'section_overlap_or_alignment_invalid': (bool(self.sections)
                and all(s['rva'] >= self.headers and alignment > 0 and s['rva'] % alignment == 0
                    and (not s['raw_size'] or (s['file_offset'] >= self.headers
                         and file_alignment > 0 and s['file_offset'] % file_alignment == 0
                         and s['raw_size'] % file_alignment == 0)) for s in self.sections)
                and disjoint((s['rva'], s['rva'] + max(s['virtual_size'], s['raw_size'])) for s in self.sections)
                and disjoint((s['file_offset'], s['file_offset'] + s['raw_size']) for s in self.sections)),
            'entry_in_executable_section_required': (entry > 0 and entry < image_size
                and any(s['characteristics'] & 0x20000000 and s['rva'] <= entry
                        < s['rva'] + s['virtual_size'] for s in self.sections)),
        }
        failures.extend(name for name, passed in conditions.items() if not passed)
        try:
            self.at_rva(entry, 1)
        except ValueError:
            failures.append('entry_not_uniquely_file_backed')
        return failures


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
    failures = pe.static_gate_failures()
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
                  bound_import_directory=pe.directory(11),
                  clr_directory=pe.directory(14),
                  header_gates_passed=not failures, static_gate_failures=failures,
                  dependencies_resolved=False, engine_executed=False,
                  launch_eligible=False, runtime_smoke_passed=False, C_coverage_addition=0)
    if args.output.exists():
        raise FileExistsError('Preserve previous PE review')
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps({k: report[k] for k in ('sha256', 'machine', 'stack_reserve',
                                            'stack_commit', 'header_gates_passed')}))
    print(json.dumps({'DLLs': [row['dll'] for row in imports]}))
    if failures:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
