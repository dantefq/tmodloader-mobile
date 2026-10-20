"""Read TMOD headers and file tables; never execute or extract mod code."""
import argparse
import json
from pathlib import Path
import struct

FORMAT_SOURCE = ('https://github.com/tModLoader/tModLoader/blob/'
                 'c9545cf27d56c456321e1896274c02adf67d0140/'
                 'patches/tModLoader/Terraria/ModLoader/Core/TmodFile.cs')


def exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError('Truncated TMOD header/table')
    return data


def string(stream):
    length = 0
    for shift in range(0, 35, 7):
        byte = exact(stream, 1)[0]
        length |= (byte & 127) << shift
        if not byte & 128:
            if length > 65536:
                raise ValueError('Oversized metadata string')
            return exact(stream, length).decode('utf-8', errors='strict')
    raise ValueError('Invalid string length encoding')


def integer(stream):
    return struct.unpack('<i', exact(stream, 4))[0]


def inspect(path, root):
    size = path.stat().st_size
    with path.open('rb') as stream:
        if exact(stream, 4) != b'TMOD':
            raise ValueError('TMOD magic missing')
        loader = string(stream)
        version_parts = tuple(int(n) for n in loader.split('.'))
        if version_parts < (0, 11):
            raise ValueError('Legacy compressed table not supported by this inspector')
        exact(stream, 20 + 256)  # Stored hash and signature; neither modified nor authenticated.
        payload_size = integer(stream)
        if payload_size != size - stream.tell():
            raise ValueError('Declared payload size mismatch')
        name, version = string(stream), string(stream)
        count = integer(stream)
        if not 0 <= count <= 100000:
            raise ValueError('Invalid file count')
        assemblies, stored_total = [], 0
        for _ in range(count):
            entry = string(stream)
            expanded, stored = integer(stream), integer(stream)
            if min(expanded, stored) < 0:
                raise ValueError('Negative entry size')
            stored_total += stored
            if entry.lower().endswith('.dll'):
                assemblies.append(entry)
        if stored_total != size - stream.tell():
            raise ValueError('Stored entry sizes do not cover payload')
    return {'path': path.relative_to(root).as_posix(), 'name': name,
            'mod_version': version, 'tmodloader_build_version': loader,
            'bytes': size, 'entry_count': count, 'assembly_entries': assemblies,
            'structure_valid': True, 'content_hash_verified': False,
            'signature_authenticated': False, 'executed': False,
            'mobile_compatibility_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Expected a workshop directory')
    records, errors = [], []
    for path in sorted(root.rglob('*.tmod')):
        try:
            records.append(inspect(path, root))
        except (ValueError, OSError, UnicodeError) as error:
            errors.append({'path': path.relative_to(root).as_posix(), 'error': str(error)})
    names = sorted({item['name'] for item in records})
    report = {'root': str(root), 'format_source': FORMAT_SOURCE,
              'unique_mod_count': len(names), 'file_count': len(records),
              'mod_names': names, 'files': records, 'errors': errors,
              'scope': 'Header/table inventory only; no extraction or mod execution'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'unique_mod_count': len(names), 'file_count': len(records),
                      'mod_names': names, 'errors': errors}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
