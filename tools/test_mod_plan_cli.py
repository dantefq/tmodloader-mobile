"""Exercise real JSON/exit-code behavior on synthetic TMODs, never game inputs."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

from plan_mod_load import build


def run_checks(dotnet_root, lab_root):
    command = build(dotnet_root, lab_root)
    folder = Path(lab_root).resolve() / 'mod-plan' / 'synthetic-inputs'
    folder.mkdir(parents=True, exist_ok=True)

    def text(value):
        data = value.encode('utf-8')
        size = len(data)
        prefix = bytearray()
        while size >= 128:
            prefix.append((size & 127) | 128)
            size >>= 7
        return bytes(prefix) + bytes([size]) + data

    def fixture(name, version, dependency=None):
        info = text('version') + text(version)
        if dependency:
            info += text('modReferences') + text(dependency) + text('')
            info += text('sortAfter') + text(dependency.split('@')[0]) + text('')
        info += text('')
        # Deliberately invalid DLL bytes. A metadata-only plan must never load it.
        assembly = b'not an executable assembly'
        payload = text(name) + text(version) + struct.pack('<i', 2)
        payload += text('Info') + struct.pack('<ii', len(info), len(info))
        payload += text(name + '.dll') + struct.pack('<ii', len(assembly), len(assembly)) + info + assembly
        data = b'TMOD' + text('2026.8.3.0') + hashlib.sha1(payload).digest() + bytes(256) + struct.pack('<i', len(payload)) + payload
        path = folder / (name + '-' + version + '.tmod'); path.write_bytes(data)
        return path

    child = fixture('AChild', '1.0', 'ZBase@1.2')
    provider = fixture('ZBase', '1.5')
    outdated = fixture('ZBase', '1.1')
    originals = {p: p.read_bytes() for p in (child, provider, outdated)}
    valid = subprocess.run([*command, 'client', str(child), str(provider)], capture_output=True, text=True, timeout=30)
    plan = json.loads(valid.stdout)
    assert valid.returncode == 0 and plan['valid'] and plan['order'] == ['ZBase', 'AChild']
    assert not plan['assembly_executed'] and not plan['compatibility_verified']
    for artifact in plan['artifacts']:
        assert artifact['sha256'] == hashlib.sha256(originals[Path(artifact['path'])]).hexdigest()
        assert artifact['payload_sha1_verified'] and not artifact['signature_authenticated']
    missing = subprocess.run([*command, 'client', str(child)], capture_output=True, text=True, timeout=30)
    missing_plan = json.loads(missing.stdout)
    assert missing.returncode == 2 and not missing_plan['valid'] and missing_plan['order'] == []
    assert missing_plan['issues'][0]['code'] == 'missing-dependency'
    old = subprocess.run([*command, 'client', str(child), str(outdated)], capture_output=True, text=True, timeout=30)
    assert old.returncode == 2 and json.loads(old.stdout)['issues'][0]['code'] == 'dependency-too-old'
    invalid = folder / 'invalid.tmod'; invalid.write_bytes(b'TMOD')
    malformed = subprocess.run([*command, 'client', str(invalid)], capture_output=True, text=True, timeout=30)
    assert malformed.returncode == 3 and malformed.stdout == '' and 'InvalidDataException' in malformed.stderr
    # Large declarations are opaque resource metadata: no texture/sound bytes
    # are expanded. Runtime MobileTmodArchive retains its separate 512 MiB cap.
    def metadata_fixture(label, entries, suffix=b'', corrupt=False):
        payload = text('Metadata') + text('1.0') + struct.pack('<i', len(entries))
        payload += b''.join(text(name) + struct.pack('<ii', expanded, len(data)) for name, expanded, data in entries)
        payload += b''.join(data for _, _, data in entries) + suffix
        digest = bytearray(hashlib.sha1(payload).digest())
        if corrupt: digest[0] ^= 1
        data = b'TMOD' + text('2026.8.3.0') + digest + bytes(256) + struct.pack('<i', len(payload)) + payload
        path = folder / (label + '.tmod'); path.write_bytes(data); originals[path] = data
        return subprocess.run([*command, 'client', str(path)], capture_output=True, text=True, timeout=30)
    info = text('version') + text('1.0') + text('')
    compressor = zlib.compressobj(wbits=-15)
    compressed = compressor.compress(info) + compressor.flush()
    large = metadata_fixture('large-declared', [('Info', len(info), info)] +
                             [('opaque/' + str(i), 128*1024*1024, b'') for i in range(5)])
    large_plan = json.loads(large.stdout)
    assert large.returncode == 0 and large_plan['artifacts'][0]['declared_expanded_bytes'] > 512*1024*1024
    assert large_plan['artifacts'][0]['resources_decompressed'] is False
    packed = metadata_fixture('compressed-info', [('Info', len(info), compressed)])
    assert packed.returncode == 0 and json.loads(packed.stdout)['artifacts'][0]['version'] == '1.0'
    for label, entries, suffix, corrupt in (
        ('duplicate-info', [('Info', len(info), info), ('Info', len(info), info)], b'', False),
        ('traversal', [('Info', len(info), info), ('../bad', 0, b'')], b'', False),
        ('coverage', [('Info', len(info), info)], b'extra', False),
        ('hash-mismatch', [('Info', len(info), info)], b'', True),
        ('missing-info', [('resource', 0, b'')], b'', False),
        ('oversized-info', [('Info', 1024*1024+1, b'')], b'', False),
        ('short-info', [('Info', len(info)+1, compressed)], b'', False),
        ('long-info', [('Info', len(info)-1, compressed)], b'', False),
        ('entry-limit', [('Info', len(info), info), ('resource', 128*1024*1024+1, b'')], b'', False),
    ):
        failure = metadata_fixture(label, entries, suffix, corrupt)
        assert failure.returncode == 3 and failure.stdout == '', (label, failure.stdout, failure.stderr)
    assert all(p.read_bytes() == original for p, original in originals.items())
    assert {p.name for p in folder.iterdir()} == {p.name for p in originals} | {'invalid.tmod'}
    print('PASS metadata CLI dependency/exit/hash checks, streaming large resource declarations, bounded compressed Info and 9 malformed inputs; no extraction/input changes')
