"""Reject self-consistent but wrong lab textures using private known exports.

No original image is embedded here. Positive exports and reference remain in a
private lab; malformed packets and replacement pixels exist only in memory.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import struct

from texture_bridge_fixture import verify_export
from texture_lab_profiles import OWN, PINNED, read_reference
from probe_device_texture_upload import encode_fixture

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('own-export', 'pinned-export', 'reference'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    def load(path):
        path = path.resolve()
        if path.is_relative_to(ROOT) or path.stat().st_size > 94208: raise ValueError('Private bounded input required')
        return json.loads(path.read_text('utf-8'))
    own = load(args.own_export); pinned = load(args.pinned_export); raw = read_reference(args.reference)
    checks = 0
    def check(action, reject=False):
        nonlocal checks
        if reject:
            try: action()
            except ValueError: checks += 1; return
            raise AssertionError('Invalid texture profile accepted')
        action(); checks += 1
    check(lambda: verify_export(own))
    check(lambda: verify_export(pinned, PINNED, raw))
    check(lambda: verify_export(own, PINNED, raw), True)
    check(lambda: verify_export(pinned, OWN), True)
    check(lambda: verify_export(pinned, PINNED), True)
    check(lambda: verify_export(pinned, PINNED, raw[:-1]), True)
    damaged_raw = bytearray(raw); damaged_raw[-1] ^= 1
    check(lambda: verify_export(pinned, PINNED, bytes(damaged_raw)), True)
    for key, value in [('itemType', 6197), ('item', 'Other/Preview'), ('width', 45), ('transferId', '00000000-0000-0000-0000-000000000000')]:
        altered = copy.deepcopy(pinned); altered['plan'][key] = value
        check(lambda: verify_export(altered, PINNED, raw), True)
    altered = copy.deepcopy(pinned); packet = bytearray(base64.b64decode(altered['packetBase64']))
    pos = 9 + struct.unpack_from('<i', packet, 5)[0]
    packet[pos + 16:pos + 48] = bytes(32); altered['plan']['archiveSha256'] = '00' * 32
    altered['packetBase64'] = base64.b64encode(packet).decode('ascii')
    check(lambda: verify_export(altered, PINNED, raw), True)
    altered = copy.deepcopy(pinned); altered['packetBase64'] = 'A' * 88204
    check(lambda: verify_export(altered, PINNED, raw), True)
    altered = copy.deepcopy(pinned); packet = bytearray(base64.b64decode(altered['packetBase64'])); packet[-1] ^= 1
    altered['packetBase64'] = base64.b64encode(packet).decode('ascii')
    check(lambda: verify_export(altered, PINNED, raw), True)
    # All framing, digests and chunk CRCs agree, but every decoded pixel is wrong.
    # The independent comparison with the pinned raw reference must still fail.
    replacement = encode_fixture(44, 34, bytes(44 * 34 * 4))
    altered = copy.deepcopy(pinned); packet = bytearray(base64.b64decode(altered['packetBase64']))
    pos = 9 + struct.unpack_from('<i', packet, 5)[0] + 48
    digest = hashlib.sha256(replacement).digest(); packet[pos + 8:pos + 12] = struct.pack('<i', len(replacement))
    packet = packet[:pos + 12] + digest + replacement
    altered['plan']['pngSha256'] = digest.hex(); altered['packetBase64'] = base64.b64encode(packet).decode('ascii')
    check(lambda: verify_export(altered, PINNED, raw), True)
    print(json.dumps({'profile_contract_cases': checks, 'passed': True,
        'self_consistent_wrong_archive_and_pixels_rejected': True, 'game_execution': False}))


if __name__ == '__main__': main()
