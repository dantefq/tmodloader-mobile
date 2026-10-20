"""Independent bounded reader for the fixed lab profiles, not arbitrary mods."""
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid
from texture_lab_profiles import OWN, PINNED, PIXELS, definition, raw_image, read_reference

def archive_digest(profile, raw):
    details = definition(profile)
    name, entry = details['asset'].split('/', 1)
    def text(value):
        data = value.encode('utf-8'); size = len(data); prefix = bytearray()
        while size >= 128: prefix.append((size & 127) | 128); size >>= 7
        prefix.append(size); return bytes(prefix) + data
    payload = text(name) + text('1.0') + struct.pack('<i', 1) + text(entry) + struct.pack('<ii', len(raw), len(raw)) + raw
    archive = b'TMOD' + text('2026.5.3.0') + hashlib.sha1(payload).digest() + bytes(256) + struct.pack('<i', len(payload)) + payload
    return hashlib.sha256(archive).hexdigest()


def verify_export(value, profile=OWN, reference=None):
    from probe_sots_item_defaults import verify_png
    plan = value['plan']
    expected = definition(profile); raw = raw_image(profile, reference)
    if (value.get('format') != 'tmal-texture-export-v1' or plan.get('format') != 'tmal-item-texture-transfer-v1' or
            (plan.get('itemType'), plan.get('item'), plan.get('asset'), plan.get('width'), plan.get('height')) !=
            (6196, expected['item'], expected['asset'], expected['width'], expected['height'])):
        raise ValueError('Fixed fixture export identity differs')
    if plan['archiveSha256'] != archive_digest(profile, raw): raise ValueError('Own resource archive identity differs')
    for key in ('generation', 'transferId'):
        token = uuid.UUID(plan[key])
        if not token.int or str(token) != plan[key]: raise ValueError('Canonical nonzero UUID required')
    for key in ('archiveSha256', 'pngSha256'):
        if not re.fullmatch('[0-9a-f]{64}', plan[key]): raise ValueError('Digest format differs')
    encoded = value['packetBase64']
    if not isinstance(encoded, str) or len(encoded) > 88200: raise ValueError('Bounded Base64 required')
    packet = base64.b64decode(encoded, validate=True)
    if base64.b64encode(packet).decode('ascii') != encoded: raise ValueError('Canonical Base64 required')
    if not 102 <= len(packet) <= 65536 + 613 or packet[:5] != b'TMIT\x01':
        raise ValueError('Bounded texture packet required')
    size = struct.unpack_from('<i', packet, 5)[0]; pos = 9 + size
    if not 1 <= size <= 512 or pos + 92 > len(packet): raise ValueError('Invalid packet framing')
    key = packet[9:pos].decode('utf-8', 'strict')
    generation = str(uuid.UUID(bytes_le=packet[pos:pos+16])); pos += 16
    archive = packet[pos:pos+32].hex(); pos += 32
    width, height, count = struct.unpack_from('<iii', packet, pos); pos += 12
    digest = packet[pos:pos+32].hex(); pos += 32
    if (key, generation, archive, width, height, digest) != (plan['asset'], plan['generation'],
            plan['archiveSha256'], expected['width'], expected['height'], plan['pngSha256']): raise ValueError('Packet detached from export plan')
    png = packet[pos:]
    if count != len(png) or not 57 <= count <= 65536 or hashlib.sha256(png).hexdigest() != digest:
        raise ValueError('Independent PNG framing/digest differs')
    verify_png(png, expected['width'], expected['height'], raw[12:])
    return plan, packet, png, raw


def read_export(path, profile=OWN, reference_path=None):
    path = path.resolve()
    if path.is_relative_to(Path(__file__).resolve().parents[1]) or path.stat().st_size > 94208:
        raise ValueError('Private bounded export file required')
    reference = read_reference(reference_path) if profile == PINNED else None
    return verify_export(json.loads(path.read_text('utf-8')), profile, reference)
