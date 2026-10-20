"""Independent reader for the own registry fixture carrying one pinned texture.

Checks matching identities, not sender authentication. No mod assembly is loaded.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid


def read_binding(plan_path: Path):
    from probe_sots_item_defaults import IMAGE_SHA, verify_png
    root = Path(__file__).resolve().parents[1]
    plan_path = plan_path.resolve()
    if plan_path.is_relative_to(root) or plan_path.stat().st_size > 4096:
        raise ValueError('Private bounded registry fixture required')
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    if (plan.get('format') != 'tmal-item-texture-transfer-v1' or plan.get('itemType') != 6196 or
            plan.get('item') != 'TextureBindingLab/Preview' or plan.get('asset') != 'TextureBindingLab/Images/SourceIcon.rawimg'):
        raise ValueError('Only the own laboratory item binding is supported')
    if (str(uuid.UUID(plan['generation'])) != plan['generation'] or uuid.UUID(plan['generation']).int == 0 or
            str(uuid.UUID(plan['transferId'])) != plan['transferId'] or uuid.UUID(plan['transferId']).int == 0 or
            any(not re.fullmatch('[0-9a-f]{64}', plan.get(key, '')) for key in ('archiveSha256', 'pngSha256'))):
        raise ValueError('Explicit registry generation and digests required')
    folder = plan_path.parent
    packet_path = folder / 'texture-binding.png.tmit'
    raw_path = folder / 'source.rawimg'
    archive_path = folder / 'own-lab-resources.tmod'
    if packet_path.stat().st_size > 65536 + 613 or raw_path.stat().st_size > 256 * 256 * 4 + 12 or archive_path.stat().st_size > 256 * 256 * 4 + 1024:
        raise ValueError('Registry fixture exceeds diagnostic bounds')
    raw = raw_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != IMAGE_SHA:
        raise ValueError('Registry fixture source image differs from pinned original')
    version, width, height = struct.unpack_from('<iii', raw)
    if version != 1 or (width, height) != (plan.get('width'), plan.get('height')):
        raise ValueError('Registry plan dimensions differ from source')
    archive = archive_path.read_bytes()
    if not archive.startswith(b'TMOD') or hashlib.sha256(archive).hexdigest() != plan['archiveSha256']:
        raise ValueError('Own laboratory resource archive identity differs')
    data = packet_path.read_bytes()
    if data[:5] != b'TMIT\x01' or len(data) < 102:
        raise ValueError('Registry texture packet signature/length differs')
    size = struct.unpack_from('<i', data, 5)[0]
    if not 1 <= size <= 512 or 9 + size + 92 > len(data):
        raise ValueError('Registry texture key length differs')
    key = data[9:9+size].decode('utf-8', errors='strict'); pos = 9 + size
    generation = str(uuid.UUID(bytes_le=data[pos:pos+16])); pos += 16
    archive_sha = data[pos:pos+32].hex(); pos += 32
    w, h, count = struct.unpack_from('<iii', data, pos); pos += 12
    digest = data[pos:pos+32].hex(); pos += 32
    if (key, generation, archive_sha, w, h) != (plan['asset'], plan['generation'], plan['archiveSha256'], width, height):
        raise ValueError('Registry packet is detached from its binding plan')
    png = data[pos:]
    if count != len(png) or count > 65536 or digest != plan['pngSha256'] or hashlib.sha256(png).hexdigest() != digest:
        raise ValueError('Registry packet PNG integrity differs')
    verify_png(png, width, height, raw[12:])
    return plan, data, png, raw
