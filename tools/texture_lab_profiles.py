"""Fixed laboratory profiles; original material is read only from private inputs."""
import hashlib
from pathlib import Path
import struct

OWN = 'own-2x2'
PINNED = 'sots-helicopterparts'
TMOD_SHA = '4642380a29751664afa9122f01a8cf4491232ef9cd7bdb40e15c6d8e4e7c3790'
DLL_SHA = 'e96d7591ec56f5236454931ae0a3045be6072d2a7649f70679131bf0f0ee338f'
RAW_SHA = '783e86053ec749c41e1b05e89cca94a09966ff3b40423ca18dd9faf8a9494b05'
PIXELS = bytes([1, 2, 3, 255, 40, 50, 60, 127, 7, 8, 9, 0, 9, 8, 7, 1])


def definition(profile):
    if profile == OWN:
        return dict(item='TextureBridgeLab/Icon', asset='TextureBridgeLab/Images/Icon.rawimg', width=2, height=2)
    if profile == PINNED:
        return dict(item='TextureBindingLab/Preview', asset='TextureBindingLab/Images/SourceIcon.rawimg', width=44, height=34)
    raise ValueError('Unknown fixed texture lab profile')


def raw_image(profile, reference=None):
    definition(profile)
    if profile == OWN: return struct.pack('<iii', 1, 2, 2) + PIXELS
    if not isinstance(reference, bytes) or len(reference) != 5996 or hashlib.sha256(reference).hexdigest() != RAW_SHA:
        raise ValueError('Pinned original raw image required')
    if struct.unpack_from('<iii', reference) != (1, 44, 34): raise ValueError('Pinned raw dimensions differ')
    return reference


def read_reference(path):
    path = Path(path).resolve()
    if path.is_relative_to(Path(__file__).resolve().parents[1]) or path.stat().st_size != 5996:
        raise ValueError('Private bounded pinned raw image required')
    return raw_image(PINNED, path.read_bytes())


def extract_reference(path):
    path = Path(path).resolve()
    if path.is_relative_to(Path(__file__).resolve().parents[1]): raise ValueError('Original mod stays private')
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != TMOD_SHA: raise ValueError('Pinned SOTS TMOD changed')
    from inspect_mod_api import assembly_bytes
    dll, header = assembly_bytes(path, 'SOTS.dll')
    if (header['mod'], header['version']) != ('SOTS', '0.25.1.9') or hashlib.sha256(dll).hexdigest() != DLL_SHA:
        raise ValueError('Pinned SOTS DLL/version changed')
    del dll
    raw, _ = assembly_bytes(path, 'Items/HelicopterParts.rawimg')
    return raw_image(PINNED, raw)
