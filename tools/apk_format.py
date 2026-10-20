"""Bounded APK probes and binary-XML string replacement; no game code copied."""
import hashlib
import struct
import zipfile

METADATA_PATH = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
ACTIVITY = 'com.unity3d.player.UnityPlayerActivity'
MOD_ACTIVITY = 'tm.loader.ModActivity'


def sha256(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _length(data, offset, utf8):
    if utf8:
        value = data[offset]
        if value & 0x80:
            return ((value & 0x7f) << 8) | data[offset + 1], offset + 2
        return value, offset + 1
    value = struct.unpack_from('<H', data, offset)[0]
    if value & 0x8000:
        return ((value & 0x7fff) << 16) | struct.unpack_from('<H', data, offset + 2)[0], offset + 4
    return value, offset + 2


def _encode_length(value, utf8):
    if utf8:
        if value < 128: return bytes([value])
        if value >= 32768: raise ValueError('AXML string too long')
        return bytes([0x80 | (value >> 8), value & 255])
    if value < 32768: return struct.pack('<H', value)
    return struct.pack('<HH', 0x8000 | (value >> 16), value & 65535)


def string_pool(chunk):
    kind, header_size, size = struct.unpack_from('<HHI', chunk)
    if kind != 1 or header_size != 28 or size != len(chunk):
        raise ValueError('Unsupported binary XML string pool')
    count, style_count, flags, start, styles_start = struct.unpack_from('<5I', chunk, 8)
    if count > 10000 or start < 28 + 4 * (count + style_count) or start > size:
        raise ValueError('Invalid string pool bounds')
    strings = []
    for i in range(count):
        offset = start + struct.unpack_from('<I', chunk, 28 + 4 * i)[0]
        n, offset = _length(chunk, offset, bool(flags & 0x100))
        if flags & 0x100:
            byte_count, offset = _length(chunk, offset, True)
            text = chunk[offset:offset + byte_count].decode('utf-8')
        else:
            text = chunk[offset:offset + 2 * n].decode('utf-16le')
        strings.append(text)
    return strings, (count, style_count, flags, start, styles_start)


def replace_activity(manifest, activity=MOD_ACTIVITY):
    kind, header_size, total = struct.unpack_from('<HHI', manifest)
    if kind != 3 or total != len(manifest): raise ValueError('Expected Android binary XML')
    result = bytearray(manifest[:header_size])
    offset = header_size
    replacements = 0
    while offset < total:
        chunk_kind, _, size = struct.unpack_from('<HHI', manifest, offset)
        if size < 8 or offset + size > total: raise ValueError('Invalid binary XML chunk')
        chunk = manifest[offset:offset + size]
        if chunk_kind == 1:
            strings, values = string_pool(chunk)
            count, style_count, flags, start, styles_start = values
            if strings.count(ACTIVITY) != 1: raise ValueError('Expected exactly one Unity activity string')
            strings[strings.index(ACTIVITY)] = activity
            replacements += 1
            utf8 = bool(flags & 0x100)
            payload = bytearray()
            offsets = []
            for text in strings:
                offsets.append(len(payload))
                utf16_length = len(text.encode('utf-16le')) // 2
                payload.extend(_encode_length(utf16_length, utf8))
                if utf8:
                    encoded = text.encode('utf-8')
                    payload.extend(_encode_length(len(encoded), True))
                    payload.extend(encoded + b'\0')
                else: payload.extend(text.encode('utf-16le') + b'\0\0')
            payload.extend(b'\0' * (-len(payload) % 4))
            prefix = bytearray(chunk[:start])
            struct.pack_into('<I', prefix, 16, flags & ~1)  # Replacement may change lexical order.
            for i, position in enumerate(offsets): struct.pack_into('<I', prefix, 28 + 4*i, position)
            styles = chunk[styles_start:] if styles_start else b''
            struct.pack_into('<I', prefix, 24, start + len(payload) if styles else 0)
            chunk = prefix + payload + styles
            struct.pack_into('<I', chunk, 4, len(chunk))
        result.extend(chunk)
        offset += size
    if replacements != 1: raise ValueError('Manifest must have one string pool')
    struct.pack_into('<I', result, 4, len(result))
    return bytes(result)


def probe(apk):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)): raise ValueError('Duplicate APK entries')
        metadata = archive.read(METADATA_PATH)
        if struct.unpack_from('<2I', metadata) != (0xFAB11BAF, 31):
            raise ValueError('Only verified IL2CPP metadata v31 is supported')
        def table(offset):
            start, size = struct.unpack_from('<2I', metadata, offset)
            if start + size > len(metadata): raise ValueError('Metadata table outside file')
            return start, size
        string_start, string_size = table(24)
        def name(index):
            if index >= string_size: raise ValueError('Invalid metadata string index')
            start = string_start + index
            return metadata[start:metadata.index(b'\0', start, string_start+string_size)].decode('utf-8')
        type_start, type_size = table(160)
        method_start, method_size = table(48)
        field_start, field_size = table(96)
        parameter_start, parameter_size = table(88)
        defaults_start, defaults_size = table(64)
        data_start, data_size = table(72)
        if type_size % 88 or method_size % 36 or field_size % 12 or parameter_size % 12:
            raise ValueError('Unexpected metadata record sizes')
        classes = {}
        copper_id = None
        for offset in range(type_start, type_start + type_size, 88):
            record = struct.unpack_from('<16I8H2I', metadata, offset)
            ns, cls = name(record[1]), name(record[0])
            if (ns, cls) not in [('Terraria','Item'), ('Terraria','Main'), ('Terraria.ID','ItemID')]: continue
            fields, methods = [], []
            for i in range(record[8], record[8] + record[18]):
                field = struct.unpack_from('<3I', metadata, field_start + 12*i)
                field_name = name(field[0])
                if field_name in ('type','damage','netMode','CopperShortsword'):
                    fields.append(field_name)
                if field_name == 'CopperShortsword':
                    for j in range(defaults_start, defaults_start + defaults_size, 12):
                        index, _, data_index = struct.unpack_from('<3i', metadata, j)
                        if index == i:
                            if not 0 <= data_index < data_size-1: raise ValueError('Invalid constant offset')
                            copper_id = struct.unpack_from('<h', metadata, data_start + data_index)[0]
            for i in range(record[9], record[9] + record[16]):
                method = struct.unpack_from('<7I4H', metadata, method_start + 36*i)
                method_name = name(method[0])
                if cls == 'Item' and method_name in ('SetDefaults','SetNameOverride'):
                    parameters = [name(struct.unpack_from('<3I',metadata,parameter_start+12*j)[0])
                                  for j in range(method[4], method[4]+method[10])]
                    methods.append({'name':method_name,'parameters':parameters,'flags':hex(method[7])})
            classes[ns+'.'+cls] = {'fields':fields,'methods':methods}
        native = archive.read('lib/arm64-v8a/libil2cpp.so')
        if native[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H',native,18)[0] != 183:
            raise ValueError('Expected ELF64 little-endian AArch64')
        exports = []
        section_start = struct.unpack_from('<Q', native, 40)[0]
        section_size, section_count = struct.unpack_from('<2H', native, 58)
        for i in range(section_count):
            section = struct.unpack_from('<IIQQQQIIQQ', native, section_start + i*section_size)
            if section[1] != 11: continue  # SHT_DYNSYM
            strings = struct.unpack_from('<IIQQQQIIQQ',native,section_start + section[6]*section_size)
            pool = native[strings[4]:strings[4]+strings[5]]
            for j in range(section[4], section[4]+section[5], section[9]):
                symbol_name, _, _, defined, _, _ = struct.unpack_from('<IBBHQQ',native,j)
                if defined and symbol_name:
                    symbol = pool[symbol_name:pool.index(b'\0',symbol_name)].decode('ascii')
                    if symbol.startswith('il2cpp_'): exports.append(symbol)
        return {'apk_sha256':sha256(apk),'entries':len(names),'metadata_version':31,
                'native_abi':'arm64-v8a','copper_shortsword_id':copper_id,
                'classes':classes,'il2cpp_exports':sorted(exports)}
