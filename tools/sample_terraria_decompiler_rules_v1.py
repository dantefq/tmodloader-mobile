"""Read-only bounded Rule-counter sampling of the pinned, owned Ghidra engine.

No debugger attach, thread suspension, remote invocation, or process-memory writes.
Rule-shaped heap objects are inferred by vptr/name/layout matches, not allocator proof.
"""
import argparse
import ctypes as C
import datetime as D
import hashlib
import json
import os
from pathlib import Path
import re
import struct

assert os.name == 'nt' and C.sizeof(C.c_void_p) == 8
LAB = Path(r'C:\Temp\terraria-re-20261012').resolve()
ENGINE = LAB / 'ghidra-guard-range-20261019/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe'
SHA = 'd64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(ENGINE) == SHA
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pid', type=int, required=True)
parser.add_argument('--base', type=lambda s: int(s, 16), required=True)
parser.add_argument('--start-utc', required=True)
parser.add_argument('--previous', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
assert args.output.resolve().is_relative_to(LAB) and not args.output.exists()
raw = ENGINE.read_bytes()
nt = struct.unpack_from('<I', raw, 0x3c)[0]
assert raw[nt:nt+4] == b'PE\0\0' and struct.unpack_from('<H', raw, nt+4)[0] == 0x8664
assert struct.unpack_from('<H', raw, nt+24)[0] == 0x20b
preferred = struct.unpack_from('<Q', raw, nt+48)[0]
section_count = struct.unpack_from('<H', raw, nt+6)[0]
optional_size = struct.unpack_from('<H', raw, nt+20)[0]
sections = []
for i in range(section_count):
    at = nt+24+optional_size+40*i
    virtual_size, rva, file_size, offset = struct.unpack_from('<IIII', raw, at+8)
    sections.append((rva, file_size, offset))


def file_bytes(va, size):
    rva = va-preferred
    matches = [p+rva-n for n, length, p in sections if n <= rva and rva+size <= n+length]
    assert len(matches) == 1
    return raw[matches[0]:matches[0]+size]


symbols_path = LAB / 'guard-range-engine-symbols-20261019.txt'
symbols = symbols_path.read_text(encoding='utf-8-sig').splitlines()
vptrs = {}
for line in symbols:
    m = re.fullmatch(r'([0-9a-fA-F]+) R vtable for ghidra::(Rule[A-Za-z0-9_]+)', line)
    if m:
        va = int(m.group(1), 16)
        assert file_bytes(va, 8) == b'\0'*8
        vptrs[args.base+va-preferred+16] = m.group(2)
assert len(vptrs) > 100
stats = [int(line.split()[0],16) for line in symbols if ' T ghidra::Rule::printStatistics(' in line]
assert len(stats) == 1
# Exact instructions observed in this SHA-pinned engine: DWORD fields +0x40/+0x44.
assert file_bytes(stats[0]+0x5b, 3) == bytes.fromhex('8b5640')
assert file_bytes(stats[0]+0x7b, 3) == bytes.fromhex('8b5644')
assert file_bytes(stats[0]+0xa, 5) == bytes.fromhex('440fb64110')


class MBI(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
                ('AllocationProtect', C.c_uint32), ('padding_or_partition', C.c_uint32),
                ('RegionSize', C.c_size_t), ('State', C.c_uint32),
                ('Protect', C.c_uint32), ('Type', C.c_uint32)]


assert C.sizeof(MBI) == 48
k = C.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.argtypes = [C.c_uint32, C.c_int, C.c_uint32]
k.OpenProcess.restype = C.c_void_p
k.CloseHandle.argtypes = [C.c_void_p]
k.ReadProcessMemory.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
k.VirtualQueryEx.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(MBI), C.c_size_t]
k.VirtualQueryEx.restype = C.c_size_t
k.QueryFullProcessImageNameW.argtypes = [C.c_void_p, C.c_uint32, C.c_wchar_p, C.POINTER(C.c_uint32)]
k.GetProcessTimes.argtypes = [C.c_void_p] + [C.POINTER(C.c_uint64)]*4
handle = k.OpenProcess(0x410, False, args.pid)  # QUERY_INFORMATION | VM_READ only
assert handle, C.get_last_error()
read_total = 0


def read(address, size):
    global read_total
    buf = C.create_string_buffer(size)
    got = C.c_size_t()
    k.ReadProcessMemory(handle, C.c_void_p(address), buf, size, C.byref(got))
    read_total += got.value
    return buf.raw[:got.value]


def string_at(data, offset):
    field = data[offset:offset+24]
    if field[0] & 1:
        length, pointer = struct.unpack_from('<QQ', field, 8)
        if not 0 < length <= 128:
            return None
        text = read(pointer, length+1)
        if len(text) != length+1 or text[-1] != 0:
            return None
        text = text[:-1]
    else:
        length = field[0] >> 1
        if not 0 < length <= 22 or field[1+length] != 0:
            return None
        text = field[1:1+length]
    try:
        result = text.decode('ascii')
    except UnicodeError:
        return None
    return result if re.fullmatch(r'[A-Za-z0-9_.:-]+', result) else None


def candidate(address):
    data = read(address, 72)
    if len(data) != 72:
        return None
    vptr = struct.unpack_from('<Q', data)[0]
    if vptr not in vptrs:
        return None
    name, group = string_at(data,16), string_at(data,40)
    if name is None or group is None:
        return None
    tests, applied = struct.unpack_from('<II', data,64)
    flags, bp = struct.unpack_from('<II',data,8)
    if flags & ~15 or bp & ~7:
        return None
    return dict(address=hex(address), vptr=hex(vptr), rule_class=vptrs[vptr], name=name,
                group=group, flags=flags, breakpoint=bp, tests=tests, applied=applied,
                raw72_sha256=hashlib.sha256(data).hexdigest())


try:
    pathbuf = C.create_unicode_buffer(32768)
    length = C.c_uint32(len(pathbuf))
    assert k.QueryFullProcessImageNameW(handle,0,pathbuf,C.byref(length))
    assert str(Path(pathbuf.value).resolve()).casefold() == str(ENGINE.resolve()).casefold()
    times = [C.c_uint64() for _ in range(4)]
    assert k.GetProcessTimes(handle,*(C.byref(t) for t in times))
    started = D.datetime.fromtimestamp((times[0].value-116444736000000000)/1e7,D.timezone.utc)
    expected = D.datetime.fromisoformat(args.start_utc.replace('Z','+00:00'))
    assert abs((started-expected).total_seconds()) < 0.01
    assert read(args.base,2) == b'MZ'
    found = {}
    scan_bytes = 0
    region_count = 0
    previous = None
    if args.previous:
        assert args.previous.resolve().is_relative_to(LAB)
        previous = json.loads(args.previous.read_text())
        assert previous['pid'] == args.pid and previous['creation_filetime'] == times[0].value and previous['engine_sha256'] == SHA
        assert previous['base'] == hex(args.base)
        for old in previous['candidates']:
            row = candidate(int(old['address'],16))
            if row and all(row[key] == old[key] for key in ('vptr','name','group','rule_class')):
                row['tests_delta'] = row['tests']-old['tests']
                row['applied_delta'] = row['applied']-old['applied']
                row['counter_decreased_or_reset'] = row['tests_delta'] < 0 or row['applied_delta'] < 0
                found[row['address']] = row
    else:
        at = 0
        needle = struct.pack('<Q',args.base)[4:]
        while at < 0x7fffffffffff and scan_bytes < 256*1024*1024:
            info = MBI()
            if k.VirtualQueryEx(handle,C.c_void_p(at),C.byref(info),C.sizeof(info)) != C.sizeof(info):
                break
            base, size = int(info.BaseAddress or 0), int(info.RegionSize)
            assert size > 0 and base+size > at
            if info.State == 0x1000 and info.Type == 0x20000 and not info.Protect & 0x100 and info.Protect & 0xff in (4,8,64,128):
                region_count += 1
                cursor, tail = base, b''
                while cursor < base+size and scan_bytes < 256*1024*1024:
                    amount = min(1024*1024,base+size-cursor,256*1024*1024-scan_bytes)
                    data = read(cursor,amount)
                    scan_bytes += amount
                    combined = tail+data
                    combined_base = cursor-len(tail)
                    index = combined.find(needle)
                    while index >= 0:
                        start = index-4
                        if start >= 0 and (combined_base+start)%8 == 0 and start+72 <= len(combined):
                            pointer = struct.unpack_from('<Q',combined,start)[0]
                            if pointer in vptrs:
                                row = candidate(combined_base+start)
                                if row:
                                    found[row['address']] = row
                        index = combined.find(needle,index+1)
                    tail = combined[-71:] if len(data) == amount else b''
                    cursor += amount
            at = base+size
    candidates = sorted(found.values(), key=lambda r: r.get('applied_delta',r['applied']), reverse=True)
    report = dict(pid=args.pid, creation_filetime=times[0].value, base=hex(args.base), engine_sha256=SHA,
                  sampler_sha256=sha(Path(__file__)), symbols_sha256=sha(symbols_path), sampled_UTC=D.datetime.now(D.timezone.utc).isoformat(),
                  read_access_mask='0x410 QUERY_INFORMATION|VM_READ', process_memory_written=False, threads_suspended=False,
                  max_heap_scan_bytes=256*1024*1024, heap_scan_bytes_requested=scan_bytes,
                  total_bytes_read=read_total, writable_private_regions_scanned=region_count,
                  previous_sha256=sha(args.previous) if args.previous else None, candidates=candidates,
                  counter_layout_proof=dict(tests_offset=64,applied_offset=68,printStatistics_RVA=hex(stats[0]-preferred),name_offset=16),
                  limitations='Bounded non-atomic read-only sample. Vptr/string/layout-matched candidates are not allocator/type-system proof. Rule copies can belong to inactive action styles; deltas can reset/wrap and are not CPU times. Unscanned regions/new objects remain unknown. Reads can affect timing/residency.')
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(candidates=len(candidates),heap_scan_MiB=scan_bytes/1024/1024,top=candidates[:12])))
finally:
    k.CloseHandle(handle)
