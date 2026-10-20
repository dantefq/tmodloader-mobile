"""Validate paired trace records; report open scopes without claiming completion."""
import argparse
import hashlib
import json
from pathlib import Path


def inspect(path):
    raw = path.read_bytes()
    lines = raw.decode('ascii').splitlines()
    def fields_of(parts):
        assert all('=' in p for p in parts)
        pairs = [p.split('=', 1) for p in parts]
        assert len({p[0] for p in pairs}) == len(pairs)
        return dict(pairs)

    assert lines
    header = lines[0].split('\t')
    assert header[0] == 'TRACEv1'
    metadata = fields_of(header[1:])
    assert set(metadata) == {'pid', 'clock', 'max_events', 'max_bytes'}
    assert 0 < int(metadata['pid']) <= 0xffffffff
    assert metadata['clock'] == 'steady_ns'
    assert metadata['max_events'] == '500000' and metadata['max_bytes'] == '67108864'
    opened, closed, begins, limits = {}, [], {}, []
    last_time = -1
    nonmonotonic = 0
    for line in lines[1:]:
        parts = line.split('\t')
        fields = fields_of(parts[1:])
        if parts[0] == 'LIMIT':
            assert set(fields) == {'time_ns', 'events', 'bytes'}
            assert all(int(value) >= 0 for value in fields.values())
            limits.append(fields)
            continue
        assert parts[0] in ('BEGIN', 'END')
        assert set(fields) == {'seq', 'parent', 'depth', 'time_ns', 'elapsed_ns',
                               'kind', 'name', 'group', 'function', 'entry', 'exception_active'}
        seq = int(fields['seq'])
        assert seq > 0 and int(fields['parent']) >= 0 and int(fields['depth']) >= 0
        assert fields['exception_active'] in ('0', '1')
        now = int(fields['time_ns'])
        assert now >= 0
        nonmonotonic += int(now < last_time)
        last_time = now
        if parts[0] == 'BEGIN':
            assert seq not in begins
            parent = int(fields['parent'])
            assert (parent == 0 and fields['depth'] == '0') or (
                parent in opened and int(fields['depth']) == int(opened[parent]['depth']) + 1)
            assert fields['elapsed_ns'] == '0'
            begins[seq] = fields
            opened[seq] = fields
        else:
            assert seq in opened
            start = opened.pop(seq)
            for key in ('parent', 'depth', 'kind', 'name', 'group', 'function', 'entry'):
                assert fields[key] == start[key]
            assert now >= int(start['time_ns']) and int(fields['elapsed_ns']) >= 0
            assert now - int(start['time_ns']) == int(fields['elapsed_ns'])
            closed.append(fields)
    return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                inspector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                bytes=len(raw), paired_records_valid=True, begin_count=len(begins),
                metadata=metadata, nonmonotonic_observed_timestamps=nonmonotonic,
                completed_scope_count=len(closed), open_scopes=list(opened.values()),
                limits=limits, all_observed_scopes_closed=bool(begins) and not opened and not limits,
                completed_commands=[r['name'] for r in closed if r['kind'] == 'command'],
                longest_completed_scopes=sorted(closed, key=lambda r: int(r['elapsed_ns']), reverse=True)[:12],
                semantic_equivalence_verified=False,
                note='No thread IDs: validates explicit pairs/parents without inferring a global thread stack. Open scopes and LIMIT are incomplete evidence.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.trace)
    assert not args.output.exists()
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('begin_count', 'completed_scope_count', 'all_observed_scopes_closed', 'completed_commands')}))
