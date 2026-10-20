"""Validate paired trace records; report open scopes without claiming completion."""
import argparse
import hashlib
import json
from pathlib import Path


def inspect(path):
    raw = path.read_bytes()
    lines = raw.decode('ascii').splitlines()
    assert lines and lines[0].startswith('TRACEv1\t')
    opened, closed, begins, limits = {}, [], {}, []
    last_time = -1
    for line in lines[1:]:
        parts = line.split('\t')
        fields = dict(p.split('=', 1) for p in parts[1:])
        if parts[0] == 'LIMIT':
            limits.append(fields)
            continue
        assert parts[0] in ('BEGIN', 'END')
        seq = int(fields['seq'])
        now = int(fields['time_ns'])
        assert now >= last_time
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
            assert now - int(start['time_ns']) == int(fields['elapsed_ns'])
            closed.append(fields)
    return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw), paired_records_valid=True, begin_count=len(begins),
                completed_scope_count=len(closed), open_scopes=list(opened.values()),
                limits=limits, all_observed_scopes_closed=not opened and not limits,
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
