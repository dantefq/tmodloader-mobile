"""Summarize validated completed guard timings by address space and exact range."""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path
from review_terraria_action_trace import inspect


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('trace', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
review = inspect(args.trace)
by_space = collections.defaultdict(lambda: dict(count=0, inclusive_elapsed_ns=0, max_elapsed_ns=0))
by_range = collections.defaultdict(lambda: dict(count=0, inclusive_elapsed_ns=0, max_elapsed_ns=0))
for line in args.trace.read_text(encoding='ascii').splitlines()[1:]:
    if not line.startswith('END\t'):
        continue
    row = dict(p.split('=', 1) for p in line.split('\t')[1:])
    if row['kind'] != 'guard-detail' and not (row['kind'] == 'heritage' and row['name'] in ('guard', 'guardInput')):
        continue
    match = re.fullmatch(r'([^@]+)@0x([0-9a-f]+)\+([0-9]+)', row['group'])
    assert match, row['group']
    space, offset, size = match.group(1), int(match.group(2), 16), int(match.group(3))
    assert size > 0
    elapsed = int(row['elapsed_ns'])
    for total in (by_space[(row['kind'], row['name'], space)],
                  by_range[(row['function'], row['kind'], row['name'], space, offset, size)]):
        total['count'] += 1
        total['inclusive_elapsed_ns'] += elapsed
        total['max_elapsed_ns'] = max(total['max_elapsed_ns'], elapsed)
spaces = [dict(kind=k[0], operation=k[1], space=k[2], **v) for k, v in by_space.items()]
ranges = [dict(function=k[0], kind=k[1], operation=k[2], space=k[3], offset=hex(k[4]), size=k[5], **v) for k, v in by_range.items()]
spaces.sort(key=lambda r: r['inclusive_elapsed_ns'], reverse=True)
ranges.sort(key=lambda r: r['inclusive_elapsed_ns'], reverse=True)
out = dict(trace_review=review, completed_by_space=spaces, completed_by_range=ranges,
           summarizer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           C_coverage_addition=0, semantic_equivalence_verified=False,
           limits='Inclusive parent/child times overlap. Only completed intervals are totaled. Open intervals do not prove a cause of process termination. Stack/register offsets are not ELF virtual addresses; emitted space names are not independently resolved here.')
assert not args.output.exists()
args.output.write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(dict(begin_count=review['begin_count'], completed_scope_count=review['completed_scope_count'],
                      open_scopes=review['open_scopes'], limits=review['limits'], completed_by_space=spaces)))
