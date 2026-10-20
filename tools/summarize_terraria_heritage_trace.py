"""Aggregate completed heritage scopes; explicitly preserve open/incomplete scope data."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
from review_terraria_action_trace import inspect


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('trace', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
review = inspect(args.trace)
totals = collections.defaultdict(lambda: dict(count=0, inclusive_elapsed_ns=0, max_elapsed_ns=0))
for line in args.trace.read_text(encoding='ascii').splitlines()[1:]:
    if not line.startswith('END\t'):
        continue
    row = dict(p.split('=', 1) for p in line.split('\t')[1:])
    if row['kind'] != 'heritage':
        continue
    key = (row['function'], row['name'])
    elapsed = int(row['elapsed_ns'])
    total = totals[key]
    total['count'] += 1
    total['inclusive_elapsed_ns'] += elapsed
    total['max_elapsed_ns'] = max(total['max_elapsed_ns'], elapsed)
rows = [dict(function=key[0], operation=key[1], **value) for key, value in totals.items()]
rows.sort(key=lambda r: r['inclusive_elapsed_ns'], reverse=True)
report = dict(trace_review=review, completed_heritage_scopes=rows,
              summarizer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              interpretation='Inclusive completed-scope timings; nested parent/child times overlap. Open scopes are incomplete, not zero-time operations.',
              C_coverage_addition=0)
assert not args.output.exists()
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(dict(begin_count=review['begin_count'], completed_scope_count=review['completed_scope_count'],
                      open_scope_count=len(review['open_scopes']), limits=review['limits'],
                      longest_completed_heritage=rows[:8])))
